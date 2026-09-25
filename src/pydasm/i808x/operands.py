"""Operand templates and their resolution into concrete operands.

A decode-table row names each operand by *template*, not by value: `ModRM8`
means "the ModRM byte decides whether this is a register or a memory reference",
`Immediate16` means "consume two more bytes". Resolving a template is the step
that reads those bytes, so it is also the step that decides how long the
instruction is -- which is why the template carries the byte-reading and the
caller must resolve templates in encoding order.

Both operands are resolved on every instruction, including the ones that will
not consume anything, because a template that picks up an immediate has to do so
in stream order (an `Ot::MODRM8` first operand followed by an `Ot::IMM8` second
consumes ModRM then immediate; reversing the resolve order would consume them
the other way round).
"""

from __future__ import annotations

import enum

from ..byte_reader import ByteReader
from ..cpu_common import (
    NO_OPERAND,
    AddressOffset16,
    Displacement,
    OperandSize,
    OperandType,
    Register8,
    Register16,
)
from ..errors import DecodeError
from ..instruction import Instruction


class OperandTemplate(enum.Enum):
    """How to build an operand, before the bytes that decide it have been read."""

    NONE = "NoOperand"
    MODRM8 = "ModRM8"
    MODRM16 = "ModRM16"
    REG8 = "Register8"
    REG16 = "Register16"
    SREG = "SegmentRegister"
    IMM8 = "Immediate8"
    IMM16 = "Immediate16"
    IMM8SE = "Immediate8SignExtended"
    REL8 = "Relative8"
    REL16 = "Relative16"
    OFF8 = "Offset8"
    OFF16 = "Offset16"
    FAR = "FarAddress"
    FIXED8 = "FixedRegister8"
    FIXED16 = "FixedRegister16"


class FixedOperand:
    """A template that carries a register with it: `FixedRegister8(Register8.AL)`."""

    __slots__ = ("template", "register")

    def __init__(self, template: OperandTemplate, register: object) -> None:
        self.template = template
        self.register = register

    def __repr__(self) -> str:
        return f"{self.template.name}({self.register})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FixedOperand):
            return NotImplemented
        return self.template is other.template and self.register is other.register

    def __hash__(self) -> int:
        return hash((self.template, self.register))


def fixed8(register: Register8) -> FixedOperand:
    return FixedOperand(OperandTemplate.FIXED8, register)


def fixed16(register: Register16) -> FixedOperand:
    return FixedOperand(OperandTemplate.FIXED16, register)


OT = OperandTemplate  # short alias for the generated table


def resolve_operand(
    template: OperandTemplate | FixedOperand,
    reader: ByteReader,
    modrm,
    displacement: Displacement,
    instruction: Instruction,
) -> OperandType:
    """Build one operand, consuming any bytes it needs from `reader`.

    Every byte consumed is appended to `instruction.instruction_bytes`, and the
    operand's own category (`immediate_bytes`, `displacement_bytes`) as well, so
    the caller can report an instruction's encoding by parts.
    """
    if isinstance(template, FixedOperand):
        if template.template is OperandTemplate.FIXED8:
            return OperandType("reg8", template.register)
        return OperandType("reg16", template.register)

    match template:
        case OperandTemplate.NONE:
            return NO_OPERAND

        case OperandTemplate.MODRM8:
            # The ModRM byte decides which of the two this is; the template only
            # says how wide the register interpretation would be.
            if modrm.is_addressing_mode():
                return OperandType("addr16", modrm.address_offset(displacement), OperandSize.Operand8)
            return OperandType("reg8", modrm.op1_reg8())

        case OperandTemplate.MODRM16:
            if modrm.is_addressing_mode():
                return OperandType("addr16", modrm.address_offset(displacement), OperandSize.Operand16)
            return OperandType("reg16", modrm.op1_reg16())

        case OperandTemplate.REG8:
            return OperandType("reg8", modrm.op2_reg8())

        case OperandTemplate.REG16:
            return OperandType("reg16", modrm.op2_reg16())

        case OperandTemplate.SREG:
            return OperandType("reg16", modrm.op2_segment_reg16())

        case OperandTemplate.IMM8 | OperandTemplate.REL8:
            value = reader.read_u8()
            instruction.instruction_bytes.append(value)
            instruction.immediate_bytes.append(value)
            if template is OperandTemplate.IMM8:
                return OperandType("imm8", value)
            return OperandType("rel8", value - 0x100 if value & 0x80 else value)

        case OperandTemplate.IMM8SE:
            value = reader.read_i8()
            instruction.instruction_bytes.append(value & 0xFF)
            instruction.immediate_bytes.append(value & 0xFF)
            return OperandType("imm8s", value)

        case OperandTemplate.IMM16 | OperandTemplate.REL16 | OperandTemplate.OFF8 | OperandTemplate.OFF16:
            value = reader.read_u16()
            raw = value.to_bytes(2, "little")
            instruction.instruction_bytes.extend(raw)
            instruction.immediate_bytes.extend(raw)
            if template is OperandTemplate.IMM16:
                return OperandType("imm16", value)
            if template is OperandTemplate.REL16:
                signed = value - 0x1_0000 if value & 0x8000 else value
                return OperandType("rel16", signed)
            if template is OperandTemplate.OFF8:
                return OperandType("offset8_16", value)
            return OperandType("offset16_16", value)

        case OperandTemplate.FAR:
            segment, offset = reader.read_farptr16()
            raw = offset.to_bytes(2, "little") + segment.to_bytes(2, "little")
            instruction.instruction_bytes.extend(raw)
            instruction.immediate_bytes.extend(raw)
            return OperandType("far16", (segment, offset))

    raise DecodeError(f"unhandled operand template: {template!r}")
