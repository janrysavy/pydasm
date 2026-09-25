"""The Intel 8088/8086 instruction decoder.

Three steps, in this order, and the order is load-bearing:

1. **Prefixes.** Consume prefix bytes until a real opcode appears. Every prefix
   seen is recorded in `raw_prefix_flags`; only the last segment override is
   kept, and an operand-size prefix only counts as *effective* against the
   default width the CPU was configured with.
2. **Opcode lookup.** Index the decode table by the opcode byte. If the row is a
   group entry, fetch the ModRM byte and re-index on its `reg` field. The ModRM
   fetch has to happen before the second lookup, which is why both live here
   rather than in a table of their own.
3. **Operand resolution.** Resolve operand 1 then operand 2, in encoding order,
   against the ModRM byte and the displacement it produced.

The 8086 has no operand-size or address-size prefix: `0x66` and `0x67` are not
prefixes on this CPU, they are the opcodes they happen to be (and on the 8088
they decode as the undocumented instructions their table rows give).
"""

from __future__ import annotations

from ..byte_reader import ByteReader
from ..cpu_common import (
    NO_OPERAND,
    AddressSize,
    Displacement,
    OperandSize,
    OperandType,
    PrefixFlags,
    Register16,
    SegmentSize,
)
from ..errors import DecodeError, UnexpectedEof
from ..instruction import Instruction
from .decode_table import DECODE
from .modrm16 import ModRmByte16
from .operands import resolve_operand

#: Prefix bytes recognised before the opcode. The 8086 treats 0xF0 and 0xF1 the
#: same way (LOCK), and 0xF2/0xF3 as the two REP families.
_PREFIX_FLAGS = {
    0x26: PrefixFlags.ES_OVERRIDE,
    0x2E: PrefixFlags.CS_OVERRIDE,
    0x36: PrefixFlags.SS_OVERRIDE,
    0x3E: PrefixFlags.DS_OVERRIDE,
    0xF0: PrefixFlags.LOCK,
    0xF1: PrefixFlags.LOCK,
    0xF2: PrefixFlags.REP1,
    0xF3: PrefixFlags.REP2,
}

_SEGMENT_PREFIXES = {
    0x26: Register16.ES,
    0x2E: Register16.CS,
    0x36: Register16.SS,
    0x3E: Register16.DS,
}

#: Separator between the base table (0..255) and the group rows.
_GROUP_BASE = 256

#: Rows per group in the table.
_GROUP_STRIDE = 8


class Intel808x:
    """Namespace for the 8088/8086 decoder."""

    @staticmethod
    def decode(reader: ByteReader, segment_size: SegmentSize = SegmentSize.Segment16) -> Instruction:
        instruction = Instruction(
            is_valid=True,
            operand_size=OperandSize.Operand16,
            segment_size=segment_size,
        )
        return _decode(reader, instruction)


def _decode(reader: ByteReader, instruction: Instruction) -> Instruction:
    instruction_bytes = instruction.instruction_bytes

    # -- step 1: prefixes -------------------------------------------------
    opcode = reader.read_u8()
    instruction_bytes.append(opcode)

    while opcode in _PREFIX_FLAGS:
        instruction.prefix_bytes.append(opcode)
        opcode = reader.read_u8()
        instruction_bytes.append(opcode)

    instruction.prefix_ct = len(instruction.prefix_bytes)
    instruction.opcode_offset = len(instruction_bytes) - 1

    # Note: this decoder records the prefix *bytes* and stops there. It computes
    # neither `raw_prefix_flags`/`effective_prefix_flags` nor `segment_override`,
    # because marty_dasm's 8086 decoder does not -- it tracks them in locals for
    # the prefix loop and never stores them, unlike the 386 decoder which does.
    # A caller that needs the override or the REP family reads `prefix_bytes`;
    # `pydasm.ghidra` does exactly that. Storing them here instead would make the
    # NASM formatter print prefixes that the reference implementation drops.

    # -- step 2: opcode lookup, with the group re-index -------------------
    row = DECODE[opcode]

    displacement = Displacement.none()
    modrm = None

    # A group opcode always has a ModRM byte even if its GDR row does not say
    # so -- the table's group rows are selected *by* that byte.
    if row.gdr.has_modrm() or row.grp != 0:
        modrm_offset = len(instruction_bytes)
        modrm = ModRmByte16.read(reader, instruction_bytes)
        displacement = modrm.displacement
        instruction.has_modrm = True
        instruction.modrm_offset = modrm_offset
        if modrm.displacement.width:
            instruction.has_displacement = True
            instruction.displacement_size = {
                1: OperandSize.Operand8,
                2: OperandSize.Operand16,
                4: OperandSize.Operand32,
            }[modrm.displacement.width]

        if row.grp != 0:
            index = _GROUP_BASE + (row.grp - 1) * _GROUP_STRIDE + modrm.op_extension()
            row = DECODE[index]

    instruction.opcode = opcode

    # -- step 3: operands, in encoding order ------------------------------
    instruction.operand1_type = resolve_operand(row.operand1, reader, modrm, displacement, instruction)
    instruction.operand2_type = resolve_operand(row.operand2, reader, modrm, displacement, instruction)
    instruction.operand3_type = NO_OPERAND

    instruction.mnemonic = row.mnemonic
    instruction.is_complete = True
    return instruction


__all__ = ["Intel808x", "DecodeError", "UnexpectedEof", "OperandType"]
