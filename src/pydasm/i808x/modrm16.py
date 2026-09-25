"""The 16-bit ModRM byte.

A ModRM byte has three fields: `mod` (2 bits), `reg` (3 bits) and `r/m` (3 bits).
`reg` means different things depending on the opcode -- a register operand, or a
three-bit opcode extension selecting a group row -- so this module deliberately
exposes it as both and lets the decoder choose.

The addressing mode depends on `mod` *and* `r/m` together:

    mod=00  [BX+SI] [BX+DI] [BP+SI] [BP+DI] [SI] [DI] [disp16] [BX]
    mod=01  the same eight, each with an 8-bit sign-extended displacement
    mod=10  the same eight, each with a 16-bit displacement
    mod=11  register direct: no addressing mode, no displacement

`mod=00 r/m=110` is the odd one out: it is an absolute `[disp16]`, not the
`[BP]` its position would suggest. The table below is built by enumerating all
256 bytes through that rule rather than by transcribing 256 cases, so the
exception is stated once.
"""

from __future__ import annotations

from ..byte_reader import ByteReader
from ..cpu_common import (
    CREGISTER_LUT,
    DREGISTER_LUT,
    REGISTER8_LUT,
    REGISTER16_LUT,
    REGISTER32_LUT,
    SREGISTER16_LUT,
    SREGISTER16_LUT_386,
    TREGISTER_LUT,
    AddressOffset16,
    ControlRegister,
    DebugRegister,
    Displacement,
    Register8,
    Register16,
    Register32,
    TestRegister,
)

_MOD = 0b11_000_000
_REG = 0b00_111_000
_RM = 0b00_000_111

# The eight `mod`/`r/m` combinations that select registers rather than addresses.
_REGISTER_MODE = 0b11

# `mod=00 r/m=110` is an absolute address, not [BP].
_ABSOLUTE_RM = 0b110

_BASE_KINDS = (
    "bx_si",
    "bx_di",
    "bp_si",
    "bp_di",
    "si",
    "di",
    "disp16",
    "bx",
)

_DISP8_KINDS = (
    "bx_si_d8",
    "bx_di_d8",
    "bp_si_d8",
    "bp_di_d8",
    "si_d8",
    "di_d8",
    "bp_d8",
    "bx_d8",
)

_DISP16_KINDS = (
    "bx_si_d16",
    "bx_di_d16",
    "bp_si_d16",
    "bp_di_d16",
    "si_d16",
    "di_d16",
    "bp_d16",
    "bx_d16",
)


def _build_table() -> tuple["ModRmByte16", ...]:
    """Enumerate all 256 ModRM bytes through the mod/r-m rule.

    The table is built rather than transcribed so the one irregular case --
    `mod=00 r/m=110` is `[disp16]`, not `[bp]` -- is stated once instead of
    hiding among 256 hand-written rows.
    """
    table = []
    for byte in range(256):
        mod = (byte & _MOD) >> 6
        rm = byte & _RM
        if mod == _REGISTER_MODE:
            # Register direct: no addressing mode and no displacement.
            mode = AddressOffset16("none")
            displacement = Displacement.none()
        elif mod == 0b00:
            mode = AddressOffset16(_BASE_KINDS[rm])
            displacement = Displacement.disp16(0) if rm == _ABSOLUTE_RM else Displacement.none()
        elif mod == 0b01:
            mode = AddressOffset16(_DISP8_KINDS[rm])
            displacement = Displacement.disp8(0)
        else:
            mode = AddressOffset16(_DISP16_KINDS[rm])
            displacement = Displacement.disp16(0)
        table.append(ModRmByte16(byte, mod, (byte & _REG) >> 3, rm, displacement, mode))
    return tuple(table)


class ModRmByte16:
    """One decoded ModRM byte, addressed by its raw value through `MODRM16_TABLE`."""

    __slots__ = ("byte", "mod", "reg", "rm", "displacement", "addressing_mode")

    def __init__(
        self,
        byte: int,
        mod: int,
        reg: int,
        rm: int,
        displacement: Displacement,
        addressing_mode: AddressOffset16,
    ) -> None:
        self.byte = byte
        self.mod = mod
        self.reg = reg
        self.rm = rm
        self.displacement = displacement
        self.addressing_mode = addressing_mode

    @classmethod
    def from_byte(cls, byte: int) -> "ModRmByte16":
        return MODRM16_TABLE[byte]

    @classmethod
    def read(cls, reader: ByteReader, instruction_bytes: bytearray) -> "ModRmByte16":
        """Read a ModRM byte and, when it addresses memory, its displacement.

        The displacement bytes belong to the instruction stream immediately
        after the ModRM byte, so they are read here rather than by the operand
        resolver -- by the time an operand is built the cursor must already be
        past the addressing information.
        """
        raw = reader.read_u8()
        instruction_bytes.append(raw)
        modrm = MODRM16_TABLE[raw]

        if modrm.mod != _REGISTER_MODE:
            if modrm.displacement.width == 1:
                disp = reader.read_u8()
                instruction_bytes.append(disp)
                modrm = ModRmByte16(
                    raw,
                    modrm.mod,
                    modrm.reg,
                    modrm.rm,
                    Displacement.disp8(disp - 0x100 if disp & 0x80 else disp),
                    modrm.addressing_mode,
                )
            elif modrm.displacement.width == 2:
                disp = reader.read_u16()
                instruction_bytes.extend(disp.to_bytes(2, "little"))
                signed = disp - 0x1_0000 if disp & 0x8000 else disp
                modrm = ModRmByte16(
                    raw,
                    modrm.mod,
                    modrm.reg,
                    modrm.rm,
                    Displacement.disp16(signed),
                    modrm.addressing_mode,
                )
        return modrm

    # -- field access ---------------------------------------------------

    def mod_value(self) -> int:
        return self.mod

    def reg_value(self) -> int:
        return self.reg

    def op_extension(self) -> int:
        """The `reg` field read as a group-opcode extension (0..7)."""
        return self.reg

    def is_addressing_mode(self) -> bool:
        return self.mod != _REGISTER_MODE

    def raw_byte(self) -> int:
        return self.byte

    # -- register interpretations ---------------------------------------

    def op1_reg8(self) -> Register8:
        return REGISTER8_LUT[self.rm]

    def op1_reg16(self) -> Register16:
        return REGISTER16_LUT[self.rm]

    def op1_reg32(self) -> Register32:
        return REGISTER32_LUT[self.rm]

    def op2_reg8(self) -> Register8:
        return REGISTER8_LUT[self.reg]

    def op2_reg16(self) -> Register16:
        return REGISTER16_LUT[self.reg]

    def op2_reg32(self) -> Register32:
        return REGISTER32_LUT[self.reg]

    def op2_segment_reg16(self) -> Register16:
        return SREGISTER16_LUT[self.reg]

    def op2_segment_reg16_386(self) -> Register16:
        return SREGISTER16_LUT_386[self.reg]

    def op2_reg_ctrl(self) -> ControlRegister:
        return CREGISTER_LUT[self.reg]

    def op2_reg_dbg(self) -> DebugRegister:
        return DREGISTER_LUT[self.reg]

    def op2_reg_test(self) -> TestRegister:
        return TREGISTER_LUT[self.reg]

    # -- addressing -----------------------------------------------------

    def address_offset(self, displacement: Displacement) -> AddressOffset16:
        """The addressing mode with the freshly-read displacement folded in."""
        return _with_displacement(self.addressing_mode, displacement)

    def set_displacement(self, displacement: Displacement) -> None:
        self.displacement = displacement
        self.addressing_mode = _with_displacement(self.addressing_mode, displacement)

    def __repr__(self) -> str:
        return (
            f"ModRmByte16(0x{self.byte:02X} mod={self.mod} reg={self.reg} "
            f"rm={self.rm} {self.addressing_mode.name})"
        )


def _with_displacement(mode: AddressOffset16, displacement: Displacement) -> AddressOffset16:
    """Fold a freshly-read displacement into an addressing mode.

    Modes that address through a register pair or a single register keep their
    kind and take the displacement value; modes that have no displacement slot
    (register direct) are returned unchanged.
    """
    if mode.carries_displacement():
        return AddressOffset16(mode.kind, displacement.value)
    return mode


MODRM16_TABLE: tuple[ModRmByte16, ...] = _build_table()
assert len(MODRM16_TABLE) == 256
