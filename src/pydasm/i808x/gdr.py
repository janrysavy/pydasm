"""The Group Decode ROM.

On the real 8088 the GDR is a PLA that emits fifteen signals for an 8-bit
opcode, and those signals -- not the opcode's arithmetic value -- decide whether
an instruction has a ModRM byte, whether the D and W bits apply, and so on.

The disassembler only needs one of those signals (`NO_MODRM`) to decide whether
to fetch a ModRM byte, but the rest are carried because the width helpers below
read naturally through them and because they are the documented shape of the
table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..cpu_common import OperandSize

GDR_IO: Final = 0b0000_0000_0000_0001
GDR_NO_LOAD_EA: Final = 0b0000_0000_0000_0010
GDR_GRP_345: Final = 0b0000_0000_0000_0100
GDR_PREFIX: Final = 0b0000_0000_0000_1000
GDR_NO_MODRM: Final = 0b0000_0000_0001_0000
GDR_SPECIAL_ALU: Final = 0b0000_0000_0010_0000
GDR_CLEARS_COND: Final = 0b0000_0000_0100_0000
GDR_USES_AREG: Final = 0b0000_0000_1000_0000
GDR_USES_SREG: Final = 0b0000_0001_0000_0000
GDR_D_VALID: Final = 0b0000_0010_0000_0000
GDR_NO_MC: Final = 0b0000_0100_0000_0000
GDR_W_VALID: Final = 0b0000_1000_0000_0000
GDR_FORCE_BYTE: Final = 0b0001_0000_0000_0000
GDR_L8: Final = 0b0010_0000_0000_0000
GDR_UPDATE_CARRY: Final = 0b0100_0000_0000_0000


@dataclass(frozen=True)
class GdrEntry:
    """One GDR output word."""

    value: int

    def has_modrm(self) -> bool:
        return not (self.value & GDR_NO_MODRM)

    def loads_ea(self) -> bool:
        return not (self.value & GDR_NO_LOAD_EA)

    def w_valid(self) -> bool:
        return bool(self.value & GDR_W_VALID)

    def d_valid(self) -> bool:
        return bool(self.value & GDR_D_VALID)

    def force_byte(self) -> bool:
        return bool(self.value & GDR_FORCE_BYTE)

    def set_l8(self) -> bool:
        return bool(self.value & GDR_L8)

    def width(self, opcode: int) -> OperandSize:
        """The operand width this opcode selects: the low opcode bit when W is valid."""
        if self.w_valid() and opcode & 1:
            return OperandSize.Operand16
        return OperandSize.Operand8
