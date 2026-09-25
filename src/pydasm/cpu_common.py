"""Registers, operand sizes, addressing modes and operand types.

Shared by every CPU family. The register lookup tables are indexed by the 3-bit
field they come from, so `REGISTER8_LUT[modrm.op2]` is the register a `reg`
field names -- and the segment table repeats its four entries twice, because the
high bit is ignored rather than rejected.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Final, Optional


class PrefixFlags:
    """Bit assignments for instruction prefixes.

    `raw_prefix_flags` records every prefix byte seen; `effective_prefix_flags`
    records only those that changed the decode. An `o32` on a 16-bit operand is
    present but ineffective, and the formatter has to be able to tell.
    """

    ES_OVERRIDE: Final = 0b0000_0000_0000_0100
    CS_OVERRIDE: Final = 0b0000_0000_0000_1000
    SS_OVERRIDE: Final = 0b0000_0000_0001_0000
    DS_OVERRIDE: Final = 0b0000_0000_0010_0000
    FS_OVERRIDE: Final = 0b0000_0000_0100_0000
    GS_OVERRIDE: Final = 0b0000_0000_1000_0000
    SEG_OVERRIDE_MASK: Final = 0b0000_0000_1111_1100
    LOCK: Final = 0b0000_0001_0000_0000
    REP1: Final = 0b0000_0010_0000_0000
    REP2: Final = 0b0000_0100_0000_0000
    REP3: Final = 0b0000_1000_0000_0000
    REP4: Final = 0b0001_0000_0000_0000
    REP_MASK: Final = 0b0001_1110_0000_0000
    OPERAND_SIZE: Final = 0b0010_0000_0000_0000
    ADDRESS_SIZE: Final = 0b0100_0000_0000_0000
    EXTENDED_0F: Final = 0b1000_0000_0000_0000


class Register8(enum.Enum):
    AL = "al"
    CL = "cl"
    DL = "dl"
    BL = "bl"
    AH = "ah"
    CH = "ch"
    DH = "dh"
    BH = "bh"

    def __str__(self) -> str:
        return self.value


class Register16(enum.Enum):
    AX = "ax"
    CX = "cx"
    DX = "dx"
    BX = "bx"
    SP = "sp"
    BP = "bp"
    SI = "si"
    DI = "di"
    ES = "es"
    CS = "cs"
    SS = "ss"
    DS = "ds"
    FS = "fs"
    GS = "gs"
    PC = "ip"
    InvalidRegister = "invalid"

    def __str__(self) -> str:
        return self.value

    def is_segment(self) -> bool:
        return self in _SEGMENT_REGISTERS

    # marty_dasm spells this predicate both ways; keep both working.
    is_segment_reg = is_segment


class Register32(enum.Enum):
    EAX = "eax"
    ECX = "ecx"
    EDX = "edx"
    EBX = "ebx"
    ESP = "esp"
    EBP = "ebp"
    ESI = "esi"
    EDI = "edi"
    ES = "es"
    CS = "cs"
    SS = "ss"
    DS = "ds"
    FS = "fs"
    GS = "gs"
    PC = "eip"
    InvalidRegister = "invalid"

    def __str__(self) -> str:
        return self.value

    def is_segment(self) -> bool:
        return self in _SEGMENT_REGISTERS32


class ControlRegister(enum.Enum):
    CR0 = "cr0"
    CR1 = "cr1"
    CR2 = "cr2"
    CR3 = "cr3"
    CR4 = "cr4"
    CR5 = "cr5"
    CR6 = "cr6"
    CR7 = "cr7"
    InvalidRegister = "invalid"

    def __str__(self) -> str:
        return self.value


class DebugRegister(enum.Enum):
    DR0 = "dr0"
    DR1 = "dr1"
    DR2 = "dr2"
    DR3 = "dr3"
    DR4 = "dr4"
    DR5 = "dr5"
    DR6 = "dr6"
    DR7 = "dr7"
    InvalidRegister = "invalid"

    def __str__(self) -> str:
        return self.value


class TestRegister(enum.Enum):
    TR4 = "tr4"
    TR5 = "tr5"
    TR6 = "tr6"
    TR7 = "tr7"
    InvalidRegister = "invalid"

    def __str__(self) -> str:
        return self.value


_SEGMENT_REGISTERS = frozenset(
    {Register16.ES, Register16.CS, Register16.SS, Register16.DS, Register16.FS, Register16.GS}
)
_SEGMENT_REGISTERS32 = frozenset(
    {Register32.ES, Register32.CS, Register32.SS, Register32.DS, Register32.FS, Register32.GS}
)

REGISTER8_LUT: Final[tuple[Register8, ...]] = (
    Register8.AL,
    Register8.CL,
    Register8.DL,
    Register8.BL,
    Register8.AH,
    Register8.CH,
    Register8.DH,
    Register8.BH,
)

REGISTER16_LUT: Final[tuple[Register16, ...]] = (
    Register16.AX,
    Register16.CX,
    Register16.DX,
    Register16.BX,
    Register16.SP,
    Register16.BP,
    Register16.SI,
    Register16.DI,
)

REGISTER32_LUT: Final[tuple[Register32, ...]] = (
    Register32.EAX,
    Register32.ECX,
    Register32.EDX,
    Register32.EBX,
    Register32.ESP,
    Register32.EBP,
    Register32.ESI,
    Register32.EDI,
)

# The segment register table only has four entries' worth of meaning; the top
# bit of the field is ignored, so ES/CS/SS/DS repeat. 386 added FS/GS into the
# slots that a 16-bit table reuses.
SREGISTER16_LUT: Final[tuple[Register16, ...]] = (
    Register16.ES,
    Register16.CS,
    Register16.SS,
    Register16.DS,
    Register16.ES,
    Register16.CS,
    Register16.SS,
    Register16.DS,
)

SREGISTER16_LUT_386: Final[tuple[Register16, ...]] = (
    Register16.ES,
    Register16.CS,
    Register16.SS,
    Register16.DS,
    Register16.FS,
    Register16.GS,
    Register16.InvalidRegister,
    Register16.InvalidRegister,
)

CREGISTER_LUT: Final[tuple[ControlRegister, ...]] = tuple(ControlRegister)  # CR0..CR7 then Invalid
DREGISTER_LUT: Final[tuple[DebugRegister, ...]] = tuple(DebugRegister)  # DR0..DR7 then Invalid
TREGISTER_LUT: Final[tuple[TestRegister, ...]] = (
    TestRegister.InvalidRegister,
    TestRegister.InvalidRegister,
    TestRegister.InvalidRegister,
    TestRegister.InvalidRegister,
    TestRegister.TR4,
    TestRegister.TR5,
    TestRegister.TR6,
    TestRegister.TR7,
)


class SegmentSize(enum.Enum):
    """The default width of a segment: 16-bit real mode, or 32-bit protected."""

    Segment16 = 16
    Segment32 = 32

    def operand_size_override(self) -> "OperandSize":
        return OperandSize.Operand32 if self is SegmentSize.Segment16 else OperandSize.Operand16

    def address_size_override(self) -> "AddressSize":
        return AddressSize.Address32 if self is SegmentSize.Segment16 else AddressSize.Address16


class AddressSize(enum.Enum):
    Address16 = 16
    Address32 = 32

    def with_override(self) -> "AddressSize":
        return AddressSize.Address32 if self is AddressSize.Address16 else AddressSize.Address16


class OperandSize(enum.Enum):
    NoOperand = 0
    Operand8 = 8
    Operand16 = 16
    Operand32 = 32

    def with_override(self) -> "OperandSize":
        if self is OperandSize.Operand16:
            return OperandSize.Operand32
        if self is OperandSize.Operand32:
            return OperandSize.Operand16
        return self


class Displacement:
    """A decoded displacement: absent, or 8/16/32 bits wide."""

    __slots__ = ("width", "value")

    def __init__(self, width: int = 0, value: int = 0) -> None:
        self.width = width
        self.value = value

    @classmethod
    def none(cls) -> "Displacement":
        return cls(0, 0)

    @classmethod
    def disp8(cls, value: int = 0) -> "Displacement":
        return cls(1, value)

    @classmethod
    def disp16(cls, value: int = 0) -> "Displacement":
        return cls(2, value)

    @classmethod
    def disp32(cls, value: int = 0) -> "Displacement":
        return cls(4, value)

    def is_some(self) -> bool:
        return self.width != 0

    def __len__(self) -> int:
        return self.width

    def __bool__(self) -> bool:
        return self.width != 0

    def __repr__(self) -> str:
        return f"Displacement(width={self.width}, value={self.value:#x})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Displacement):
            return NotImplemented
        return self.width == other.width and self.value == other.value

    def __str__(self) -> str:
        # marty_dasm renders 'NoDisp' as the literal text [None], and a signed
        # displacement with a forced sign and an 'h' suffix.
        if self.width == 0:
            return "[None]"
        if self.value < 0:
            return f"-{abs(self.value):X}h"
        return f"+{self.value:X}h"


#: The 16-bit effective-address forms, as (kind, register text). Kinds ending in
#: `_d8`/`_d16` carry a displacement of that width; `disp16` is the absolute form
#: that `mod=00 r/m=110` selects. The names match marty_dasm's enum variants.
ADDR16_FORMS: Final[tuple[tuple[str, str], ...]] = (
    ("none", ""),
    ("bx_si", "bx+si"),
    ("bx_di", "bx+di"),
    ("bp_si", "bp+si"),
    ("bp_di", "bp+di"),
    ("si", "si"),
    ("di", "di"),
    ("disp16", ""),
    ("bx", "bx"),
    ("bx_si_d8", "bx+si"),
    ("bx_di_d8", "bx+di"),
    ("bp_si_d8", "bp+si"),
    ("bp_di_d8", "bp+di"),
    ("si_d8", "si"),
    ("di_d8", "di"),
    ("bp_d8", "bp"),
    ("bx_d8", "bx"),
    ("bx_si_d16", "bx+si"),
    ("bx_di_d16", "bx+di"),
    ("bp_si_d16", "bp+si"),
    ("bp_di_d16", "bp+di"),
    ("si_d16", "si"),
    ("di_d16", "di"),
    ("bp_d16", "bp"),
    ("bx_d16", "bx"),
)

ADDR16_REGISTER_TEXT: Final[dict[str, str]] = dict(ADDR16_FORMS)


def addr16_base_kind(kind: str) -> str:
    """Strip the displacement suffix: `bx_si_d8` -> `bx_si`."""
    if kind.endswith("_d8"):
        return kind[:-3]
    if kind.endswith("_d16"):
        return kind[:-4]
    return kind


@dataclass(frozen=True)
class AddressOffset16:
    """A 16-bit effective address: base/index registers plus an optional displacement.

    Modelled as a tagged record rather than an enum because most forms carry a
    displacement, so `mod=01 [bx+si+disp8]` and `mod=10 [bx+si+disp16]` differ in
    both their kind and their payload.
    """

    kind: str
    displacement: int = 0

    def is_none(self) -> bool:
        return self.kind == "none"

    def carries_displacement(self) -> bool:
        return self.kind in _ADDR16_DISP_KINDS

    def base_register(self) -> Register16:
        """The segment a bare [mem] operand addresses through.

        Anything involving BP defaults to SS; everything else to DS. This is the
        segment the NASM formatter prints when no override is present.
        """
        if addr16_base_kind(self.kind).startswith("bp"):
            return Register16.SS
        return Register16.DS

    def __str__(self) -> str:
        """Render as marty_dasm's Display does: registers then a signed displacement."""
        text = ADDR16_REGISTER_TEXT.get(self.kind, "")
        if self.kind == "disp16":
            return f"{self.displacement & 0xFFFF:X}h"
        if self.kind not in _ADDR16_DISP_KINDS:
            return text
        return f"{text}{_signed_hex(self.displacement)}"


_ADDR16_DISP_KINDS = frozenset(
    kind for kind, _ in ADDR16_FORMS if kind.endswith(("_d8", "_d16"))
) | {"disp16"}

_ADDR16_D8_KINDS = frozenset(kind for kind, _ in ADDR16_FORMS if kind.endswith("_d8"))
_ADDR16_D16_KINDS = frozenset(kind for kind, _ in ADDR16_FORMS if kind.endswith("_d16"))


def _signed_hex(value: int) -> str:
    """A displacement with a forced sign: small magnitudes in decimal, else hex."""
    magnitude = abs(value)
    if magnitude == 0:
        return ""
    if magnitude < 10:
        return f"-{magnitude}" if value < 0 else f"+{magnitude}"
    text = f"{magnitude:X}"
    return f"-{text}h" if value < 0 else f"+{text}h"


class SibScale(enum.Enum):
    One = 1
    Two = 2
    Four = 4
    Eight = 8

    def __str__(self) -> str:
        return f"*{self.value}"


class ScaledIndex(enum.Enum):
    None_ = "none"
    EaxScaled = (Register32.EAX,)
    EcxScaled = (Register32.ECX,)
    EdxScaled = (Register32.EDX,)
    EbxScaled = (Register32.EBX,)
    EbpScaled = (Register32.EBP,)
    EsiScaled = (Register32.ESI,)
    EdiScaled = (Register32.EDI,)

    def is_some(self) -> bool:
        return self is not ScaledIndex.None_


class BaseRegister:
    """An optional 32-bit base register in a SIB byte."""

    __slots__ = ("register",)

    def __init__(self, register: Optional[Register32] = None) -> None:
        self.register = register

    def is_some(self) -> bool:
        return self.register is not None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseRegister):
            return NotImplemented
        return self.register is other.register

    def __repr__(self) -> str:
        return f"BaseRegister({self.register})"

    def __str__(self) -> str:
        return "" if self.register is None else str(self.register)


class AddressOffset32:
    """A 32-bit effective address: base, scaled index, displacement, or a SIB byte.

    `sib` is None for the non-SIB forms and a `(base, index, displacement_width)`
    triple otherwise. `ebp_relative` marks the SIB forms that address through SS
    and that NASM needs a bare `[disp32]` for.
    """

    __slots__ = ("kind", "sib", "displacement")

    def __init__(self, kind: str, sib: Optional[tuple[BaseRegister, ScaledIndex]] = None, displacement: int = 0) -> None:
        self.kind = kind
        self.sib = sib
        self.displacement = displacement

    def base_register(self) -> Register16:
        if self.kind in ("ebp", "ebp_d8", "ebp_d32", "sib_ebp"):
            return Register16.SS
        if self.sib is not None and self.sib[0].register is Register32.ESP:
            return Register16.SS
        return Register16.DS

    def __repr__(self) -> str:
        return f"AddressOffset32({self.kind})"


@dataclass(frozen=True)
class OperandType:
    """A resolved operand: what the instruction actually operates on.

    `kind` names the shape and `value` carries it. Rather than one class per
    shape, everything the decoder, the Instruction model and the two formatters
    need is expressed as a small tagged record -- which keeps the operand types
    comparable and printable without a visitor.
    """

    kind: str
    value: object = None
    size: OperandSize = OperandSize.NoOperand

    def is_memory(self) -> bool:
        return self.kind in _MEMORY_KINDS

    def is_address(self) -> bool:
        return self.kind in ("addr16", "addr32")

    def is_register(self) -> bool:
        return self.kind in ("reg8", "reg16")

    def is_segment_register(self) -> bool:
        if self.kind == "reg16":
            return self.value.is_segment()
        if self.kind == "reg32":
            return self.value.is_segment()
        return False

    def __str__(self) -> str:
        return f"{self.kind}({self.value!r})" if self.value is not None else self.kind


_MEMORY_KINDS = frozenset(
    {
        "addr16",
        "addr32",
        "offset8_16",
        "offset8_32",
        "offset16_16",
        "offset16_32",
        "offset32_16",
        "offset32_32",
        "far16",
        "far32",
        "m16pair",
    }
)

# Sentinel operands, shared so identity comparisons are cheap.
NO_OPERAND: Final = OperandType("none")
INVALID_OPERAND: Final = OperandType("invalid")


def operand_size_of(operand: OperandType) -> OperandSize:
    """The width of an operand, mirroring `OperandType::size()`.

    Addressing modes carry their own size; everything else is implied by the
    kind. Anything unmapped is `NoOperand` rather than an error.
    """
    kind = operand.kind
    if kind in ("imm8", "imm8s", "rel8", "reg8"):
        return OperandSize.Operand8
    if kind in ("imm16", "rel16", "offset16_16", "offset32_16", "offset8_16", "reg16"):
        return OperandSize.Operand16
    if kind in (
        "imm32",
        "rel32",
        "offset8_32",
        "offset32_32",
        "offset16_32",
        "reg32",
        "creg",
        "dreg",
        "treg",
    ):
        return OperandSize.Operand32
    if kind in ("addr16", "addr32"):
        return operand.size
    return OperandSize.NoOperand
