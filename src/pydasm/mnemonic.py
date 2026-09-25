"""Behavioural predicates over mnemonics.

The enum and its display strings are generated (`pydasm._mnemonics`); this module
is the hand-written half -- the classification the decoder and the two
formatters ask questions of.

`to_str` is not the same as `str(mnemonic)`: `CALLF` displays as `CALL` and
`XLAT` displays as `XLATB`, because those are the names a reader expects. The
enum member name and the printed name are deliberately separate.
"""

from __future__ import annotations

from ._mnemonics import MNEMONIC_FALLBACK, MNEMONIC_STR, Mnemonic
from .cpu_common import OperandSize

__all__ = ["Mnemonic", "mnemonic_to_str", "native_o32", "native_a32", "o32_override", "o16_override"]

_STRING_OPS = frozenset(
    {
        Mnemonic.MOVSB, Mnemonic.MOVSW, Mnemonic.MOVSD,
        Mnemonic.CMPSB, Mnemonic.CMPSW, Mnemonic.CMPSD,
        Mnemonic.SCASB, Mnemonic.SCASW, Mnemonic.SCASD,
        Mnemonic.LODSB, Mnemonic.LODSW, Mnemonic.LODSD,
        Mnemonic.STOSB, Mnemonic.STOSW, Mnemonic.STOSD,
        Mnemonic.INSB, Mnemonic.INSW, Mnemonic.INSD,
        Mnemonic.OUTSB, Mnemonic.OUTSW, Mnemonic.OUTSD,
    }
)

_STOS = frozenset({Mnemonic.STOSB, Mnemonic.STOSW, Mnemonic.STOSD})
_SCAS = frozenset({Mnemonic.SCASB, Mnemonic.SCASW, Mnemonic.SCASD})
_INS = frozenset({Mnemonic.INSB, Mnemonic.INSW, Mnemonic.INSD})

#: Conditional jumps. JCXZ is a jump but not conditional in this sense.
_JCND = frozenset(
    {
        Mnemonic.JO, Mnemonic.JNO, Mnemonic.JB, Mnemonic.JNB, Mnemonic.JZ, Mnemonic.JNZ,
        Mnemonic.JBE, Mnemonic.JNBE, Mnemonic.JS, Mnemonic.JNS, Mnemonic.JP, Mnemonic.JNP,
        Mnemonic.JL, Mnemonic.JNL, Mnemonic.JLE, Mnemonic.JNLE,
    }
)

_JUMPS = _JCND | {
    Mnemonic.JCXZ, Mnemonic.JECXZ, Mnemonic.JMP, Mnemonic.JMPF,
}

#: Aliases iced-x86 renders differently. Used only when the caller asks for
#: iced-style mnemonics; marty_dasm's own spelling is the default.
_ICED_ALIASES = {
    Mnemonic.JNL: "JGE",
    Mnemonic.JNLE: "JG",
    Mnemonic.JNB: "JAE",
    Mnemonic.JNBE: "JA",
    Mnemonic.JZ: "JE",
    Mnemonic.JNZ: "JNE",
    Mnemonic.SETZ: "SETE",
    Mnemonic.SETNZ: "SETNE",
    Mnemonic.SETNL: "SETGE",
    Mnemonic.SETNLE: "SETG",
    Mnemonic.SETNBE: "SETA",
    Mnemonic.SETNB: "SETAE",
}

_NEEDS_OPERAND_SIZE_OVERRIDE = frozenset(
    {
        Mnemonic.STR, Mnemonic.LIDT, Mnemonic.SIDT, Mnemonic.SLDT, Mnemonic.LLDT,
        Mnemonic.LMSW, Mnemonic.VERR, Mnemonic.VERW, Mnemonic.JCXZ, Mnemonic.POP,
    }
)

_DISAMBIGUATE_OPERAND_SIZE = frozenset(
    {
        Mnemonic.PUSH, Mnemonic.LOCK, Mnemonic.POP, Mnemonic.JO, Mnemonic.JNO, Mnemonic.JB,
        Mnemonic.JNB, Mnemonic.JZ, Mnemonic.JNZ, Mnemonic.JBE, Mnemonic.JNBE, Mnemonic.JS,
        Mnemonic.JNS, Mnemonic.JP, Mnemonic.JNP, Mnemonic.JL, Mnemonic.JNL, Mnemonic.JLE,
        Mnemonic.JNLE, Mnemonic.ENTER, Mnemonic.LEAVE, Mnemonic.LOOPNE, Mnemonic.LOOPE,
        Mnemonic.LOOP, Mnemonic.JCXZ, Mnemonic.JECXZ, Mnemonic.JMP, Mnemonic.LMSW,
        Mnemonic.LIDT, Mnemonic.STR, Mnemonic.SIDT, Mnemonic.SLDT, Mnemonic.LLDT,
        Mnemonic.VERR, Mnemonic.VERW,
    }
)

_SUPPRESS_OPERAND_PREFIX = frozenset(
    {
        Mnemonic.SETO, Mnemonic.SETNO, Mnemonic.SETB, Mnemonic.SETNB, Mnemonic.SETZ,
        Mnemonic.SETNZ, Mnemonic.SETBE, Mnemonic.SETNBE, Mnemonic.SETS, Mnemonic.SETNS,
        Mnemonic.SETP, Mnemonic.SETNP, Mnemonic.SETL, Mnemonic.SETNL, Mnemonic.SETLE,
        Mnemonic.SETNLE,
    }
)

_LOOPS = frozenset({Mnemonic.LOOP, Mnemonic.LOOPE, Mnemonic.LOOPNE})

_REP1_NEEDS_REPNE = frozenset(
    {
        Mnemonic.MOVSB, Mnemonic.MOVSW, Mnemonic.MOVSD, Mnemonic.CMPSB, Mnemonic.CMPSW,
        Mnemonic.CMPSD, Mnemonic.SCASB, Mnemonic.SCASW, Mnemonic.SCASD, Mnemonic.LODSB,
        Mnemonic.LODSW, Mnemonic.LODSD, Mnemonic.STOSB, Mnemonic.STOSW, Mnemonic.STOSD,
        Mnemonic.INSB, Mnemonic.INSW, Mnemonic.INSD, Mnemonic.OUTSB, Mnemonic.OUTSW,
        Mnemonic.OUTSD,
    }
)

_REP2_NEEDS_REPE = _SCAS | {Mnemonic.CMPSB, Mnemonic.CMPSW, Mnemonic.CMPSD}
_REP2_NEEDS_REP = {
    Mnemonic.MOVSB, Mnemonic.MOVSW, Mnemonic.MOVSD,
    Mnemonic.LODSB, Mnemonic.LODSW, Mnemonic.LODSD,
}

#: Word-sized mnemonics that become doubleword on a 32-bit operand size.
_NATIVE_O32 = {
    Mnemonic.CBW: Mnemonic.CWDE,
    Mnemonic.CWD: Mnemonic.CDQ,
    Mnemonic.STOSW: Mnemonic.STOSD,
    Mnemonic.MOVSW: Mnemonic.MOVSD,
    Mnemonic.LODSW: Mnemonic.LODSD,
    Mnemonic.SCASW: Mnemonic.SCASD,
    Mnemonic.CMPSW: Mnemonic.CMPSD,
    Mnemonic.INSW: Mnemonic.INSD,
    Mnemonic.OUTSW: Mnemonic.OUTSD,
}

_O32_OVERRIDE = {
    Mnemonic.NOP: Mnemonic.XCHG,
    Mnemonic.IRET: Mnemonic.IRETD,
    Mnemonic.RET: Mnemonic.RETD,
    Mnemonic.RETF: Mnemonic.RETFD,
    Mnemonic.PUSHF: Mnemonic.PUSHFD,
    Mnemonic.PUSHA: Mnemonic.PUSHAD,
    Mnemonic.POPF: Mnemonic.POPFD,
    Mnemonic.POPA: Mnemonic.POPAD,
}

_O16_OVERRIDE = {
    Mnemonic.NOP: Mnemonic.XCHG,
    Mnemonic.PUSHF: Mnemonic.PUSHFW,
    Mnemonic.PUSHA: Mnemonic.PUSHAW,
    Mnemonic.POPA: Mnemonic.POPAW,
    Mnemonic.IRET: Mnemonic.IRETW,
    Mnemonic.RET: Mnemonic.RETW,
    Mnemonic.RETF: Mnemonic.RETFW,
    Mnemonic.POPF: Mnemonic.POPFW,
}


def mnemonic_to_str(mnemonic: Mnemonic) -> str:
    """The mnemonic as it should be printed."""
    return MNEMONIC_STR.get(mnemonic, MNEMONIC_FALLBACK)


def is_string_op(mnemonic: Mnemonic) -> bool:
    return mnemonic in _STRING_OPS


def is_stos(mnemonic: Mnemonic) -> bool:
    return mnemonic in _STOS


def is_scas(mnemonic: Mnemonic) -> bool:
    return mnemonic in _SCAS


def is_ins(mnemonic: Mnemonic) -> bool:
    return mnemonic in _INS


def is_jump(mnemonic: Mnemonic) -> bool:
    return mnemonic in _JUMPS


def is_jcnd(mnemonic: Mnemonic) -> bool:
    return mnemonic in _JCND


def is_far(mnemonic: Mnemonic) -> bool:
    return mnemonic in (Mnemonic.JMPF, Mnemonic.CALLF)


def is_call(mnemonic: Mnemonic) -> bool:
    return mnemonic in (Mnemonic.CALL, Mnemonic.CALLF)


def is_push(mnemonic: Mnemonic) -> bool:
    return mnemonic is Mnemonic.PUSH


def is_pop(mnemonic: Mnemonic) -> bool:
    return mnemonic is Mnemonic.POP


def is_push_or_pop(mnemonic: Mnemonic) -> bool:
    return mnemonic in (Mnemonic.PUSH, Mnemonic.POP)


def is_loop(mnemonic: Mnemonic) -> bool:
    return mnemonic in _LOOPS


def native_o32(mnemonic: Mnemonic) -> Mnemonic:
    return _NATIVE_O32.get(mnemonic, mnemonic)


def native_a32(mnemonic: Mnemonic) -> Mnemonic:
    return Mnemonic.JECXZ if mnemonic is Mnemonic.JCXZ else mnemonic


def a16_override(mnemonic: Mnemonic) -> Mnemonic:
    return Mnemonic.JCXZ if mnemonic is Mnemonic.JECXZ else mnemonic


def a32_override(mnemonic: Mnemonic) -> Mnemonic:
    return Mnemonic.JECXZ if mnemonic is Mnemonic.JCXZ else mnemonic


def o32_override(mnemonic: Mnemonic) -> Mnemonic:
    return _O32_OVERRIDE.get(mnemonic, mnemonic)


def o16_override(mnemonic: Mnemonic) -> Mnemonic:
    return _O16_OVERRIDE.get(mnemonic, mnemonic)


def needs_operand_size_override_prefix(mnemonic: Mnemonic) -> bool:
    return mnemonic in _NEEDS_OPERAND_SIZE_OVERRIDE


def disambiguate_operand_size(mnemonic: Mnemonic) -> bool:
    return mnemonic in _DISAMBIGUATE_OPERAND_SIZE


def suppress_operand_prefix(mnemonic: Mnemonic) -> bool:
    return mnemonic in _SUPPRESS_OPERAND_PREFIX


def to_iced_str(mnemonic: Mnemonic) -> str | None:
    return _ICED_ALIASES.get(mnemonic)


def rep1_prefix(mnemonic: Mnemonic) -> str:
    return "repne" if mnemonic in _REP1_NEEDS_REPNE else "rep"


def rep2_prefix(mnemonic: Mnemonic) -> str:
    if mnemonic in _REP2_NEEDS_REPE:
        return "repe"
    return "rep"


# The widest operand size an ALU-style opcode can select, used by callers that
# need to reason about a mnemonic's natural width without a decoded instruction.
_NATURAL_SIZE = {
    Mnemonic.MOVSB: OperandSize.Operand8,
    Mnemonic.MOVSW: OperandSize.Operand16,
    Mnemonic.MOVSD: OperandSize.Operand32,
}


def natural_operand_size(mnemonic: Mnemonic) -> OperandSize:
    return _NATURAL_SIZE.get(mnemonic, OperandSize.NoOperand)
