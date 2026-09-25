"""A Ghidra-compatible listing renderer.

Ghidra is not a formatter you can reimplement from its documentation, so this
module is written against a *specimen*: 29,525 lines of real Ghidra output taken
over an x86 real-mode DOS image with a byte-anchored exporter. Every rule below
was read off that output and is pinned by `tests/test_ghidra_corpus.py` -- the
corpus comparison is the specification.

That corpus is not distributed with this repository, because the image it was
taken over is a third-party binary that cannot be redistributed. See `NOTICE`;
`tests/conftest.py` explains how to supply it.

The line format is:

    <seg>:<off> <mnemonic padded to 9><operands> ; bytes=<hex pairs> len=<n>

The bytes are from the *relocated* image: Ghidra applies the MZ fixups before
disassembling, so a far pointer's segment field is the loaded one, not the one
in the file. Decoding the raw file gives plausible-looking wrong segments -- see
`pydasm.mz`.

Three rules account for most of the difference between a naive port and this
one, and all three are the kind of thing that looks right until you diff it:

**Addresses are linear, then re-normalised.** A far pointer, a relative branch
and a memory reference all print as `0xSSSS:0xOOOO`, but not the segment the
instruction bytes carry. The bytes give a segment and an offset; Ghidra converts
to a linear address and splits it at a 64K boundary:

    seg = (linear >> 16) << 12,   off = linear & 0xFFFF

So `9A 41 04 57 20` -- segment 0x2057, offset 0x0441 -- renders as
`0x2000:09b1`, because both spell 0x209B1. Relative branches wrap in 20 bits for
the same reason.

**A memory operand names its size unless the instruction form already does.**
`MOV word ptr [BP + -0x4], AX` needs the `word`; `MOV [0x65be], AX` does not,
because the accumulator opcode `A3` fixes the width. Ghidra shows the size
exactly when a reader -- or an assembler -- could not infer it.
"""

from __future__ import annotations

from typing import Optional

from .cpu_common import (
    ADDR16_REGISTER_TEXT,
    NO_OPERAND,
    OperandSize,
    OperandType,
    Register8,
    Register16,
    addr16_base_kind,
)
from .errors import DecodeError
from .instruction import Instruction
from .mnemonic import Mnemonic

#: The mnemonic field is left-justified into nine columns and the trailing
#: spaces are *kept*, so an instruction with no operands still ends in a run of
#: spaces before the `;`. It reads like trimming is safe; it is not.
MNEMONIC_COLUMN = 9

#: Ghidra's names where marty_dasm's enum member name is not what it prints.
#:
#: The condition-code spellings are the interesting part. marty_dasm names each
#: jump by one flag sense (`JNBE`, "jump if not below or equal"); Ghidra names it
#: by the complementary test (`JA`, "jump if above"). Both describe the same
#: instruction and both are correct, but they are different strings, and a
#: listing is only useful if it reads the way the rest of the toolchain reads.
_MNEMONIC_OVERRIDES = {
    Mnemonic.XLAT: "XLAT",
    Mnemonic.JB: "JC",
    Mnemonic.JNB: "JNC",
    Mnemonic.JNL: "JGE",
    Mnemonic.JNLE: "JG",
    Mnemonic.JNBE: "JA",
}

#: `MOV r/m16, Sreg` (8C) and `MOV Sreg, r/m16` (8E). Ghidra prints these
#: register-first regardless of which side the encoding puts first.
_MOV_SREG_OPCODES = frozenset({0x8C, 0x8E})

#: The shift and rotate group. The count is implied by the opcode and printed
#: anyway: one for D0/D1, CL for D2/D3, an explicit byte for C0/C1.
_SHIFT_GROUP_OPCODES = frozenset({0xD0, 0xD1, 0xD2, 0xD3, 0xC0, 0xC1})

_SHIFT_MNEMONICS = frozenset(
    {Mnemonic.ROL, Mnemonic.ROR, Mnemonic.RCL, Mnemonic.RCR, Mnemonic.SHL, Mnemonic.SHR, Mnemonic.SAR}
)

#: String instructions. Ghidra writes their implicit operands out, because the
#: segment and the pointer registers are half the meaning of the instruction.
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

#: `XCHG` reads its operands in the order Ghidra writes them.
_XCHG_MNEMONICS = frozenset({Mnemonic.XCHG})

#: Opcodes whose memory operand omits the size because the instruction form
#: already fixes the width:
#:
#:   A0-A3  the accumulator is named in the opcode, so AL/AX says how wide
#:   C4/C5  LES/LDS read a pointer whose size is fixed at 16:16
#:   8D     LEA computes an address, which has no width
#:   FF /3, FF /5  far indirect call/jump, which Ghidra also prints without a
#:                 segment override
_SIZE_IMPLIED_OPCODES = frozenset({0xA0, 0xA1, 0xA2, 0xA3, 0xC4, 0xC5, 0x8D})

#: `FF /3` and `FF /5` are the far indirect call and jump.
_FAR_INDIRECT_EXTENSIONS = frozenset({3, 5})

#: Which `83 /x` operations treat their 8-bit immediate as signed.
#:
#: This is not a style choice -- it comes from Ghidra's own SLEIGH spec
#: (`x86/data/languages/ia.sinc`), which declares the token per operation:
#: `ADD`, `ADC`, `SBB`, `SUB` and `CMP` take `simm8` (signed, so `-0x1`), while
#: `OR`, `AND` and `XOR` take `usimm8` (zero-extended, so `0xffff`). The two
#: look arbitrary side by side and are perfectly consistent once you know the
#: logical operations have no sign to preserve.
_SIGNED_IMM8_EXTENSIONS = frozenset({0, 2, 3, 5, 7})

_SIZE_WORDS = {
    OperandSize.Operand8: "byte",
    OperandSize.Operand16: "word",
    OperandSize.Operand32: "dword",
}


def normalize(linear: int) -> tuple[int, int]:
    """Split a linear address into the segment:offset pair Ghidra displays."""
    return ((linear >> 16) << 12, linear & 0xFFFF)


def format_pointer(linear: int) -> str:
    """A far pointer as Ghidra writes it: hex segment, colon, *no* second `0x`.

    A memory reference renders its displacement as `0x1234` but a far pointer
    target renders as `0x2000:09b1`. Both are hex; only one repeats the prefix.
    """
    segment, offset = normalize(linear)
    return f"0x{segment:04x}:{offset:04x}"


def format_number(value: int) -> str:
    """Ghidra's scalar style: lowercase hex, `-` outside the `0x`."""
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


def _raw_opcode(instruction: Instruction) -> int:
    """The opcode byte, with any prefix bytes skipped."""
    return instruction.instruction_bytes[instruction.opcode_offset]


#: Prefix byte -> the segment register it overrides, if any.
_SEGMENT_PREFIXES = {
    0x26: Register16.ES,
    0x2E: Register16.CS,
    0x36: Register16.SS,
    0x3E: Register16.DS,
}


def _segment_override(instruction: Instruction) -> Optional[Register16]:
    """The effective segment override, read from the prefix bytes.

    Only the last override counts: `26 2E MOV AX,[BX]` addresses through CS,
    because each override replaces the previous one rather than accumulating.
    """
    segment = None
    for byte in instruction.prefix_bytes:
        if byte in _SEGMENT_PREFIXES:
            segment = _SEGMENT_PREFIXES[byte]
    return segment


def _rep_flags(instruction: Instruction) -> tuple[bool, bool]:
    """Whether an F2 or an F3 prefix is present, as (rep1, rep2)."""
    has_rep1 = any(byte == 0xF2 for byte in instruction.prefix_bytes)
    has_rep2 = any(byte == 0xF3 for byte in instruction.prefix_bytes)
    return has_rep1, has_rep2


def _modrm_extension(instruction: Instruction) -> Optional[int]:
    """The ModRM `reg` field read as a group extension, if there is one."""
    if not instruction.has_modrm:
        return None
    return (instruction.instruction_bytes[instruction.modrm_offset] >> 3) & 0x07


def _supplies_own_size(instruction: Instruction) -> bool:
    """Whether the instruction form makes a memory operand's width unambiguous."""
    opcode = _raw_opcode(instruction)
    if opcode in _SIZE_IMPLIED_OPCODES:
        return True
    if opcode == 0xFF:
        return _modrm_extension(instruction) in _FAR_INDIRECT_EXTENSIONS
    return False


def _shows_segment_override(instruction: Instruction) -> bool:
    """Segment overrides print on every memory operand except far indirect.

    `FF /3` and `FF /5` read a pair the mnemonic already calls far, and Ghidra
    omits the segment there even when the instruction carries one. It is the one
    place the rule "print the override if there is one" does not hold.
    """
    if _segment_override(instruction) is None:
        return False
    if _raw_opcode(instruction) == 0xFF:
        return _modrm_extension(instruction) not in _FAR_INDIRECT_EXTENSIONS
    return True


def ghidra_mnemonic(instruction: Instruction) -> str:
    """The mnemonic column, including any REP suffix the prefixes imply."""
    base = _MNEMONIC_OVERRIDES.get(instruction.mnemonic, instruction.mnemonic.name)
    if instruction.mnemonic not in _STRING_OPS:
        return base
    return base + _rep_suffix(instruction)


def _rep_suffix(instruction: Instruction) -> str:
    """`.REP`, `.REPNE` or `.REPE`, spelled the way the mnemonic's own rep is.

    Which byte means which is per-mnemonic: F3 is `rep` before MOVS but `repe`
    before CMPS, and F2 is `repne` before SCAS. That mapping already exists for
    the NASM formatter (`mnemonic.rep1_prefix`/`rep2_prefix`); this reuses it
    rather than restating it.
    """
    from .mnemonic import rep1_prefix, rep2_prefix

    has_rep1, has_rep2 = _rep_flags(instruction)
    if has_rep1:
        return f".{rep1_prefix(instruction.mnemonic).upper()}"
    if has_rep2:
        return f".{rep2_prefix(instruction.mnemonic).upper()}"
    return ""


def _string_operands(instruction: Instruction) -> str:
    """The implicit operands of a string instruction, as Ghidra writes them.

    The destination is always ES:DI and is never overridable; the source is
    DS:SI and *is*, which is why LODSB appears as `LODSB CS:SI` when the
    instruction carries a segment prefix.
    """
    mnemonic = instruction.mnemonic
    destination = "ES:DI"
    # The source is DS:SI by default, and Ghidra writes the bare `SI` in that
    # case -- the segment is spelled out only when it is *not* DS, because an
    # unqualified `SI` already means DS.
    segment = _segment_override(instruction)
    source = "SI" if segment is None or segment is Register16.DS else f"{segment.name.upper()}:SI"

    if mnemonic in (Mnemonic.STOSB, Mnemonic.STOSW, Mnemonic.STOSD, Mnemonic.SCASB, Mnemonic.SCASW, Mnemonic.SCASD):
        return destination
    if mnemonic in (Mnemonic.LODSB, Mnemonic.LODSW, Mnemonic.LODSD):
        return source
    if mnemonic in (
        Mnemonic.MOVSB, Mnemonic.MOVSW, Mnemonic.MOVSD,
        Mnemonic.CMPSB, Mnemonic.CMPSW, Mnemonic.CMPSD,
    ):
        return f"{destination}, {source}"
    # INSB/OUTSB address the port, not memory; leave them operandless.
    return ""


def _render_addr16(mode: object, instruction: Instruction) -> str:
    """`[BX + SI + 0x4]`, with any segment override written inside the brackets."""
    kind = mode.kind
    base = addr16_base_kind(kind)

    if kind == "disp16":
        # mod=00 r/m=110 is an absolute address, not [BP]. Unlike a signed
        # displacement this prints unsigned: `[0xfef6]` is a 16-bit address, not
        # a negative offset.
        inside = format_number(mode.displacement & 0xFFFF)
    else:
        registers = ADDR16_REGISTER_TEXT.get(kind, "")
        inside = " + ".join(part.upper() for part in registers.split("+") if part)
        if mode.carries_displacement():
            displacement = mode.displacement
            if kind.endswith("_d8"):
                # An 8-bit displacement is sign-extended and prints signed, with
                # the operator kept separate: `[BP + -0x1]`, never `[BP - 0x1]`.
                inside += f" + {format_number(displacement)}"
            else:
                # A 16-bit displacement prints as the unsigned address it is:
                # `[BP + 0xfe00]`, never `[BP - 0x200]`.
                inside += f" + {format_number(displacement & 0xFFFF)}"

    segment = _segment_override(instruction)
    if segment is not None and _shows_segment_override(instruction):
        return f"{segment.name.upper()}:[{inside}]"
    return f"[{inside}]"


def _immediate_value(instruction: Instruction, value: int) -> int:
    """How a sign-extended 8-bit immediate is printed.

    `83 F2 FF` is `XOR DX, 0xffff` and `83 FA FF` is `CMP DX, -0x1`. Both are the
    same byte; the group extension decides whether the operand is read as signed
    or zero-extended (`_SIGNED_IMM8_EXTENSIONS`), and the listing follows.
    """
    if value >= 0:
        return value
    if _raw_opcode(instruction) == 0x83 and _modrm_extension(instruction) in _SIGNED_IMM8_EXTENSIONS:
        return value
    if instruction.operand_size is OperandSize.Operand16:
        return value & 0xFFFF
    if instruction.operand_size is OperandSize.Operand32:
        return value & 0xFFFFFFFF
    return value & 0xFF


def _render_operand(instruction: Instruction, operand: OperandType, address: int, with_size: bool) -> str:
    kind = operand.kind

    if kind in ("reg8", "reg16", "reg32", "creg", "dreg", "treg"):
        return str(operand.value).upper()

    if kind in ("imm8", "imm16", "imm32"):
        return format_number(operand.value)
    if kind == "imm8s":
        return format_number(_immediate_value(instruction, operand.value))

    if kind in ("rel8", "rel16"):
        # A near branch is intra-segment: the displacement is added to IP and
        # the offset wraps at 64K, but the segment does not move. Treating the
        # whole thing as a linear address and re-normalising would push a
        # backward branch near the segment base into segment 0 -- `1000:494c
        # CALL 0x1000:f807`, not `0x0000:f807`.
        segment = (address >> 4) & 0xF000
        offset = (address & 0xFFFF) + instruction.length + operand.value
        return f"0x{segment:04x}:{offset & 0xFFFF:04x}"

    if kind == "far16":
        segment, offset = operand.value
        return format_pointer((segment << 4) + offset)

    if kind.startswith("offset"):
        # An absolute direct address (A0-A3). The stored word is the offset into
        # the instruction's own segment, whose base shows only as a qualifier.
        prefix = ""
        segment = _segment_override(instruction)
        if segment is not None and _shows_segment_override(instruction):
            prefix = f"{segment.name.upper()}:"
        return f"{prefix}[{format_number(operand.value & 0xFFFF)}]"

    if kind in ("addr16", "addr32"):
        # `word ptr [..]`, not `word [..]`.
        prefix = f"{_SIZE_WORDS.get(operand.size, '')} ptr " if with_size else ""
        return prefix + _render_addr16(operand.value, instruction)

    if kind == "none":
        return ""

    raise DecodeError(f"cannot render operand kind {kind!r}")


def _effective_operands(instruction: Instruction) -> list[OperandType]:
    """The operands as Ghidra orders and completes them.

    Four adjustments to what the decode table resolved:

    * `XCHG` prints its operands in the opposite order to the encoding.
    * `MOV r/m16, Sreg` and `MOV Sreg, r/m16` both print the segment register
      second, so 8E comes out reversed.
    * `0x90` is `XCHG AX, AX` in the table and a bare `NOP` in a listing, so its
      operands are dropped.
    * The shift/rotate group implies its count from the opcode and prints it
      anyway: `D1 E0` is `SHL AX, 0x1`, not `SHL AX`.
    """
    operands = [
        operand
        for operand in (instruction.operand1_type, instruction.operand2_type, instruction.operand3_type)
        if operand is not NO_OPERAND
    ]

    opcode = _raw_opcode(instruction)

    if instruction.mnemonic is Mnemonic.NOP:
        return []

    if instruction.mnemonic in _XCHG_MNEMONICS:
        operands.reverse()
    elif opcode == 0x8E and len(operands) == 2 and not operands[1].is_memory():
        # `MOV Sreg, r16` prints register-first, `MOV Sreg, m16` does not: Ghidra
        # keeps the memory operand last in both directions of the move, so only
        # the register-to-register form reads "backwards".
        operands.reverse()

    if opcode in _SHIFT_GROUP_OPCODES and instruction.mnemonic in _SHIFT_MNEMONICS and len(operands) == 1:
        if opcode in (0xD0, 0xD1):
            operands.append(OperandType("imm8", 1))
        elif opcode in (0xD2, 0xD3):
            operands.append(OperandType("reg8", Register8.CL))

    return operands


def render_operands(instruction: Instruction, address: int) -> str:
    """The operand column for one instruction, without the leading separator."""
    if instruction.mnemonic in _STRING_OPS:
        return _string_operands(instruction)

    operands = _effective_operands(instruction)
    if not operands:
        return ""

    supplies = _supplies_own_size(instruction)
    parts = []
    for operand in operands:
        with_size = operand.is_memory() and not supplies
        parts.append(_render_operand(instruction, operand, address, with_size))
    return ", ".join(parts)


def render_bytes(instruction: Instruction) -> str:
    return " ".join(f"{byte:02X}" for byte in instruction.instruction_bytes)


def render_body(instruction: Instruction, address: int) -> str:
    """The listing body: padded mnemonic plus operands, with no address."""
    if not instruction.is_valid or not instruction.is_complete:
        return ""
    # The mnemonic is padded to the column and the operands follow immediately,
    # with no separator. An instruction with no operands therefore ends in the
    # padding itself -- `CBW      `, six trailing spaces into the field.
    #
    # A REP-suffixed mnemonic (`MOVSB.REP`, nine characters) fills the field
    # exactly, so the operands need the separator back or they run into it.
    mnemonic = ghidra_mnemonic(instruction)
    operands = render_operands(instruction, address)
    if operands and len(mnemonic) >= MNEMONIC_COLUMN:
        return f"{mnemonic} {operands}"
    return f"{mnemonic:<{MNEMONIC_COLUMN}}{operands}"


def render_line(instruction: Instruction, segment: int, offset: int, address: int) -> str:
    """One full listing line, in the exporter's exact layout."""
    body = render_body(instruction, address)
    return f"{segment:04x}:{offset:04x} {body} ; bytes={render_bytes(instruction)} len={instruction.length}"


def format_instruction(instruction: Instruction, address: int) -> str:
    """Render an instruction at a linear address."""
    segment, offset = normalize(address)
    return render_line(instruction, segment, offset, address)


def render_placeholder(segment: int, offset: int) -> str:
    """The exporter's line for a byte it has no instruction at."""
    return f"{segment:04x}:{offset:04x} <no instruction>"


__all__ = [
    "format_instruction",
    "format_number",
    "format_pointer",
    "ghidra_mnemonic",
    "normalize",
    "render_body",
    "render_line",
    "render_placeholder",
    "MNEMONIC_COLUMN",
]
