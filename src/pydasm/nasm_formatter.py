"""marty_dasm's own NASM-style formatter.

A faithful port of `formatter/nasm_formatter.rs`. Where the Ghidra renderer
(`pydasm.ghidra`) exists to reproduce another tool's output exactly, this one
reproduces the reference implementation's own house style: lowercase mnemonics,
`word`/`byte` size qualifiers from marty_dasm's own disambiguation rules,
`o16`/`o32` prefix preservation, and its number formatting.

Some of this formatter is inert on the 8086, and that is by design rather than
by accident: operand-size and address-size disambiguation both hang off prefixes
the 8088 does not have, and `Instruction.disambiguate` is only set by the 386
decoder. The code is kept because the two renderers share an operand model and
a port that silently dropped the branches would be harder to extend to the 386
than one that keeps them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .cpu_common import (
    ADDR16_REGISTER_TEXT,
    NO_OPERAND,
    AddressSize,
    OperandSize,
    OperandType,
    PrefixFlags,
    Register16,
    addr16_base_kind,
    operand_size_of,
)
from .instruction import Instruction
from .mnemonic import (
    Mnemonic,
    is_far,
    is_jcnd,
    is_loop,
    is_push_or_pop,
    is_string_op,
    is_stos,
    is_scas,
    is_ins,
    mnemonic_to_str,
    rep1_prefix,
    rep2_prefix,
    suppress_operand_prefix,
    to_iced_str,
)


@dataclass
class FormatOptions:
    """Options controlling disassembly formatting."""

    ip: int = 0
    #: Render the mnemonic in uppercase rather than lowercase.
    uppercase_mnemonic: bool = False
    #: Use iced-x86's mnemonics where the two differ (ja vs jnbe, ...).
    iced_mnemonics: bool = False
    #: Emit only the mnemonic, with no operands.
    mnemonic_only: bool = False
    #: Show the size of memory operands, e.g. `mov al,[dword ds:5F976B58h]`.
    memory_operand_size: bool = True


class TokenStream:
    """A sink that records what kind of text the formatter emitted.

    `FormatterOutput` in the reference implementation exists so a caller can
    colourise a listing without re-parsing it. Anything not using the token
    categories can just pass a `list[str]` or use `format_instruction`.
    """

    def __init__(self) -> None:
        self.tokens: list[tuple[str, str]] = []

    def write_text(self, text: str) -> None:
        self.tokens.append(("text", text))

    def write_prefix(self, text: str) -> None:
        self.tokens.append(("prefix", text))

    def write_register(self, text: str) -> None:
        self.tokens.append(("register", text))

    def write_mnemonic(self, text: str) -> None:
        self.tokens.append(("mnemonic", text))

    def write_operand(self, text: str) -> None:
        self.tokens.append(("operand", text))

    def write_immediate(self, text: str) -> None:
        self.tokens.append(("immediate", text))

    def write_relative(self, text: str) -> None:
        self.tokens.append(("relative", text))

    def write_displacement(self, text: str) -> None:
        self.tokens.append(("displacement", text))

    def write_separator(self, text: str) -> None:
        self.tokens.append(("separator", text))

    def write_symbol(self, text: str) -> None:
        self.tokens.append(("symbol", text))

    def write_error(self) -> None:
        self.write_text("** ERROR **")

    def to_string(self) -> str:
        return "".join(text for _, text in self.tokens)


class _TextSink:
    """The minimal output surface the formatter needs."""

    __slots__ = ("parts",)

    def __init__(self) -> None:
        self.parts: list[str] = []

    def __getattr__(self, name: str):
        # Any `write_*` method simply appends its text.
        if name.startswith("write_"):
            return self.parts.append
        raise AttributeError(name)

    def to_string(self) -> str:
        return "".join(self.parts)


def format_hex_or_decimal(value: int) -> str:
    """Decimal below ten, otherwise uppercase hex with an `h` suffix."""
    if 0 <= value < 10:
        return str(value)
    return f"{value:X}h"


def format_signed_hex_or_decimal(value: int) -> str:
    """A forced-sign displacement: `+4`, `-7`, `+1Fh`, or empty for zero."""
    magnitude = abs(value)
    if magnitude == 0:
        return ""
    if magnitude < 10:
        return f"-{magnitude}" if value < 0 else f"+{magnitude}"
    return f"-{magnitude:X}h" if value < 0 else f"+{magnitude:X}h"


def format_hex_or_decimal_16(value: int) -> str:
    if 0 <= value < 10:
        return str(value)
    return f"{value & 0xFFFF:04X}h"


def format_hex_or_decimal_32(value: int) -> str:
    if 0 <= value < 10:
        return str(value)
    return f"{value & 0xFFFFFFFF:08X}h"


def format_scale(scale: int) -> str:
    return f"*{scale}"


def format_address_16(mode: object) -> str:
    """A 16-bit effective address, registers first and displacement last."""
    text = ADDR16_REGISTER_TEXT.get(mode.kind, "")
    if mode.kind == "disp16":
        return format_hex_or_decimal(mode.displacement & 0xFFFF)
    if not mode.carries_displacement():
        return text
    return f"{text}{format_signed_hex_or_decimal(mode.displacement)}"


class NasmFormatter:
    """Renders instructions in marty_dasm's NASM style."""

    # -- prefixes -------------------------------------------------------

    def format_prefixes(self, instruction: Instruction, opts: FormatOptions, out) -> None:
        if (
            instruction.has_address_size_override()
            and not self._operands_will_disambiguate_address_size(instruction)
            and not instruction.has_modrm
            and not is_loop(instruction.mnemonic)
        ):
            if instruction.address_size is AddressSize.Address16:
                out.write_prefix("a16")
                out.write_separator(" ")
            else:
                out.write_prefix("a32")
                out.write_separator(" ")

        self.format_operand_size_disambiguation(instruction, opts, out)

        if instruction.effective_prefix_flags & PrefixFlags.SEG_OVERRIDE_MASK:
            # A string operation's segment override is part of its operand, so
            # it is written with the operand rather than as a prefix. STOS, SCAS
            # and INS only ever touch ES, which cannot be overridden.
            if (
                not instruction.has_modrm
                and (is_string_op(instruction.mnemonic) or instruction.mnemonic is Mnemonic.XLAT)
                and not is_stos(instruction.mnemonic)
                and not is_scas(instruction.mnemonic)
                and not is_ins(instruction.mnemonic)
            ):
                segment = instruction.segment_override
                if segment is not None and segment is not Register16.DS:
                    out.write_prefix(str(segment).lower())
                    out.write_separator(" ")

        if instruction.raw_prefix_flags & PrefixFlags.LOCK:
            out.write_prefix("lock")
            out.write_separator(" ")

        if is_string_op(instruction.mnemonic) and (instruction.effective_prefix_flags & PrefixFlags.REP_MASK):
            if instruction.effective_prefix_flags & PrefixFlags.REP1:
                out.write_prefix(rep1_prefix(instruction.mnemonic))
            elif instruction.effective_prefix_flags & PrefixFlags.REP2:
                out.write_prefix(rep2_prefix(instruction.mnemonic))
            out.write_separator(" ")

    # -- mnemonic -------------------------------------------------------

    def format_mnemonic(self, instruction: Instruction, opts: FormatOptions, out) -> None:
        if opts.iced_mnemonics:
            text = to_iced_str(instruction.mnemonic) or mnemonic_to_str(instruction.mnemonic)
        else:
            text = mnemonic_to_str(instruction.mnemonic)

        out.write_mnemonic(text if opts.uppercase_mnemonic else text.lower())

    # -- operands -------------------------------------------------------

    def operands_suppressed(self, instruction: Instruction) -> bool:
        if instruction.mnemonic in (Mnemonic.AAM, Mnemonic.AAD):
            # AAD and AAM default to 0x0A, which is conventionally not printed.
            if instruction.operand1_type.kind == "imm8":
                return instruction.operand1_type.value == 0x0A
            return False
        if instruction.mnemonic is Mnemonic.NOP:
            # NOP is often an encoded `XCHG eAX, eAX`; the operands are noise.
            return True
        return False

    def format_operands(self, instruction: Instruction, opts: FormatOptions, out) -> None:
        self.format_memory_disambiguation(instruction, opts, instruction.operand1_type, out)
        self.format_operand(instruction, instruction.operand1_type, instruction.segment_override, opts, out)

        if instruction.operand2_type is not NO_OPERAND:
            out.write_separator(",")
        self.format_memory_disambiguation(instruction, opts, instruction.operand2_type, out)
        self.format_operand(instruction, instruction.operand2_type, instruction.segment_override, opts, out)

        if instruction.operand3_type is not NO_OPERAND:
            out.write_separator(",")
        self.format_operand(instruction, instruction.operand3_type, instruction.segment_override, opts, out)

    def format_instruction(self, instruction: Instruction, opts: Optional[FormatOptions] = None, out=None) -> str:
        """Render one instruction. Returns the text, or writes it to `out`."""
        opts = opts or FormatOptions()
        sink = out if out is not None else _TextSink()

        if opts.mnemonic_only:
            self.format_mnemonic(instruction, opts, sink)
            return sink.to_string()

        if instruction.mnemonic is Mnemonic.Invalid or not instruction.is_complete or not instruction.is_valid:
            sink.write_text("(bad)")
            if instruction.mnemonic is Mnemonic.Invalid:
                return sink.to_string()
            sink.write_separator(" ")

        self.format_prefixes(instruction, opts, sink)
        self.format_mnemonic(instruction, opts, sink)

        if instruction.has_operands() and not self.operands_suppressed(instruction):
            sink.write_separator(" ")
            self.format_operands(instruction, opts, sink)

        return sink.to_string()

    # -- size disambiguation --------------------------------------------

    def _has_operand_size_disambiguation(self, instruction: Instruction, operand: OperandType) -> bool:
        if not instruction.disambiguate:
            return False

        size = None
        if operand.kind in ("addr16", "addr32"):
            size = operand.size
        elif operand.kind in ("rel16", "rel32"):
            if instruction.has_operand_size_override():
                if instruction.operand_size in (OperandSize.Operand16, OperandSize.Operand32):
                    return True
            size = None

        return size in (OperandSize.Operand8, OperandSize.Operand16, OperandSize.Operand32)

    def _operands_will_disambiguate_operand_size(self, instruction: Instruction) -> bool:
        return self._has_operand_size_disambiguation(
            instruction, instruction.operand1_type
        ) or self._has_operand_size_disambiguation(instruction, instruction.operand2_type)

    def _operand_will_disambiguate_address_size(self, operand: OperandType) -> bool:
        return operand.kind in (
            "addr16",
            "addr32",
            "rel8",
            "rel16",
            "rel32",
            "offset8_32",
            "offset8_16",
            "offset16_16",
            "offset32_16",
            "offset16_32",
            "offset32_32",
        )

    def _operands_will_disambiguate_address_size(self, instruction: Instruction) -> bool:
        return self._operand_will_disambiguate_address_size(
            instruction.operand1_type
        ) or self._operand_will_disambiguate_address_size(instruction.operand2_type)

    def format_memory_address_size(self, instruction: Instruction, out) -> None:
        out.write_text("word" if instruction.address_size is AddressSize.Address16 else "dword")

    def format_pointer_size(self, instruction: Instruction, out) -> None:
        if instruction.operand_size is OperandSize.Operand16:
            out.write_text("word")
        elif instruction.operand_size is OperandSize.Operand32:
            out.write_text("dword")

    def format_operand_size_disambiguation(
        self, instruction: Instruction, opts: FormatOptions, out
    ) -> None:
        """Write an `o16`/`o32` prefix when the operand size would be invisible."""
        disambiguate = False
        flip = False

        operand1 = instruction.operand1_type

        if is_push_or_pop(instruction.mnemonic) and instruction.has_operand_size_override():
            disambiguate = operand1.is_segment_register() or operand1.kind in ("imm8", "imm8s")
        elif instruction.has_operand_size_override() and instruction.mnemonic in (Mnemonic.ENTER, Mnemonic.LEAVE):
            disambiguate = True
        elif operand1.kind == "rel8" and instruction.has_operand_size_override():
            disambiguate = True
        elif (
            instruction.has_operand_size_override()
            and instruction.mnemonic in (Mnemonic.SLDT, Mnemonic.SMSW)
            and instruction.has_memory_operand()
        ):
            disambiguate = True
        elif (
            instruction.has_operand_size_override()
            and instruction.mnemonic is Mnemonic.MOV
            and instruction.has_memory_operand()
            and (operand1.is_segment_register() or instruction.operand2_type.is_segment_register())
        ):
            disambiguate = True
        elif instruction.has_ineffective_operand_size_override() and instruction.mnemonic in (
            Mnemonic.LMSW,
            Mnemonic.LLDT,
            Mnemonic.LTR,
            Mnemonic.VERR,
            Mnemonic.VERW,
        ):
            disambiguate = True
            flip = True
        elif (
            not suppress_operand_prefix(instruction.mnemonic)
            and instruction.has_ineffective_operand_size_override()
            and not self._operands_will_disambiguate_operand_size(instruction)
            and instruction.operand_ct() == 1
            and instruction.has_memory_operand()
        ):
            disambiguate = True
            flip = True

        if not disambiguate:
            return

        size = instruction.operand_size
        if (size is OperandSize.Operand16 and not flip) or (size is OperandSize.Operand32 and flip):
            out.write_text("o16")
            out.write_separator(" ")
        elif (size is OperandSize.Operand16 and flip) or (size is OperandSize.Operand32 and not flip):
            out.write_text("o32")
            out.write_separator(" ")

    def format_memory_disambiguation(
        self, instruction: Instruction, opts: FormatOptions, operand: OperandType, out
    ) -> None:
        """Write `byte`/`word`/`dword`/`short`/`near`/`far` where the size is unclear."""
        if not instruction.disambiguate:
            return

        if operand.kind == "rel8":
            out.write_text("short")
            out.write_separator(" ")
            return

        if operand.kind in ("rel16", "rel32"):
            if is_jcnd(instruction.mnemonic):
                out.write_text("near")
                out.write_separator(" ")
            if instruction.has_operand_size_override():
                self.format_pointer_size(instruction, out)
                out.write_separator(" ")
            return

        if operand.kind in ("addr16", "addr32"):
            if is_far(instruction.mnemonic):
                if instruction.has_operand_size_override():
                    self.format_pointer_size(instruction, out)
                    out.write_separator(" ")
                out.write_text("far")
                out.write_separator(" ")
            else:
                size_word = {
                    OperandSize.Operand8: "byte",
                    OperandSize.Operand16: "word",
                    OperandSize.Operand32: "dword",
                }.get(operand.size)
                if size_word:
                    out.write_text(size_word)
                out.write_separator(" ")

    # -- operands -------------------------------------------------------

    def format_operand(
        self,
        instruction: Instruction,
        operand: OperandType,
        seg_override: Optional[Register16],
        opts: FormatOptions,
        out,
    ) -> None:
        kind = operand.kind

        if kind in ("imm8", "imm16", "imm32"):
            out.write_immediate(format_hex_or_decimal(operand.value))
            return

        if kind == "imm8s":
            value = operand.value
            if instruction.operand_size is OperandSize.Operand16:
                display = format_hex_or_decimal(value & 0xFFFF)
            elif instruction.operand_size is OperandSize.Operand32:
                display = format_hex_or_decimal(value & 0xFFFFFFFF)
            else:
                display = format_hex_or_decimal(value & 0xFF)
            out.write_immediate(display)
            return

        if kind == "rel8":
            if instruction.operand_size is OperandSize.Operand16:
                # Wrap at 16 bits: IP is a 16-bit register on this CPU, so a
                # branch past its end comes back round rather than extending.
                target = ((opts.ip & 0xFFFF) + operand.value + instruction.length) & 0xFFFF
                out.write_relative(format_hex_or_decimal_16(target))
            elif instruction.operand_size is OperandSize.Operand32:
                target = (opts.ip + operand.value + instruction.length) & 0xFFFFFFFF
                out.write_relative(format_hex_or_decimal_32(target))
            else:
                out.write_text("??BADOP??")
            return

        if kind == "rel16":
            if instruction.operand_size is OperandSize.Operand16:
                target = ((opts.ip & 0xFFFF) + operand.value + instruction.length) & 0xFFFF
                out.write_relative(format_hex_or_decimal_16(target))
            elif instruction.operand_size is OperandSize.Operand32:
                target = (opts.ip + operand.value + instruction.length) & 0xFFFFFFFF
                out.write_relative(format_hex_or_decimal_32(target))
            else:
                out.write_text("??BADOP??")
            return

        if kind == "rel32":
            target = (opts.ip + operand.value + instruction.length) & 0xFFFFFFFF
            out.write_relative(format_hex_or_decimal_32(target))
            return

        if kind.startswith("offset"):
            base = seg_override if seg_override is not None else Register16.DS
            out.write_separator("[")
            if instruction.has_address_size_override() and opts.memory_operand_size:
                self.format_memory_address_size(instruction, out)
                out.write_separator(" ")
            out.write_register(f"{base}:")
            out.write_text(format_hex_or_decimal(operand.value))
            out.write_separator("]")
            return

        if kind in ("reg8", "reg16", "reg32", "creg", "dreg", "treg"):
            out.write_register(str(operand.value))
            return

        if kind in ("addr16", "addr32"):
            mode = operand.value
            base = seg_override if seg_override is not None else mode.base_register()
            out.write_separator("[")
            out.write_register(f"{base}:")
            out.write_text(format_address_16(mode))
            out.write_separator("]")
            return

        if kind == "far16":
            segment, offset = operand.value
            if instruction.has_operand_size_override() and opts.memory_operand_size:
                self.format_pointer_size(instruction, out)
                out.write_separator(" ")
            out.write_text(format_hex_or_decimal_16(segment))
            out.write_separator(":")
            out.write_text(format_hex_or_decimal_16(offset))
            return

        if kind == "far32":
            segment, offset = operand.value
            if instruction.has_operand_size_override() and opts.memory_operand_size:
                self.format_pointer_size(instruction, out)
                out.write_separator(" ")
            out.write_text(format_hex_or_decimal_16(segment))
            out.write_separator(":")
            out.write_text(format_hex_or_decimal_32(offset))
            return

        if kind in ("m16pair", "none", "invalid"):
            return

        out.write_error()


def format_instruction(instruction: Instruction, opts: Optional[FormatOptions] = None) -> str:
    """Convenience: format one instruction to a string."""
    return NasmFormatter().format_instruction(instruction, opts)


__all__ = [
    "FormatOptions",
    "NasmFormatter",
    "TokenStream",
    "format_address_16",
    "format_hex_or_decimal",
    "format_hex_or_decimal_16",
    "format_hex_or_decimal_32",
    "format_instruction",
    "format_signed_hex_or_decimal",
]
