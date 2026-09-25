"""The decoded-instruction record."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .cpu_common import (
    NO_OPERAND,
    AddressSize,
    OperandSize,
    OperandType,
    PrefixFlags,
    Register16,
    SegmentSize,
    operand_size_of,
)
from .mnemonic import Mnemonic


@dataclass
class Instruction:
    """One decoded instruction, with its bytes and its resolved operands.

    `instruction_bytes` is authoritative for length: it holds every byte the
    decoder consumed, prefixes included, in order. The `*_bytes` sub-lists are
    views onto parts of the same stream, which is what lets a caller reassemble
    the encoding or report where an immediate started.
    """

    is_valid: bool = False
    is_complete: bool = False
    opcode: int = 0
    instruction_bytes: bytearray = field(default_factory=bytearray)
    displacement_bytes: bytearray = field(default_factory=bytearray)
    immediate_bytes: bytearray = field(default_factory=bytearray)
    prefix_bytes: bytearray = field(default_factory=bytearray)
    has_modrm: bool = False
    has_sib: bool = False
    has_immediate: bool = False
    immediate_size: OperandSize = OperandSize.NoOperand
    has_displacement: bool = False
    displacement_size: OperandSize = OperandSize.NoOperand
    opcode_offset: int = 0
    modrm_offset: int = 0
    sib_offset: int = 0
    #: Flags for every prefix byte present, whether or not it had an effect.
    raw_prefix_flags: int = 0
    #: Flags for only the prefixes that actually changed the decode.
    effective_prefix_flags: int = 0
    prefix_ct: int = 0
    address: int = 0
    segment_size: SegmentSize = SegmentSize.Segment16
    operand_size: OperandSize = OperandSize.NoOperand
    address_size: AddressSize = AddressSize.Address16
    mnemonic: Mnemonic = Mnemonic.Invalid
    segment_override: Optional[Register16] = None
    disambiguate: bool = False
    hide_operands: bool = False
    operand1_type: OperandType = NO_OPERAND
    operand2_type: OperandType = NO_OPERAND
    operand3_type: OperandType = NO_OPERAND

    # -- derived queries ------------------------------------------------

    @property
    def length(self) -> int:
        return len(self.instruction_bytes)

    def has_operands(self) -> bool:
        return (
            self.operand1_type is not NO_OPERAND
            or self.operand2_type is not NO_OPERAND
            or self.operand3_type is not NO_OPERAND
        )

    def operand_ct(self) -> int:
        return sum(
            1
            for operand in (self.operand1_type, self.operand2_type, self.operand3_type)
            if operand is not NO_OPERAND
        )

    def has_operand_size_override(self) -> bool:
        """Whether an operand-size override actually took effect."""
        return bool(self.effective_prefix_flags & PrefixFlags.OPERAND_SIZE)

    def has_operand_size_override_prefix(self) -> bool:
        """Whether an operand-size override byte is present, effective or not."""
        return bool(self.raw_prefix_flags & PrefixFlags.OPERAND_SIZE)

    def has_ineffective_operand_size_override(self) -> bool:
        return self.has_operand_size_override_prefix() and not self.has_operand_size_override()

    def has_address_size_override(self) -> bool:
        if self.segment_size is SegmentSize.Segment16:
            return self.address_size is AddressSize.Address32
        return self.address_size is AddressSize.Address16

    def has_memory_operand(self) -> bool:
        return self.has_modrm and (self.operand1_type.is_memory() or self.operand2_type.is_memory())

    def operand_size_of(self, operand: OperandType) -> OperandSize:
        return operand_size_of(operand)

    def __repr__(self) -> str:
        hexed = " ".join(f"{b:02X}" for b in self.instruction_bytes)
        return f"<Instruction {self.mnemonic.name} [{hexed}]>"
