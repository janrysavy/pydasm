"""pydasm -- a Python port of marty_dasm.

The decoder is marty_dasm's: same decode table, same prefix and ModRM handling,
same operand resolution. On top of it sit two renderers -- a NASM-style one
ported from marty_dasm, and a Ghidra-compatible one that reproduces the listing
format a byte-anchored Ghidra exporter produces.
"""

from __future__ import annotations

from ._mnemonics import Mnemonic
from .byte_reader import ByteReader
from .cpu_common import (
    AddressOffset16,
    AddressSize,
    Displacement,
    OperandSize,
    OperandType,
    Register8,
    Register16,
    Register32,
    SegmentSize,
)
from .decoder import CpuType, Decoder, DecoderOptions, decode_one
from .errors import (
    DecodeError,
    Eof,
    InvalidInput,
    InvalidOptions,
    UnexpectedEof,
    UnsupportedOpcode,
)
from .instruction import Instruction

__version__ = "0.3.5"

__all__ = [
    "AddressOffset16",
    "AddressSize",
    "ByteReader",
    "CpuType",
    "DecodeError",
    "Decoder",
    "DecoderOptions",
    "Displacement",
    "Eof",
    "Instruction",
    "InvalidInput",
    "InvalidOptions",
    "Mnemonic",
    "OperandSize",
    "OperandType",
    "Register8",
    "Register16",
    "Register32",
    "SegmentSize",
    "UnexpectedEof",
    "UnsupportedOpcode",
    "decode_one",
    "__version__",
]
