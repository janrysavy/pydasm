"""The streaming decoder.

Tracks a byte position over an input buffer so a caller can walk an image from a
chosen start and, when a decode fails partway, learn exactly how far it got.
That position is not a convenience: an image walk needs to know whether a failed
instruction consumed bytes, because an instruction that consumed none means the
walker is at a clean boundary and an instruction that consumed some means the
boundary it started from was wrong.
"""

from __future__ import annotations

import enum
from typing import Optional

from .byte_reader import ByteReader
from .cpu_common import SegmentSize
from .errors import DecodeError, Eof, UnexpectedEof
from .i808x import Intel808x
from .instruction import Instruction


class CpuType(enum.Enum):
    """Which CPU's decode rules to apply."""

    Intel808x = "8088/8086"
    NecVx0 = "V20/V30"
    Intel8018x = "80186/80188"
    Intel80286 = "80286"
    Intel80386 = "80386"


class DecoderOptions:
    """How to decode."""

    __slots__ = ("cpu", "segment_size")

    def __init__(self, cpu: CpuType = CpuType.Intel808x, segment_size: SegmentSize = SegmentSize.Segment16) -> None:
        self.cpu = cpu
        self.segment_size = segment_size

    def replace(self, **changes: object) -> "DecoderOptions":
        current = {"cpu": self.cpu, "segment_size": self.segment_size}
        current.update(changes)
        return DecoderOptions(**current)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        return f"DecoderOptions(cpu={self.cpu.name}, segment_size={self.segment_size.name})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DecoderOptions):
            return NotImplemented
        return self.cpu is other.cpu and self.segment_size is other.segment_size


class Decoder:
    """Decodes instructions from a byte buffer, one at a time."""

    def __init__(self, data: bytes | bytearray | memoryview = b"", options: Optional[DecoderOptions] = None) -> None:
        self._reader = ByteReader(data)
        self._opts = options if options is not None else DecoderOptions()

    # -- configuration --------------------------------------------------

    @property
    def options(self) -> DecoderOptions:
        return self._opts

    def set_options(self, options: DecoderOptions) -> None:
        self._opts = options

    # -- position -------------------------------------------------------

    @property
    def position(self) -> int:
        """Bytes consumed since this decoder was created."""
        return self._reader.position

    def is_eof(self) -> bool:
        return self._reader.at_eof()

    def set_position(self, position: int) -> None:
        if not 0 <= position <= len(self._reader):
            raise ValueError(f"position {position} outside input of {len(self._reader)} bytes")
        self._reader.position = position

    def rewind(self) -> None:
        self._reader.position = 0

    # -- decoding -------------------------------------------------------

    def decode_next(self) -> Instruction:
        """Decode the next instruction.

        Raises `Eof` when the input is exhausted before anything was consumed,
        and `UnexpectedEof` when an instruction was started but the input ran
        out. The exception carries the reader's position either way, so a caller
        can resume or report.
        """
        start = self._reader.position
        cpu = self._opts.cpu

        try:
            if cpu is CpuType.Intel808x:
                return Intel808x.decode(self._reader, self._opts.segment_size)
            if cpu is CpuType.Intel80386:
                raise DecodeError("386 decoding is not part of this port yet")
            raise DecodeError(f"{cpu.name} decoding is not part of this port yet")
        except UnexpectedEof:
            # Distinguish "nothing here" from "stopped in the middle". This is
            # the distinction the reference implementation makes, and a walker
            # depends on it.
            if self._reader.position == start:
                raise Eof() from None
            raise

    def __iter__(self):
        return self

    def __next__(self) -> Instruction:
        try:
            return self.decode_next()
        except Eof:
            raise StopIteration from None


def decode_one(
    data: bytes | bytearray | memoryview,
    options: Optional[DecoderOptions] = None,
) -> Instruction:
    """Decode a single instruction from a buffer."""
    return Decoder(data, options).decode_next()
