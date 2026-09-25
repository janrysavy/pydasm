"""Little-endian fixed-width reads over a byte stream.

The reference implementation reads through Rust's `BufRead` and tracks consumed
bytes as a side effect of `consume()`. The decoder needs both halves of that:
the bytes it read, and exactly how many -- an instruction's length is the number
of bytes consumed, not the number of bytes it meant to read. A reader that
slurps eagerly would report a length for an instruction that ran off the end of
its input.

So `ByteReader` keeps an explicit cursor over a `bytes` buffer and every read
advances it by exactly the bytes it returned.
"""

from __future__ import annotations

from .errors import UnexpectedEof


class ByteReader:
    """A cursor over a byte buffer with fixed-width little-endian reads.

    `position` is the number of bytes consumed so far and is always the count of
    bytes any returned value was built from, which is what makes it usable as an
    instruction length.
    """

    __slots__ = ("_buf", "position")

    def __init__(self, data: bytes | bytearray | memoryview = b"") -> None:
        self._buf = memoryview(bytes(data))
        self.position = 0

    def __len__(self) -> int:
        return len(self._buf)

    def remaining(self) -> int:
        return len(self._buf) - self.position

    def at_eof(self) -> bool:
        return self.position >= len(self._buf)

    def peek(self, count: int = 1) -> bytes:
        """Return the next `count` bytes without consuming them.

        Raises `UnexpectedEof` when fewer than `count` bytes remain, so a caller
        can never be handed a short read that it mistakes for a complete one.
        """
        end = self.position + count
        if end > len(self._buf):
            raise UnexpectedEof()
        return bytes(self._buf[self.position : end])

    def read_bytes(self, count: int) -> bytes:
        data = self.peek(count)
        self.position += count
        return data

    def read_u8(self) -> int:
        if self.position >= len(self._buf):
            raise UnexpectedEof()
        value = self._buf[self.position]
        self.position += 1
        return value

    def read_i8(self) -> int:
        value = self.read_u8()
        return value - 0x100 if value & 0x80 else value

    def read_u16(self) -> int:
        lo = self.read_u8()
        hi = self.read_u8()
        return lo | (hi << 8)

    def read_i16(self) -> int:
        value = self.read_u16()
        return value - 0x1_0000 if value & 0x8000 else value

    def read_u32(self) -> int:
        lo = self.read_u16()
        hi = self.read_u16()
        return lo | (hi << 16)

    def read_i32(self) -> int:
        value = self.read_u32()
        return value - 0x1_0000_0000 if value & 0x8000_0000 else value

    def read_farptr16(self) -> tuple[int, int]:
        """Read a 16:16 far pointer stored offset-first. Returns (segment, offset)."""
        offset = self.read_u16()
        segment = self.read_u16()
        return segment, offset

    def read_farptr32(self) -> tuple[int, int]:
        """Read a 16:32 far pointer stored offset-first. Returns (segment, offset)."""
        offset = self.read_u32()
        segment = self.read_u16()
        return segment, offset
