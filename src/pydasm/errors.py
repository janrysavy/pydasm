"""Decode errors.

The distinction that matters is `Eof` versus `UnexpectedEof`, and it is not
cosmetic. `Eof` means the decoder was asked for an instruction and the input was
already exhausted -- a clean end of stream. `UnexpectedEof` means it started an
instruction, consumed bytes, and then ran out. A caller walking a flat image
loops on the first and refuses to trust the offset on the second.
"""

from __future__ import annotations


class DecodeError(Exception):
    """Base class for every decode failure."""

    is_eof = False
    is_unexpected_eof = False


class Eof(DecodeError):
    """No instruction was started because the input was already exhausted."""

    is_eof = True

    def __init__(self) -> None:
        super().__init__("End of input")


class UnexpectedEof(DecodeError):
    """An instruction was started but the input ran out mid-instruction."""

    is_unexpected_eof = True

    def __init__(self, detail: str = "") -> None:
        suffix = f": {detail}" if detail else ""
        super().__init__(f"Unexpected EOF while decoding an instruction{suffix}")


class InvalidOptions(DecodeError):
    """The decoder was configured with something it cannot honour."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Invalid options provided: {detail}")


class InvalidInput(DecodeError):
    """The input cannot be decoded with the requested settings."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Invalid input: {detail}")


class UnsupportedOpcode(DecodeError):
    """The opcode is not decodable for the selected CPU."""

    def __init__(self, opcode: int) -> None:
        self.opcode = opcode
        super().__init__(f"Unsupported opcode: 0x{opcode:02X}")
