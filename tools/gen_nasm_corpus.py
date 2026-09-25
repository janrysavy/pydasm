#!/usr/bin/env python3
"""Emit the NASM corpus: one `IP HEXBYTES` line per case, to stdout.

The corpus is deliberately wider than any one real program. It sweeps every
opcode with a spread of ModRM bytes so the parts of the decode table a small
target never exercises -- the 80186 additions, the undocumented forms, both
shift encodings, far and direct-address operands -- are all covered, and it
repeats each case at several instruction pointers so relative-branch arithmetic
is exercised where it wraps.
"""
from __future__ import annotations

#: Instruction pointers the cases are repeated at. The last few sit near the top
#: of a segment so a forward branch overflows it.
IPS = (0x0, 0x100, 0xFFF0, 0xFFFF, 0x1234, 0xF000, 0x12345, 0xFFFFF, 0x8000)

#: ModRM bytes chosen to hit every addressing form: register direct on both
#: sides, each displacement width, the absolute form, and the group extensions.
MODRM = (0x06, 0x80, 0x34, 0x46, 0x86, 0xC0, 0xFA)

PREFIXES = (0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3)


def emit(rows: list[str], encoding: list[int], ip: int) -> None:
    rows.append(f"{ip:x} " + " ".join(f"{byte:02X}" for byte in encoding))


def main() -> None:
    rows: list[str] = []

    for opcode in range(256):
        for ip in IPS:
            # Bare opcode, then with a ModRM and displacement, then with a
            # full complement of trailing bytes so immediates are complete.
            emit(rows, [opcode], ip)
            emit(rows, [opcode, 0x06, 0x34, 0x12], ip)
            emit(rows, [opcode, 0x80, 0x34, 0x12, 0x56, 0x78], ip)
            for modrm in MODRM:
                emit(rows, [opcode, modrm, 0x34, 0x12], ip)

    for prefix in PREFIXES:
        for opcode in (0x00, 0x88, 0x8B, 0x90, 0xA0, 0xA1, 0xA4, 0xA6, 0xAC, 0xAA, 0xAE, 0xC3, 0xE8, 0xEB, 0x9A, 0x74, 0xE3, 0xE2):
            for ip in (0x100, 0xFFF0, 0x12345):
                emit(rows, [prefix, opcode, 0x06, 0x34, 0x12], ip)

    print("\n".join(rows))


if __name__ == "__main__":
    main()
