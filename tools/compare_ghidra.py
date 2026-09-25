#!/usr/bin/env python3
"""Differential check: our Ghidra renderer against a captured Ghidra listing.

The golden file is a byte-anchored Ghidra listing taken over a target image.
Every instruction line is decoded and re-rendered from the image bytes and the
two are compared byte for byte.

    python tools/compare_ghidra.py <listing.txt> <target.EXE>

Divergences are grouped by (mnemonic, reason) so one root cause shows up as one
entry with a count rather than as hundreds of lines.
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydasm import Decoder, DecoderOptions  # noqa: E402
from pydasm.errors import Eof, UnexpectedEof  # noqa: E402
from pydasm.ghidra import render_line  # noqa: E402
from pydasm.mz import load  # noqa: E402

#: The load image is mapped at this paragraph, so linear = 0x10000 + file offset.
IMAGE_PARA = 0x1000

LINE_RE = re.compile(r"^([0-9a-f]{4}):([0-9a-f]{4}) (.*?) ; bytes=([0-9A-F ]+) len=(\d+)$")


def parse_lines(path: Path):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        m = LINE_RE.match(line)
        if m:
            segment, offset, body, raw, length = m.groups()
            yield {
                "segment": int(segment, 16),
                "offset": int(offset, 16),
                "body": body,
                "line": line,
                "bytes": bytes.fromhex(raw.replace(" ", "")),
                "length": int(length),
            }


def main() -> int:
    listing = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus/listing.txt")
    exe_path = Path(sys.argv[2] if len(sys.argv) > 2 else "corpus/target.EXE")
    # Ghidra disassembles the *relocated* image, so the comparison has to start
    # from the same bytes the loader would have built.
    image = load(exe_path.read_bytes(), IMAGE_PARA).image

    decoder = Decoder(image, DecoderOptions())
    total = 0
    agree = 0
    failures = collections.Counter()
    examples: dict[tuple, str] = {}

    for record in parse_lines(listing):
        total += 1
        linear = (record["segment"] << 4) + record["offset"]
        file_offset = linear - (IMAGE_PARA << 4)
        if not 0 <= file_offset < len(image):
            failures["address outside image", record["body"]] += 1
            continue

        decoder.set_position(file_offset)
        try:
            instruction = decoder.decode_next()
        except (Eof, UnexpectedEof) as exc:
            failures["decode error", type(exc).__name__] += 1
            examples.setdefault(("decode error", type(exc).__name__), f"{linear:05x} {record['body']}")
            continue

        if instruction.instruction_bytes != record["bytes"]:
            key = ("byte length/content mismatch", record["body"].split()[0])
            failures[key] += 1
            examples.setdefault(
                key,
                f"{linear:05x} expected={record['bytes'].hex(' ')} got={instruction.instruction_bytes.hex(' ')}",
            )
            continue

        # Compare the whole line -- address prefix, body, and trailing fields.
        # All three are part of what a consumer of the listing reads.
        ours = render_line(instruction, record["segment"], record["offset"], linear)
        if ours == record["line"]:
            agree += 1
        else:
            key = ("text mismatch", record["body"].split()[0])
            failures[key] += 1
            examples.setdefault(key, f"{linear:05x}\n    ghidra: {record['line']!r}\n    ours  : {ours!r}")

    print(f"lines compared : {total}")
    print(f"exact matches  : {agree}")
    print(f"divergences    : {total - agree}")
    if failures:
        print()
        for (reason, detail), count in failures.most_common():
            print(f"  {count:6d}  {reason}  [{detail}]")
            print(f"          e.g. {examples[(reason, detail)]}")
    return 0 if agree == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
