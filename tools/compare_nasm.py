#!/usr/bin/env python3
"""Differential check: our NASM formatter against marty_dasm's own.

Reads the encodings and the oracle's answers, decodes and formats each with the
Python port, and reports every difference. The oracle is built from the
reference crate by `tools/nasm_oracle.sh`, so the comparison is against the
implementation rather than against a reading of it.

    python tools/compare_nasm.py tests/data/nasm_cases.txt tests/data/nasm_expected.txt
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydasm import Decoder, DecoderOptions  # noqa: E402
from pydasm.errors import DecodeError  # noqa: E402
from pydasm.nasm_formatter import FormatOptions, NasmFormatter  # noqa: E402


def main() -> int:
    cases_path = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/data/nasm_cases.txt")
    expected_path = Path(sys.argv[2] if len(sys.argv) > 2 else "tests/data/nasm_expected.txt")

    formatter = NasmFormatter()
    options = DecoderOptions()
    decoder = Decoder(b"", options)

    total = 0
    agree = 0
    errors_agree = 0
    failures = collections.Counter()
    examples: dict[str, list[str]] = {}

    with cases_path.open() as cases, expected_path.open() as expected:
        for raw_case, raw_expect in zip(cases, expected):
            raw_case = raw_case.strip()
            raw_expect = raw_expect.rstrip("\n")
            if not raw_case:
                continue
            total += 1
            ip_text, _, hex_text = raw_case.partition(" ")
            ip = int(ip_text, 16)
            data = bytes.fromhex(hex_text.replace(" ", ""))

            decoder.set_options(options)
            decoder.rewind()
            # The decoder wraps the input; rebuild it per case for clarity.
            decoder = Decoder(data, options)

            expected_error = raw_expect.startswith("ERR\t")
            try:
                instruction = decoder.decode_next()
            except DecodeError:
                if expected_error:
                    errors_agree += 1
                    agree += 1
                else:
                    failures["we errored, oracle decoded"] += 1
                continue

            if expected_error:
                failures["oracle errored, we decoded"] += 1
                examples.setdefault("oracle errored, we decoded", [])
                if len(examples["oracle errored, we decoded"]) < 5:
                    examples["oracle errored, we decoded"].append(f"{raw_case} -> {raw_expect}")
                continue

            expect_len, _, expected_text = raw_expect.partition("\t")
            if int(expect_len) != instruction.length:
                failures["length mismatch"] += 1
                examples.setdefault("length mismatch", [])
                if len(examples["length mismatch"]) < 5:
                    examples["length mismatch"].append(
                        f"{raw_case}: oracle={expect_len} ours={instruction.length}"
                    )
                continue

            ours = formatter.format_instruction(instruction, FormatOptions(ip=ip))
            if ours == expected_text:
                agree += 1
            else:
                key = expected_text.split(" ")[0] if expected_text else "<empty>"
                failures[f"text ({key})"] += 1
                examples.setdefault(f"text ({key})", [])
                if len(examples[f"text ({key})"]) < 3:
                    examples[f"text ({key})"].append(
                        f"{raw_case}\n      oracle: {expected_text!r}\n      ours  : {ours!r}"
                    )

    print(f"cases compared : {total}")
    print(f"exact matches  : {agree}   (of which matching errors: {errors_agree})")
    print(f"divergences    : {total - agree}")
    if failures:
        print()
        for reason, count in failures.most_common(25):
            print(f"  {count:6d}  {reason}")
            for example in examples.get(reason, []):
                print(f"          {example}")
    return 0 if agree == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
