"""The NASM formatter against marty_dasm's own output.

`tests/data/nasm_cases.txt` holds encodings and `nasm_expected.txt` holds what
the reference Rust implementation printed for each. The oracle is the real
crate, built with a small example driver, not a reading of the source -- see
`tools/README.md` to regenerate.

The corpus sweeps every opcode with a spread of ModRM bytes, plus prefix
combinations, so it covers the parts of the table a small real program never
exercises: the 80186 additions, the undocumented forms, both shift-count
encodings, and the far and direct-address operands.

Matching *errors* count as agreement. Roughly a quarter of the cases are
truncated encodings that must fail; a port that decoded them would be wrong in
the same way as one that rejected the valid ones.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydasm import Decoder, DecoderOptions
from pydasm.errors import DecodeError
from pydasm.nasm_formatter import FormatOptions, NasmFormatter

DATA = Path(__file__).parent / "data"
CASES = DATA / "nasm_cases.txt"
EXPECTED = DATA / "nasm_expected.txt"


def load_corpus():
    cases = CASES.read_text().splitlines()
    expected = EXPECTED.read_text().splitlines()
    assert len(cases) == len(expected), "case and expectation files are out of step"
    entries = []
    for raw_case, raw_expect in zip(cases, expected):
        case = raw_case.strip()
        if not case:
            continue
        ip_text, _, hex_text = case.partition(" ")
        entries.append((case, int(ip_text, 16), bytes.fromhex(hex_text.replace(" ", "")), raw_expect))
    return entries


def test_corpus_is_the_expected_size():
    assert len(load_corpus()) == 23418


def test_nasm_formatting_matches_the_reference_implementation():
    formatter = NasmFormatter()
    mismatches = []
    errors_agreed = 0

    for case, ip, data, expected in load_corpus():
        expects_error = expected.startswith("ERR\t")
        decoder = Decoder(data, DecoderOptions())

        try:
            instruction = decoder.decode_next()
        except DecodeError:
            if expects_error:
                errors_agreed += 1
                continue
            mismatches.append((case, expected, "we raised, the oracle decoded"))
            continue

        if expects_error:
            mismatches.append((case, expected, "the oracle raised, we decoded"))
            continue

        expected_length, _, expected_text = expected.partition("\t")
        assert instruction.length == int(expected_length), f"{case}: instruction length"

        ours = formatter.format_instruction(instruction, FormatOptions(ip=ip))
        if ours != expected_text:
            mismatches.append((case, expected_text, ours))

    # A corpus where nothing failed would prove less than it looks like it does.
    assert errors_agreed > 1000, errors_agreed
    assert not mismatches, "\n".join(
        f"  {case}\n    oracle: {expected!r}\n    ours  : {actual!r}"
        for case, expected, actual in mismatches[:10]
    )
