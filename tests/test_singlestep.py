"""The decoder against the SingleStepTests hardware suites.

These corpora are recordings of real silicon -- an AMD D8088 and an Intel
P80C86A -- so they answer a different question from the rest of the suite. Every
other test here compares the decoder against *another implementation*
(marty_dasm, Ghidra); a shared misreading of the 8086 would pass all of them.
These answer to the part.

`tests/data/sst_8088.json` and `sst_8086.json` are evenly spaced samples across
every opcode file, frozen so the tests need no download. The full suites are
~900 MB compressed and ~15 GB expanded; `tools/check_sst.py` runs them in full
and is what actually proves the decoder. This corpus keeps the proof runnable.

Three properties are checked, and the docstring of `tools/check_sst.py` says why
each one is the shape it is. The short version: *length* for linear
instructions, *target* for relative transfers, and *effective address* where the
instruction writes memory. Control transfers whose destination the record does
not contain (indirect calls, returns, interrupts) and instructions that fault
are counted as skipped rather than as passes, because their recorded IP is not
the next instruction and nothing about the decoder follows from it.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import check_sst  # noqa: E402


def run_corpus(path: Path):
    tests = json.loads(path.read_text(encoding="utf-8"))
    stats: collections.Counter = collections.Counter()
    failures: list = []
    check_sst.check(tests, stats, failures, show=10)
    return stats, failures


def test_8088_corpus_passes():
    """The AMD D8088 recording, sampled over every opcode."""
    stats, failures = run_corpus(DATA / "sst_8088.json")

    assert not failures, "\n".join(str(f) for f in failures[:6])
    assert stats["LENGTH MISMATCH"] == 0
    assert stats["TARGET MISMATCH"] == 0
    assert stats["ADDRESS MISMATCH"] == 0

    # A run that skipped everything would pass vacuously. These floors are what
    # make the assertion above mean something.
    assert stats["length ok"] > 3000
    assert stats["relative target ok (taken)"] + stats["relative not taken, length ok"] > 300
    assert stats["address ok"] > 500
    assert stats["undecodable"] == 0


def test_8086_corpus_passes():
    """The Intel P80C86A recording, sampled over every opcode."""
    stats, failures = run_corpus(DATA / "sst_8086.json")

    assert not failures, "\n".join(str(f) for f in failures[:6])
    assert stats["LENGTH MISMATCH"] == 0
    assert stats["TARGET MISMATCH"] == 0
    assert stats["ADDRESS MISMATCH"] == 0

    assert stats["length ok"] > 3000
    assert stats["address ok"] > 800
    assert stats["undecodable"] == 0


#: Opcode bytes the suite has no standalone test file for. They are not gaps in
#: the sample: the prefixes are exercised *as prefixes* on other opcodes, and
#: the rest are instructions the suite does not test in isolation.
_NOT_STANDALONE = frozenset(
    {
        0x0F,  # POP CS on the 8086; the suite omits it
        0x26, 0x2E, 0x36, 0x3E,  # segment override prefixes
        0x9B,  # WAIT
        0xF0, 0xF1,  # LOCK
        0xF2, 0xF3,  # REP / REPNE
        0xF4,  # HLT
    }
)


def test_the_corpora_cover_every_opcode_the_suite_provides():
    """A sample collapsed to one opcode would pass the checks above vacuously.

    The suites ship one file per opcode and one per group extension, so the only
    opcode bytes absent are the prefixes and the handful listed above.
    """
    for name in ("sst_8088.json", "sst_8086.json"):
        tests = json.loads((DATA / name).read_text(encoding="utf-8"))
        opcodes = set()
        for test in tests:
            raw = test["bytes"]
            index = 0
            while index < len(raw) and raw[index] in (0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3):
                index += 1
            opcodes.add(raw[index])
        missing = set(range(256)) - opcodes
        assert missing <= _NOT_STANDALONE, f"{name} misses {sorted(missing - _NOT_STANDALONE)}"
        assert len(opcodes) >= 245, f"{name} covers only {len(opcodes)} opcode bytes"


def test_the_corpora_include_prefixed_and_group_forms():
    """The suites prepend segment overrides and split groups by extension."""
    tests = json.loads((DATA / "sst_8088.json").read_text(encoding="utf-8"))
    prefixed = sum(1 for t in tests if t["bytes"][0] in (0x26, 0x2E, 0x36, 0x3E))
    assert prefixed > 100, prefixed


# -- the checker's own classification ----------------------------------


@pytest.mark.parametrize(
    "encoding, expected",
    [
        (bytes([0x75, 0x08]), "relative"),  # jnz rel8
        (bytes([0xE9, 0x00, 0x00]), "relative"),  # jmp rel16
        (bytes([0xE8, 0x00, 0x00]), "opaque"),  # call rel16 -- pushes a return
        (bytes([0xFF, 0xE4]), "opaque"),  # jmp sp, indirect through a register
        (bytes([0xFF, 0x26, 0x00, 0x00]), "opaque"),  # jmp [0], indirect via memory
        (bytes([0xC3]), "opaque"),  # ret
        (bytes([0xF6, 0xF0]), "faults"),  # div al, which can fault
        (bytes([0xD4, 0x00]), "faults"),  # aam 0, a divide by zero
        (bytes([0x90]), "linear"),  # nop
        (bytes([0x01, 0xD8]), "linear"),  # add ax, bx
    ],
)
def test_classification(encoding, expected):
    """How each form's IP delta has to be read.

    This is the part of the checker that was wrong twice, both times in a way
    that reported a decoder bug: an indirect `jmp` read as linear, and a
    register-target `jmp sp` missed by a memory-only test for indirectness.
    """
    from pydasm import DecoderOptions, decode_one

    assert check_sst.classify(decode_one(encoding, DecoderOptions())) == expected


def test_effective_address_uses_the_override_and_the_right_segment():
    """`26 01 15` is `add word [es:di], dx`: ES, not DI's default DS."""
    from pydasm import DecoderOptions, decode_one

    instruction = decode_one(bytes([0x26, 0x01, 0x15]), DecoderOptions())
    regs = {"es": 0x584, "ds": 0x16BE, "ss": 0x0000, "cs": 0x0000, "di": 0xA239, "bx": 0, "bp": 0, "si": 0}
    assert check_sst.effective_address(instruction, regs) == (0x584 << 4) + 0xA239


def test_effective_address_defaults_to_ds_without_an_override():
    from pydasm import DecoderOptions, decode_one

    instruction = decode_one(bytes([0x01, 0x15]), DecoderOptions())  # add [di], dx
    regs = {"es": 0, "ds": 0x16BE, "ss": 0, "cs": 0, "di": 0xA239, "bx": 0, "bp": 0, "si": 0}
    assert check_sst.effective_address(instruction, regs) == (0x16BE << 4) + 0xA239


def test_effective_address_of_a_bp_operand_uses_ss():
    """BP-relative operands address through SS, not DS.

    `8B 46 08` is `mov ax, [bp+8]`: the memory operand is the *second* one, so
    this also pins that the helper looks at the right operand rather than only
    the first.
    """
    from pydasm import DecoderOptions, decode_one

    instruction = decode_one(bytes([0x8B, 0x46, 0x08]), DecoderOptions())
    assert instruction.operand1_type.kind == "reg16"
    assert instruction.operand2_type.kind == "addr16"

    regs = {"es": 0, "ds": 0x1000, "ss": 0x2000, "cs": 0, "bp": 0x0100, "bx": 0, "si": 0, "di": 0}
    assert check_sst.effective_address(instruction, regs, operand=2) == (0x2000 << 4) + 0x0108
