"""Static routine frames, checked against headers written by hand.

The routines pinned here were decoded and documented by hand, from the image,
before this module existed -- so their headers are an outside answer to compare
against rather than a restatement of its rules. Both reproduce exactly, which is
what makes the derivation worth having; anything not so checked is a reading,
not a fact.

They need the image, which is not redistributable: the `corpus` fixture skips
them when it is absent. See `NOTICE`.

**A caveat about measuring this at scale.** Those headers are prose, and they
document the frames of the routines a routine *calls* as well as its own: one
header names `[bp+0x06]` and `[bp+0x0a]` because those are where the routine it
calls receives its arguments, not where it receives its own. Comparing this
module's output to a header wholesale therefore measures the wrong thing, and a
percentage over all of them is not a fidelity number. What is checkable is that
the derivation is right on routines whose own interface is documented -- which
is what the tests below do.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydasm.frame import (
    ARGUMENT_BASE_FAR,
    ARGUMENT_BASE_NEAR,
    analyse_frame,
    call_targets_from_relocations,
    find_prologue_starts,
)
from pydasm.mz import load

from conftest import LISTING_NAME, SEGMENTS_NAME, TARGET_NAME

#: The target lives outside the repository -- see NOTICE. The `corpus` fixture
#: skips these when it is absent.
DATA = Path(__file__).parent / "data"


@pytest.fixture(scope="module")
def image(corpus: Path) -> bytes:
    return load((corpus / TARGET_NAME).read_bytes(), 0x1000).image


@pytest.fixture(scope="module")
def mz(corpus: Path):
    return load((corpus / TARGET_NAME).read_bytes(), 0x1000)


def test_read_axes_matches_its_hand_written_header(image):
    """A routine at image 0x0f8ae..0x0f906, decoded and documented by hand.

    The header records: a far procedure, `RETF 0Ah`, `[bp+0x0e]` a word line
    mask, `[bp+0x0a]` and `[bp+0x06]` far pointers, and one DGROUP word as the
    polling timeout. Every one of those comes out of the bytes.
    """
    frame = analyse_frame(image, 0x0F8AE, 0x0F906)

    assert frame.has_bp_frame
    assert frame.return_discipline == "far"
    assert frame.pops == 0x0A

    offsets = [argument.offset for argument in frame.arguments]
    assert offsets == [0x06, 0x0A, 0x0E]

    kinds = {argument.offset: argument.kind for argument in frame.arguments}
    assert kinds[0x06] == "far pointer"
    assert kinds[0x0A] == "far pointer"
    assert kinds[0x0E] == "word"

    assert frame.globals_touched == (0x6EEE,)
    assert frame.frame_size is None  # no locals beyond the frame pointer
    assert not frame.notes


def test_read_axes_argument_extent_is_what_the_return_declares(image):
    frame = analyse_frame(image, 0x0F8AE, 0x0F906)
    assert frame.argument_extent == (ARGUMENT_BASE_FAR, ARGUMENT_BASE_FAR + 0x0A)


def test_power10_matches_its_hand_written_header(image):
    """A routine at image 0x04e2..0x0514, decoded and documented by hand.

    The header records: a near function, `RET 4`, `[bp+0x06]` a loop count, and
    `[bp+0x04]` "the hidden nested-procedure static link, not a logical
    argument" -- which the caller supplies and the callee pops without reading.
    A derivation built from reads alone misses that slot; this one does not, and
    flags it for what it is.
    """
    frame = analyse_frame(image, 0x04E2, 0x0514)

    assert frame.has_bp_frame
    assert frame.return_discipline == "near"
    assert frame.pops == 4

    offsets = [argument.offset for argument in frame.arguments]
    assert offsets == [0x04, 0x06]

    link, exponent = frame.arguments
    assert link.width == 2 and link.accessed_width == 0
    assert exponent.width == 2 and exponent.accessed_width == 2

    assert frame.frame_size == 4
    assert any("never read" in note and "static link" in note for note in frame.notes)


def test_scramble_string_records_the_under_pop_its_own_notes_describe(image):
    """`0xd604..0xd70c`: a routine reading an argument its `ret` does not pop.

    The hand-written description of this routine records the same thing
    independently -- a callee whose `ret 4` pops one of the two far pointers the
    caller pushed -- so this is a reading that can be checked against an outside
    account rather than only asserted.
    """
    frame = analyse_frame(image, 0xD604, 0xD70C)
    assert frame.return_discipline == "near"
    assert frame.pops == 4
    assert any("pops only 4 byte(s)" in note for note in frame.notes)


def test_a_leaf_routine_reports_no_frame(image):
    """No `push bp` means no frame, and the analysis says so rather than guessing."""
    # One byte: `NOP`.
    frame = analyse_frame(image, 0, 1)
    assert not frame.has_bp_frame
    assert frame.return_discipline is None
    assert frame.arguments == ()


def test_a_range_that_does_not_decode_stops_and_says_so(image):
    """A data table inside a claimed range yields a short reading, not an exception."""
    # A run of zero bytes decodes as `ADD [BX+SI],AL` forever, so force a stub
    # by cutting the range mid-instruction instead.
    frame = analyse_frame(image, 0x0F8AE, 0x0F8B0)  # `push bp` / `mov bp,sp` only
    assert frame.has_bp_frame
    assert frame.return_discipline is None  # no epilogue in the range
    assert frame.pops is None


def test_header_lines_read_like_the_projects_own(image):
    frame = analyse_frame(image, 0x0F8AE, 0x0F906)
    lines = frame.header_lines()
    joined = "\n".join(lines)
    assert "far procedure" in joined
    assert "ret 10" in joined
    assert "[bp+0x06] far pointer" in joined
    assert "[bp+0x0e] word" in joined
    assert "0x6eee" in joined


# -- entry-point discovery ----------------------------------------------


def test_relocation_table_yields_call_targets(image, mz):
    """The offline source of entry points, needing no disassembly.

    Every relocated far pointer in the code is a call to another segment, and
    the target offset is the word in front of the relocated segment.
    """
    targets = call_targets_from_relocations(image, mz.relocations)
    assert len(targets) > 50

    # `CRT.GOTOXY` is image 0x12bb3 (segment 0x129a, offset 0x0213) and is the
    # hottest far target in the image, so it must be in the set.
    assert 0x12BB3 in targets
    # `unit10af0_map_attribute` at image 0x10f21, the hottest game-side target.
    assert 0x10F21 in targets

    # Every candidate is inside the image.
    assert all(0 <= target < len(image) for target in targets)


def test_prologue_scan_finds_the_routines_a_sweep_cannot_enter(image):
    starts = find_prologue_starts(image)
    assert len(starts) > 100
    # The 84 entry points a linear sweep misses are prologues; the scan is how
    # they are found without an analysis pass.
    assert 0x0F8AE in starts  # the far procedure above
    assert 0x04E2 in starts  # the near function above
