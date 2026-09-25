"""The segment map: file offset to the address a listing prints.

The map itself is data for a particular image, so these tests build their own
where the arithmetic is what is under test and take the `corpus` fixture where
the claim is about a real listing.

The address column is the one part of the output that is a property of the load
layout rather than of the instruction, and it is the part that is easiest to get
subtly wrong, because a linear address re-split at a 64K boundary is *also* a
valid `ssss:oooo` pair naming the same byte. It is just not the one a listing
prints.

The test that matters is the one tying the map to a corpus listing: for every
line in the listing, the map's answer for that line's file offset must equal that
line's address column. A map that drifted would fail on the second block.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pydasm.segments import Segment, SegmentMap

from conftest import LISTING_NAME, SEGMENTS_NAME, TARGET_NAME

#: The corpus lives outside the repository -- see NOTICE. Tests that need it take
#: the `corpus` fixture and skip when it is absent; the rest build a map here and
#: always run.
IMAGE_PARA = 0x1000


@pytest.fixture(scope="module")
def segment_map() -> SegmentMap:
    """A synthetic three-block map, for the arithmetic.

    Contiguous, like a real load image: block two starts where block one ends, so
    the case a linear re-split gets wrong -- the *second* block's address -- is
    reachable without any gap between them.
    """
    return SegmentMap(
        (
            Segment("first", 0x00000, 0x0F840, "main", "first block"),
            Segment("second", 0x0F840, 0x0100, "unit", "second block"),
            Segment("third", 0x0F940, 0x0080, "dgroup", "data"),
        ),
        load_paragraph=0x1000,
        target_sha256="",
    )


@pytest.fixture(scope="module")
def corpus_map(corpus) -> SegmentMap:
    return SegmentMap.load(corpus / "segments.json")


def test_map_has_the_expected_blocks(segment_map):
    names = [segment.id for segment in segment_map.segments]
    assert names == ["first", "second", "third"]


def test_blocks_are_ascending_and_do_not_overlap(segment_map):
    previous = None
    for segment in segment_map.segments:
        assert segment.size > 0
        if previous is not None:
            assert segment.base >= previous.end, f"{segment.id} overlaps {previous.id}"
        previous = segment


def test_total_extent_matches_the_load_image(segment_map):
    last = segment_map.segments[-1]
    assert last.end == 0x0F9C0


def test_first_block_starts_at_zero(segment_map):
    """The first block has no far pointer to it, so it is the load base."""
    assert segment_map.segments[0].base == 0


@pytest.mark.parametrize(
    "file_offset, expected",
    [
        (0x00000, (0x1000, 0x0000)),
        (0x00050, (0x1000, 0x0050)),
        (0x0F83F, (0x1000, 0xF83F)),  # last byte of the first block
        (0x0F840, (0x1F84, 0x0000)),  # second block: the case a linear split gets wrong
        (0x0F850, (0x1F84, 0x0010)),
        (0x0F93F, (0x1F84, 0x00FF)),  # last byte of the second block
        (0x0F940, (0x1F94, 0x0000)),  # third block
    ],
)
def test_known_addresses(segment_map, file_offset, expected):
    assert segment_map.address(file_offset) == expected


def test_the_linear_split_is_a_different_answer(segment_map):
    """Both name the same byte; only one matches a listing.

    This is the whole reason the map exists, so it is asserted rather than
    described. File offset 0x0F840 is `1f84:0000` in the listing -- the start of
    the second block -- and the linear re-split of the same byte is
    `1000:f840`, one paragraph low and in the wrong block entirely.
    """
    file_offset = 0x0F840
    linear = (IMAGE_PARA << 4) + file_offset
    assert segment_map.address(file_offset) == (0x1F84, 0x0000)
    assert (((linear >> 16) << 12), linear & 0xFFFF) == (0x1000, 0xF840)
    # Same byte, two different spellings.
    assert ((0x1F84 << 4) + 0x0000) == ((0x1000 << 4) + 0xF840) == linear


def test_a_byte_outside_every_block_falls_back_to_the_linear_split(segment_map):
    """The heap beyond the load image has no block, so there is no block base."""
    outside = 0x0F9C0 + 0x40
    assert segment_map.address(outside) == (IMAGE_PARA + (outside >> 4), outside & 0xF)


def test_containing_finds_the_right_block(segment_map):
    assert segment_map.containing(0x0F83F).id == "first"
    assert segment_map.containing(0x0F840).id == "second"
    assert segment_map.containing(0x0F93F).id == "second"
    assert segment_map.containing(0x0F940).id == "third"
    assert segment_map.containing(0x0F9BF).id == "third"
    assert segment_map.containing(0x0F9C0) is None


def test_blame_runs_to_the_expected_owners(segment_map):
    """The map is also how a caller learns what a block is."""
    assert segment_map.segment_by_id("first").kind == "main"
    assert segment_map.segment_by_id("second").kind == "unit"
    assert segment_map.segment_by_id("third").kind == "dgroup"
    assert segment_map.segment_by_id("nope") is None


def test_the_map_reproduces_every_instruction_address_in_the_corpus(corpus, corpus_map):
    """The corpus is the oracle: every instruction's address column checked.

    A block base one paragraph out would fail here on the first instruction of
    the block it belongs to, which is why this is worth running over all 29,525
    rather than a sample.
    """
    checked = 0
    wrong = []
    for raw in (corpus / "listing.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if len(line) < 10 or line[4] != ":" or "<no instruction>" in line:
            continue
        segment, offset = int(line[:4], 16), int(line[5:9], 16)
        linear = (segment << 4) + offset
        file_offset = linear - (IMAGE_PARA << 4)
        checked += 1
        ours = corpus_map.address(file_offset)
        if ours != (segment, offset):
            wrong.append((line[:9], f"{ours[0]:04x}:{ours[1]:04x}"))

    assert checked == 29525, checked
    assert not wrong, f"{len(wrong)} address columns wrong, first: {wrong[:5]}"


def test_the_placeholder_rows_are_an_exporter_quirk_not_a_map_error(corpus, corpus_map):
    """The exporter's `<no instruction>` rows do not always agree with the map.

    452 of the 11,670 filler rows carry an address the map disagrees with, all
    of them where the exporter ran one row past the end of a block before
    restarting at the next one -- `1f84:0100` rather than the next block's
    `1f94:0000`.

    No instruction is affected: every one of the 29,525 decoded rows agrees with
    the map exactly. The quirk is recorded rather than reproduced, because
    reproducing it would mean emitting addresses that are wrong about which
    block a byte is in, and the byte at `1f84:0100` is not in that block at all.
    """
    disagreements = 0
    for raw in (corpus / "listing.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if len(line) < 10 or line[4] != ":" or "<no instruction>" not in line:
            continue
        segment, offset = int(line[:4], 16), int(line[5:9], 16)
        file_offset = ((segment << 4) + offset) - (IMAGE_PARA << 4)
        if corpus_map.address(file_offset) != (segment, offset):
            disagreements += 1
    assert disagreements == 452, disagreements


def test_a_shifted_load_paragraph_shifts_the_blocks(segment_map):
    """Relocating elsewhere moves every block base by the same amount."""
    shifted = SegmentMap(
        segment_map.segments, load_paragraph=0x2000, target_sha256=""
    )
    assert shifted.address(0x0F840) == (0x2F84, 0x0000)
    assert shifted.address(0x00000) == (0x2000, 0x0000)


def test_a_gap_between_blocks_falls_back_to_the_linear_split():
    """Blocks need not be contiguous, and a byte in the gap belongs to neither.

    The fallback is the flat rule, which is what a listing shows for a byte the
    map does not place -- the MZ header or the heap, in a real image.
    """
    gapped = SegmentMap(
        (Segment("low", 0x0000, 0x0100, "code", ""), Segment("high", 0x0200, 0x0100, "data", "")),
        load_paragraph=0x1000,
    )
    assert gapped.containing(0x0180) is None
    assert gapped.address(0x0180) == (0x1000 + 0x18, 0x0)


def test_a_flat_map_addresses_everything_from_the_load_paragraph():
    """With no blocks, the rule reduces to one big block at offset zero."""
    flat = SegmentMap.flat()
    assert flat.is_flat
    assert flat.containing(0x1234) is None
    assert flat.address(0x1234) == (0x1234 >> 4, 0x4)
    assert flat.address(0x1234) == (0x0123, 0x4)

    based = SegmentMap.flat(load_paragraph=0x2000)
    assert based.address(0x1234) == (0x2123, 0x4)


def test_a_map_round_trips_through_json(tmp_path, segment_map):
    path = tmp_path / "segments.json"
    path.write_text(json.dumps(segment_map.to_json()), encoding="utf-8")
    restored = SegmentMap.load(path)
    assert [s.id for s in restored.segments] == [s.id for s in segment_map.segments]
    assert [s.base for s in restored.segments] == [s.base for s in segment_map.segments]
    assert [s.size for s in restored.segments] == [s.size for s in segment_map.segments]
    assert restored.load_paragraph == segment_map.load_paragraph


def test_a_map_with_a_digest_refuses_a_different_image(segment_map, tmp_path):
    """A map generated for one build must not silently address another."""
    import hashlib

    image = bytes([0x90, 0x90, 0x90, 0x90])
    digest = hashlib.sha256(image).hexdigest()
    checked = SegmentMap(segment_map.segments, load_paragraph=0x1000, target_sha256=digest)
    assert checked.matches(image)
    assert not checked.matches(b"different bytes")
    # A map that records no digest makes no claim and is not refused.
    assert SegmentMap.flat().matches(b"anything")
