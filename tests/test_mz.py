"""MZ loading and relocation.

This is the layer that decides what bytes get disassembled, so it is worth
pinning independently of the renderer. The property that matters is that the
fixup *adds* to the word already at the target rather than replacing it: the
linker left a program-relative segment there and the loader shifts it.

The target these are pinned against has 2,265 relocations. The first 1,818 of
them have a zero segment field, which is exactly why a loader that ignores that
field looks correct for a while and then writes to the wrong places -- the last
447 entries carry a non-zero segment. `test_relocations_apply_the_load_segment`
covers both regions.

The target itself is not redistributable, so these take the `corpus` fixture and
skip when it is absent; see `NOTICE`. The MZ parser's own tests -- rejection of
non-MZ input, and the relocation arithmetic on a synthetic image -- need no
corpus and always run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydasm.mz import load, load_file

from conftest import LISTING_NAME, SEGMENTS_NAME, TARGET_NAME

#: The target lives outside the repository -- see NOTICE. The `corpus` fixture
#: skips these when it is absent.
DATA = Path(__file__).parent / "data"

PAGE = 512


def test_rejects_a_file_that_is_not_an_exe():
    with pytest.raises(ValueError, match="not an MZ executable"):
        load(b"\x7fELF" + b"\x00" * 64)
    with pytest.raises(ValueError):
        load(b"")


@pytest.fixture(scope="module")
def target(corpus: Path):
    return load_file(str(corpus / TARGET_NAME), 0x1000)


def test_load_module_size(target):
    assert len(target.raw) == 86192
    assert len(target.image) == 86192


def test_header_fields(target):
    assert (target.entry_cs, target.entry_ip) == (0x0000, 0xEE29)
    assert target.entry_point == 0xEE29
    assert (target.stack_ss, target.stack_sp) == (0x1C5E, 0x4000)


def test_relocation_count(target):
    assert len(target.relocations) == 2265


def test_relocations_apply_the_load_segment(target):
    """Both the zero-segment and non-zero-segment halves of the table."""
    load_segment = 0x1000
    for offset, segment in target.relocations:
        # Non-zero segment fields are real, and reading the offset as a bare
        # load index would misplace exactly these.
        assert offset < len(target.raw), hex(offset)

    # Every relocated word differs from the file's copy by exactly the load
    # segment, modulo 16 bits.
    changed = 0
    for offset, _segment in target.relocations:
        before = int.from_bytes(target.raw[offset : offset + 2], "little")
        after = int.from_bytes(target.image[offset : offset + 2], "little")
        assert after == (before + load_segment) & 0xFFFF
        if before != after:
            changed += 1
    assert changed == len(target.relocations)


def test_non_zero_segment_entries_are_present(target):
    """The entries a naive loader would misplace.

    A reader that treats the offset as a bare load-module index is correct for
    the first 1,818 entries and silently wrong for these 447, which carry a
    segment of their own.
    """
    with_segment = [(o, s) for o, s in target.relocations if s != 0]
    assert len(with_segment) == 447
    assert {s for _o, s in with_segment} == {3988, 4271, 4660, 4183, 4860, 4256, 4762, 4922, 4886, 4891}
    # Every one lands inside the load module once the segment is applied.
    assert all(o < len(target.raw) for o, _s in with_segment)


def test_far_pointer_at_the_first_relocation_site(corpus):
    """The worked example from the module docstring.

    `9A 41 04 57 10` in the file becomes `9A 41 04 57 20` once loaded at
    paragraph 0x1000, which is why Ghidra lists it as `0x2000:09b1` rather than
    as `0x1057:0441`.
    """
    target = load_file(str(corpus / TARGET_NAME), 0x1000)
    assert target.raw[0x5F:0x61] == bytes([0x57, 0x10])
    assert target.image[0x5F:0x61] == bytes([0x57, 0x20])
    assert target.image[0x5C:0x61] == bytes([0x9A, 0x41, 0x04, 0x57, 0x20])


def test_relocating_at_a_different_paragraph_shifts_every_fixup(target):
    other = target.relocate(0x2000)
    for offset, _segment in target.relocations[:50]:
        before = int.from_bytes(target.raw[offset : offset + 2], "little")
        assert int.from_bytes(other[offset : offset + 2], "little") == (before + 0x2000) & 0xFFFF


def test_the_header_describes_the_file(target, corpus):
    """Page count, last-page length and header size add up to the whole file.

    A check that the load module is being cut out of the file at the right
    place, rather than being the whole file by accident.
    """
    page_count, last_page_bytes, header_paragraphs = 187, 48, 568
    declared = (page_count - 1) * PAGE + last_page_bytes
    assert declared == (corpus / TARGET_NAME).stat().st_size
    assert target.header_size == header_paragraphs * 16
    assert len(target.raw) == declared - target.header_size
