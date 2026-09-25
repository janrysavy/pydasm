"""The Ghidra renderer against a captured Ghidra listing.

The corpus is 29,525 lines of real Ghidra output, taken by a byte-anchored
exporter over an x86 real-mode DOS image. It is the whole specification for
`pydasm.ghidra`: every formatting rule in that module was read off the file, and
this test asserts the module still reproduces it exactly, line for line,
character for character.

**The corpus is not in this repository.** The image it was taken over is a
third-party binary that cannot be redistributed, and a Ghidra listing carries
the bytes it decoded -- measured at 86% of the load image -- so shipping the
listing would republish the binary just as surely as shipping the file. The
`corpus` fixture skips these tests when the corpus is absent; see `NOTICE` and
`tests/conftest.py` for how to supply one.

Two things about this test are deliberate and worth knowing before editing it.

**It compares whole lines.** The address prefix, the mnemonic padding, the
operand text and the trailing `; bytes=... len=...` are all checked. Comparing
only the mnemonics would pass on a renderer that gets every operand wrong.

**It is not a linear sweep.** Ghidra decodes where its analysis found code and
leaves everything else undefined, so the test drives the decoder from Ghidra's
own instruction addresses rather than walking the image. A sweep would decode
data as instructions and disagree with the listing for reasons that have
nothing to do with the renderer. The addresses are the input; the text is the
claim.

"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pydasm import Decoder, DecoderOptions
from pydasm.errors import DecodeError
from pydasm.ghidra import render_line
from pydasm.mz import load

from conftest import LISTING_NAME, SEGMENTS_NAME, TARGET_NAME

#: The corpus lives outside the repository -- see NOTICE. The `corpus` fixture
#: skips the test when it is absent, so these run only for someone who holds the
#: binary legitimately.
CORPUS = Path(__file__).parent / "data"


def listing_path(corpus: Path) -> Path:
    return corpus / "listing.txt"


def target_path(corpus: Path) -> Path:
    return corpus / TARGET_NAME

#: The load paragraph Ghidra imported the image at. `image:0xN` is
#: `1000:0000 + N` -- see the corpus header for how this is established.
IMAGE_PARA = 0x1000

LINE_RE = re.compile(r"^([0-9a-f]{4}):([0-9a-f]{4}) (.*?) ; bytes=([0-9A-F ]+) len=(\d+)$")


def read_corpus(corpus: Path):
    for raw in listing_path(corpus).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        match = LINE_RE.match(line)
        if match:
            segment, offset, body, raw_bytes, length = match.groups()
            yield (
                int(segment, 16),
                int(offset, 16),
                line,
                body,
                bytes.fromhex(raw_bytes.replace(" ", "")),
                int(length),
            )


@pytest.fixture(scope="module")
def relocated_image(corpus: Path) -> bytes:
    return load(target_path(corpus).read_bytes(), IMAGE_PARA).image


def test_corpus_is_the_expected_size(corpus):
    """A guard against the corpus being truncated or regenerated differently."""
    assert sum(1 for _ in read_corpus(corpus)) == 29525


def test_every_instruction_line_matches_ghidra_exactly(relocated_image, corpus):
    decoder = Decoder(relocated_image, DecoderOptions())
    mismatches = []
    total = 0

    for segment, offset, text, body, listed_bytes, listed_length in read_corpus(corpus):
        total += 1
        linear = (segment << 4) + offset
        file_offset = linear - (IMAGE_PARA << 4)
        assert 0 <= file_offset < len(relocated_image), f"{text!r} is outside the image"

        decoder.set_position(file_offset)
        instruction = decoder.decode_next()

        # The bytes come first: if these differ the renderer is being asked the
        # wrong question, and a text diff would be misleading.
        assert bytes(instruction.instruction_bytes) == listed_bytes, (
            f"{text!r}: decoded {instruction.instruction_bytes.hex(' ')}"
        )
        assert instruction.length == listed_length, f"{text!r}: length"

        ours = render_line(instruction, segment, offset, linear)
        if ours != text:
            mismatches.append((text, ours))

    assert total == 29525
    assert not mismatches, "\n".join(
        f"  ghidra: {expected!r}\n  ours  : {actual!r}" for expected, actual in mismatches[:10]
    )


def test_a_linear_sweep_agrees_wherever_ghidra_also_decoded(relocated_image, corpus):
    """A second, independent path to the same instructions.

    The corpus test drives the decoder from Ghidra's own instruction addresses.
    This one walks the first segment linearly instead, ignoring Ghidra's
    boundaries, and checks that wherever the two land on the same address they
    render the same text.

    The two are not expected to agree everywhere -- a sweep decodes data regions
    that Ghidra's analysis left undefined, and those show up as instructions
    against a `<no instruction>` line. What must never happen is a position
    where *both* decoded, and the text differs: that would be a renderer
    disagreement rather than an alignment one.
    """
    decoder = Decoder(relocated_image, DecoderOptions())
    ghidra = {}
    for segment, offset, text, body, _listed_bytes, _length in read_corpus(corpus):
        if segment == 0x1000:
            ghidra[offset] = (text, body)

    position = 0
    agreed = 0
    disagreements = []
    while position < 0x10000:
        decoder.set_position(position)
        try:
            instruction = decoder.decode_next()
        except (DecodeError, ValueError):
            position += 1
            continue

        known = ghidra.get(position)
        if known is not None:
            text, _body = known
            if "<no instruction>" not in text:
                ours = render_line(instruction, 0x1000, position, 0x10000 + position)
                if ours == text:
                    agreed += 1
                else:
                    disagreements.append((position, text, ours))
        position += max(1, instruction.length)

    # A sweep that agreed on nothing would make the assertion below vacuous.
    assert agreed > 20000, agreed
    assert not disagreements, "\n".join(
        f"  {address:#06x}\n    ghidra: {expected!r}\n    ours  : {actual!r}"
        for address, expected, actual in disagreements[:10]
    )


def test_listing_bytes_match_the_relocated_image(relocated_image, corpus):
    """Proves the load image the renderer reads is the one Ghidra read.

    If the relocation model were wrong, the instruction *text* test could still
    pass on the lines whose relocation targets are not decoded, while the bytes
    field disagreed everywhere. This checks every listed byte string against the
    image directly, independently of any decoding.
    """
    mismatches = []
    checked = 0
    for segment, offset, text, _body, listed_bytes, _length in read_corpus(corpus):
        linear = (segment << 4) + offset
        file_offset = linear - (IMAGE_PARA << 4)
        actual = relocated_image[file_offset : file_offset + len(listed_bytes)]
        checked += 1
        if actual != listed_bytes:
            mismatches.append((text, listed_bytes.hex(" "), actual.hex(" ")))
    assert checked == 29525
    assert not mismatches, "\n".join(
        f"  {text}: ghidra={expected} image={actual}" for text, expected, actual in mismatches[:10]
    )
