"""Segment maps: file offset to the address a listing prints.

A listing is **per block**. The image is a set of paragraph-aligned segments, and
a byte is addressed as its own block's segment plus the offset within it:

    segment = load_paragraph + block_paragraph
    offset  = file_offset - block_start

This is not the same as re-splitting the linear address at a 64K boundary, and
the difference only shows up in the second block and later. For a block starting
at file offset 0x0F840 with the image loaded at paragraph 0x1000, that byte is
`1f84:0000` in a listing while the linear re-split of the same address is
`1000:f840`. Both name the same byte; only one matches what the tooling prints.

The map itself is a property of a particular image, so it is not carried here --
load one from JSON with `SegmentMap.from_json`:

    {"load_paragraph": "0x1000",
     "target_sha256": "d41d8cd9...",
     "segments": [{"id": "seg00000", "base": "0x00000", "size": 63552,
                   "kind": "main", "owner": "entry stub and main body"}]}

`tools/gen_segments.py` writes one from a project's own segment model, so the
map a caller disassembles with is the model that produced the listing rather
than a second guess at it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

#: The load paragraph the analysis behind the reference listings used. A caller
#: importing a project at a different paragraph passes its own.
DEFAULT_LOAD_PARAGRAPH = 0x1000


def _number(value: object) -> int:
    """Accept an int or a `0x`-prefixed string, which is how the JSON writes them."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"expected an int or a numeric string, got {type(value).__name__}")


@dataclass(frozen=True)
class Segment:
    """One paragraph-aligned block of a load image."""

    id: str
    #: Offset of the block within the load image, in bytes.
    base: int
    size: int
    kind: str = ""
    owner: str = ""

    @property
    def end(self) -> int:
        return self.base + self.size


class SegmentMap:
    """The blocks of one load image, in ascending order.

    An empty map is legal and means "this image has one unnamed block starting
    at offset zero", which is the right answer for a flat binary and the fallback
    for an image whose layout is not known.
    """

    def __init__(
        self,
        segments: Iterable[Segment],
        load_paragraph: int = DEFAULT_LOAD_PARAGRAPH,
        target_sha256: str = "",
    ) -> None:
        self.segments: tuple[Segment, ...] = tuple(segments)
        self.load_paragraph = load_paragraph
        self.target_sha256 = target_sha256

    # -- construction ---------------------------------------------------

    @classmethod
    def flat(cls, load_paragraph: int = 0) -> "SegmentMap":
        """A single unnamed block at offset zero: a flat binary's layout."""
        return cls((), load_paragraph=load_paragraph)

    @classmethod
    def from_json(cls, data: dict) -> "SegmentMap":
        return cls(
            (
                Segment(
                    entry["id"],
                    _number(entry["base"]),
                    _number(entry["size"]),
                    entry.get("kind", ""),
                    entry.get("owner", ""),
                )
                for entry in data.get("segments", ())
            ),
            load_paragraph=_number(data.get("load_paragraph", DEFAULT_LOAD_PARAGRAPH)),
            target_sha256=data.get("target_sha256", ""),
        )

    @classmethod
    def load(cls, path: str | Path) -> "SegmentMap":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_json(self) -> dict:
        return {
            "load_paragraph": f"{self.load_paragraph:#x}",
            "target_sha256": self.target_sha256,
            "segments": [
                {
                    "id": segment.id,
                    "base": f"{segment.base:#07x}",
                    "size": segment.size,
                    "kind": segment.kind,
                    "owner": segment.owner,
                }
                for segment in self.segments
            ],
        }

    # -- queries --------------------------------------------------------

    @property
    def is_flat(self) -> bool:
        return not self.segments

    @property
    def size(self) -> int:
        """The load image's extent, or 0 for a flat map with no declared size."""
        return max((segment.end for segment in self.segments), default=0)

    def containing(self, file_offset: int) -> Optional[Segment]:
        """The block a byte belongs to, or None if it is outside every block."""
        for segment in self.segments:
            if segment.base <= file_offset < segment.end:
                return segment
        return None

    def address(self, file_offset: int) -> tuple[int, int]:
        """The `(segment, offset)` a listing prints for a byte.

        A flat map -- or a byte outside every declared block -- reduces to
        `load_paragraph + file_offset // 16 : file_offset % 16`, which is the
        same rule with one very large block.
        """
        segment = self.containing(file_offset)
        if segment is None:
            return self.load_paragraph + (file_offset >> 4), file_offset & 0xF
        return self.load_paragraph + (segment.base >> 4), file_offset - segment.base

    def segment_by_id(self, name: str) -> Optional[Segment]:
        for segment in self.segments:
            if segment.id == name:
                return segment
        return None

    def matches(self, image: bytes) -> bool:
        """Whether this map is for `image`, when the map records a digest.

        A map with no recorded digest answers True: it makes no claim.
        """
        if not self.target_sha256:
            return True
        import hashlib

        return hashlib.sha256(image).hexdigest() == self.target_sha256
