#!/usr/bin/env python3
"""Write a segment-map JSON from a project's own segment model.

    python tools/gen_segments.py project_segments.json -o corpus/segments.json

The map decides the address column of a listing, so it has to be the model that
produced the listing rather than a second guess at it: each block's base and size
come from the project, not from arithmetic on the load image.

The output is data, not code, because the map belongs to a particular image. A
project keeps its JSON beside the binary it describes; `pydasm` reads it with
`SegmentMap.load`. This script deliberately understands only the shape described
in `src/pydasm/segments.py`, so porting it to another project means mapping that
project's keys, not rewriting the logic.

Expected input shape (extra keys are ignored):

    {"source": {"sha256": "..."},
     "address_space": {"dgroup_base": "0x15030", "entry": "0x0ee29"},
     "segments": [{"id": "seg00000", "base_linear": "0x00000",
                   "size_bytes": 63552, "kind": "main", "owner": "..."}]}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydasm.segments import DEFAULT_LOAD_PARAGRAPH, Segment, SegmentMap  # noqa: E402


def build(model: dict, load_paragraph: int) -> SegmentMap:
    """Map a project's segment model onto a `SegmentMap`."""
    source = model.get("source", {})
    segments = [
        Segment(
            entry["id"],
            int(entry["base_linear"], 16),
            int(entry["size_bytes"]),
            entry.get("kind", ""),
            entry.get("owner", ""),
        )
        for entry in model["segments"]
    ]
    return SegmentMap(segments, load_paragraph=load_paragraph, target_sha256=source.get("sha256", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path, help="the project's segment model JSON")
    parser.add_argument("-o", "--output", type=Path, required=True, help="where to write the map")
    parser.add_argument(
        "--load-paragraph",
        type=lambda t: int(t, 0),
        default=DEFAULT_LOAD_PARAGRAPH,
        help=f"the paragraph the analysis loaded the image at (default {DEFAULT_LOAD_PARAGRAPH:#x})",
    )
    args = parser.parse_args()

    model = json.loads(args.model.read_text(encoding="utf-8"))
    segment_map = build(model, args.load_paragraph)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(segment_map.to_json(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output} ({len(segment_map.segments)} blocks, {segment_map.size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
