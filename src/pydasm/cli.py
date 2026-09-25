"""Command-line disassembler.

    python -m pydasm IMAGE                    Ghidra-style listing
    python -m pydasm IMAGE --nasm             marty_dasm's NASM style
    python -m pydasm GAME.EXE                 loads and relocates an MZ executable
    python -m pydasm IMAGE --segments MAP     address the listing per block

The default output is the Ghidra-compatible listing format, so this can stand in
for a listing exporter in a pipeline that consumes that.

`--segments` supplies the load layout. Without it the whole image is treated as
one block at offset zero, which is correct for a flat binary and gives the right
answer for the *first* block of a segmented image -- but not for the second and
later, where a listing addresses bytes from their own block's base. A project
exports its map with `tools/gen_segments.py`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import Decoder, DecoderOptions, __version__
from .errors import Eof, UnexpectedEof
from .ghidra import render_line
from .mz import load as load_mz
from .nasm_formatter import FormatOptions, NasmFormatter
from .segments import SegmentMap

#: Default load paragraph for an MZ image: the paragraph DOS would use for a
#: program of this size, and the one the reference listings were taken at.
DEFAULT_LOAD_SEGMENT = 0x1000


def list_address(segment_map: SegmentMap, load_segment: int, file_offset: int) -> tuple[int, int]:
    """The address column of a listing for a byte of the load image.

    A listing is *per block*: the image's segments are paragraph-aligned blocks,
    and a byte is addressed as its own block's segment plus the offset within it.
    Re-splitting a linear address at a 64K boundary gives a different, equally
    valid pair of numbers for the same byte -- and the wrong one for matching a
    listing.

    A flat map, or no map at all, reduces to one block covering everything.
    """
    block = segment_map.containing(file_offset)
    if block is None:
        return load_segment + (file_offset >> 4), file_offset & 0xF
    return load_segment + (block.base >> 4), file_offset - block.base


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pydasm",
        description="Disassemble an 8088/8086 image or DOS executable.",
    )
    parser.add_argument("image", type=Path, help="flat load image, or an MZ .EXE")
    parser.add_argument(
        "--nasm",
        action="store_true",
        help="use marty_dasm's NASM style instead of the Ghidra listing format",
    )
    parser.add_argument(
        "--segment",
        type=lambda text: int(text, 16),
        default=DEFAULT_LOAD_SEGMENT,
        metavar="PARA",
        help=f"load paragraph for an MZ image (default 0x{DEFAULT_LOAD_SEGMENT:04x})",
    )
    parser.add_argument("--start", type=lambda t: int(t, 0), default=0, metavar="OFFSET")
    parser.add_argument("--end", type=lambda t: int(t, 0), default=None, metavar="OFFSET")
    parser.add_argument(
        "--seed",
        type=lambda t: int(t, 0),
        action="append",
        default=[],
        metavar="OFFSET",
        help=(
            "a file offset that is known to start an instruction (a far-call "
            "target from the relocation table, a routine entry). Repeatable. "
            "Covers entry points a sweep cannot reach, because they sit behind "
            "data or padding."
        ),
    )
    parser.add_argument(
        "--segments",
        type=Path,
        default=None,
        metavar="JSON",
        help=(
            "the image's load layout, as written by tools/gen_segments.py. "
            "Without it the image is one block at offset zero, which "
            "mis-addresses every block after the first."
        ),
    )
    parser.add_argument(
        "--frame",
        action="store_true",
        help=(
            "for each --seed range, print the routine's frame as a header: "
            "frame size, argument slots and widths, locals, globals and call "
            "sites. Meant for the ASM->Pascal reading step."
        ),
    )
    parser.add_argument(
        "--uppercase",
        action="store_true",
        help="uppercase mnemonics (NASM style only)",
    )
    parser.add_argument("--version", action="version", version=f"pydasm {__version__}")
    return parser


def load_image(path: Path, load_segment: int) -> tuple[bytes, int]:
    """Return the image bytes and the base paragraph to render addresses at."""
    data = path.read_bytes()
    if data[:2] == b"MZ":
        image = load_mz(data, load_segment)
        return image.image, load_segment
    return data, 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.image.is_file():
        print(f"pydasm: no such file: {args.image}", file=sys.stderr)
        return 2

    image, base = load_image(args.image, args.segment)
    end = len(image) if args.end is None else min(args.end, len(image))

    if args.segments is not None:
        segment_map = SegmentMap.load(args.segments)
        # Check against the file on disk, not the load image: the map records
        # the digest of the executable it was generated from, and relocation
        # changes the bytes.
        if not segment_map.matches(args.image.read_bytes()):
            print(
                f"pydasm: {args.segments} is for a different image "
                f"(sha256 does not match {args.image})",
                file=sys.stderr,
            )
            return 2
    else:
        segment_map = SegmentMap.flat()

    decoder = Decoder(image, DecoderOptions())
    formatter = NasmFormatter() if args.nasm else None
    options = FormatOptions(uppercase_mnemonic=args.uppercase)

    def emit(position: int, instruction) -> None:
        linear = (base << 4) + position
        if formatter is None:
            segment, offset = list_address(segment_map, base, position)
            print(render_line(instruction, segment, offset, linear))
        else:
            options.ip = linear
            print(f"{linear:05x}  {formatter.format_instruction(instruction, options)}")

    def placeholder(position: int) -> None:
        linear = (base << 4) + position
        if formatter is None:
            segment, offset = list_address(segment_map, base, position)
            print(f"{segment:04x}:{offset:04x} <no instruction>")
        else:
            print(f"{linear:05x}  <no instruction>")

    def decode_at(position: int):
        decoder.set_position(position)
        return decoder.decode_next()

    position = args.start
    if args.nasm:
        # NASM style walks a fixed IP, so it needs the address to render
        # relative branches against; a flat image starts at zero.
        options.ip = (base << 4) + position

    seeded = set(args.seed)

    if args.frame:
        # Frame reading is driven by the seeds: a routine's frame is readable
        # only from the exact extent of that routine, and the seed list is where
        # the caller states those extents.
        from .frame import analyse_frame

        for position in sorted(seeded):
            if not 0 <= position < len(image):
                print(f"pydasm: seed {position:#x} is outside the image", file=sys.stderr)
                return 2
            end = args.end if args.end is not None else len(image)
            frame = analyse_frame(image, position, end)
            for line in frame.header_lines():
                print(f"; {line}")
            print()
        return 0

    emitted: set[int] = set()

    while position < end:
        try:
            instruction = decode_at(position)
        except Eof:
            break
        except UnexpectedEof:
            # A byte we cannot decode from here. Emit the placeholder the
            # Ghidra exporter uses and resynchronise one byte on.
            placeholder(position)
            position += 1
            continue

        emit(position, instruction)
        emitted.add(position)
        position += max(1, instruction.length)

    # Seeds cover what the sweep cannot start on: a routine entry that sits
    # behind data or padding has no instruction boundary leading into it, so a
    # sweep never reaches it. They are emitted after the sweep, in address
    # order, so the output stays sorted and diffable.
    for position in sorted(seeded - emitted):
        if not 0 <= position < len(image):
            print(f"pydasm: seed {position:#x} is outside the image", file=sys.stderr)
            return 2
        try:
            instruction = decode_at(position)
        except (Eof, UnexpectedEof):
            print(f"pydasm: seed {position:#x} does not decode", file=sys.stderr)
            return 2
        emit(position, instruction)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
