"""The command-line entry point.

Some of these drive the CLI over a real target and need the licensed corpus
(the `corpus` fixture skips them when it is absent); the rest build their own
synthetic images and always run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydasm.cli import build_parser, load_image, main

from conftest import LISTING_NAME, SEGMENTS_NAME, TARGET_NAME

DATA = Path(__file__).parent / "data"

#: A range whose lines are all real instructions in the corpus.
START, END = 0x51, 0x78


def golden_range(listing: Path, start: int, end: int) -> list[str]:
    """The corpus lines whose offsets fall in [start, end)."""
    lines = []
    for raw in listing.read_text(encoding="utf-8").splitlines():
        if not raw.startswith("1000:"):
            continue
        offset = int(raw[5:9], 16)
        if start <= offset < end:
            lines.append(raw.rstrip())
    return lines


def test_cli_output_matches_the_corpus(corpus, capsys):
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    listing = corpus / "listing.txt"
    assert main([str(target), "--segments", str(segments), "--start", hex(START), "--end", hex(END)]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert printed == golden_range(listing, START, END)


def test_every_instruction_the_cli_prints_matches_the_corpus(corpus, capsys):
    """The whole image, end to end, against the golden listing.

    A sweep reaches 29,441 of Ghidra's 29,525 instructions -- the other 84 are
    function entry points behind data, which no sweep can find. Of the ones it
    does reach, every line must be identical, address column included.
    """
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    listing = corpus / LISTING_NAME
    assert main([str(target), "--segments", str(segments)]) == 0
    printed = capsys.readouterr().out.splitlines()

    golden = {}
    for raw in listing.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if len(line) >= 10 and line[4] == ":" and "<no instruction>" not in line:
            golden[line.split(" ")[0]] = line

    ours = {}
    for line in printed:
        if len(line) >= 10 and line[4] == ":":
            ours.setdefault(line.split(" ")[0], line)

    shared = set(golden) & set(ours)
    assert len(shared) == 29441, len(shared)

    mismatches = [(golden[a], ours[a]) for a in shared if golden[a] != ours[a]]
    assert not mismatches, "\n".join(
        f"  ghidra: {expected!r}\n  ours  : {actual!r}" for expected, actual in mismatches[:10]
    )

    # The 84 the sweep cannot reach are function entry points behind data; a
    # sweep has no way to start there. They are reachable when a caller names
    # them, so this is a sweep limit rather than a decode one -- see
    # `test_a_missing_instruction_is_reachable_when_its_entry_is_named`.
    unreached = sorted(set(golden) - set(ours))
    assert len(unreached) == 84



def test_exe_is_loaded_and_relocated(corpus, tmp_path, capsys):
    """An MZ file's far pointers must be relocated before disassembly."""
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    assert main([str(target), "--segments", str(segments), "--start", "0x5c", "--end", "0x61"]) == 0
    out = capsys.readouterr().out
    assert "CALLF    0x2000:09b1" in out
    # The unrelocated segment would render as 0x1057 instead.
    assert "0x1057" not in out


def test_flat_image_is_not_relocated(tmp_path, capsys):
    """A flat binary has no header, so its bytes are decoded as they lie.

    The same five bytes as the EXE test above, but with the *unrelocated*
    segment field. The listing shows the difference in the byte column: the
    pointer renders at the same linear address either way, because relocation
    moves the segment and the linear address together, so the bytes are what
    actually distinguishes the two paths.
    """
    flat = tmp_path / "flat.bin"
    flat.write_bytes(bytes([0x9A, 0x41, 0x04, 0x57, 0x10]))
    assert main([str(flat), "--start", "0", "--end", "5"]) == 0
    out = capsys.readouterr().out
    assert "bytes=9A 41 04 57 10" in out
    # A flat image is addressed from paragraph 0: it is its own block.
    assert out.startswith("0000:0000"), out


def test_nasm_style(corpus, capsys):
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    assert main([str(target), "--segments", str(segments), "--nasm", "--start", "0x90", "--end", "0x95"]) == 0
    out = capsys.readouterr().out
    assert "lea di,[ss:bp" in out or "les di," in out or "mov " in out


def test_start_and_end_bounds_are_respected(corpus, capsys):
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    listing = corpus / LISTING_NAME
    assert main([str(target), "--segments", str(segments), "--start", hex(START), "--end", hex(END)]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == len(golden_range(listing, START, END))


def test_missing_file_reports_and_fails(capsys):
    assert main(["does-not-exist.bin"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_load_segment_shifts_both_the_addresses_and_the_pointer(corpus, capsys):
    """The block bases and the relocated pointers move together.

    At load paragraph 0x2000 every block base is 0x1000 higher, so file offset
    0x5c is `2000:005c` rather than `1000:005c`; and the far pointer it holds
    relocates to 0x3000:09b1 rather than 0x2000:09b1.
    """
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    assert main([str(target), "--segments", str(segments), "--segment", "0x2000", "--start", "0x5c", "--end", "0x61"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("2000:005c"), out
    assert "0x3000:09b1" in out


def test_load_image_recognises_the_mz_signature(corpus, tmp_path):
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    flat = tmp_path / "flat.bin"
    flat.write_bytes(b"\x90\x90\x90\x90")
    image, base = load_image(flat, 0x1000)
    assert image == b"\x90\x90\x90\x90"
    assert base == 0  # a flat image has no load paragraph

    mz = tmp_path / "prog.exe"
    mz.write_bytes(target.read_bytes())
    image, base = load_image(mz, 0x1000)
    assert len(image) == 86192
    assert base == 0x1000


def test_seeds_reach_the_entry_points_a_sweep_cannot(corpus, capsys):
    """A sweep misses 84 instructions; naming their entries reaches all of them.

    Those 84 are routine prologues whose first byte no instruction boundary
    leads into -- the preceding bytes are data or padding, so the sweep steps
    over the entry. They are exactly what the relocation table and the project's
    own unit map supply, so this is the offline path to the full listing.

    The entries are derived here from the corpus rather than hard-coded, so the
    test keeps testing the mechanism if the corpus is regenerated.
    """
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    listing = corpus / "listing.txt"
    from pydasm import Decoder, DecoderOptions
    from pydasm.mz import load

    image = load(target.read_bytes(), 0x1000).image
    decoder = Decoder(image, DecoderOptions())

    golden = {}
    for raw in listing.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if len(line) >= 10 and line[4] == ":" and "<no instruction>" not in line:
            golden[(int(line[:4], 16), int(line[5:9], 16))] = line

    # Where the plain sweep lands.
    emitted = set()
    position = 0
    while position < len(image):
        decoder.set_position(position)
        try:
            instruction = decoder.decode_next()
        except Exception:
            position += 1
            continue
        emitted.add(position)
        position += max(1, instruction.length)

    entries = sorted(
        ((segment << 4) + offset) - 0x10000
        for (segment, offset) in golden
        if ((segment << 4) + offset) - 0x10000 not in emitted
    )
    assert len(entries) == 84

    argv = [str(target), "--segments", str(segments)] + [
        arg for entry in entries for arg in ("--seed", hex(entry))
    ]
    assert main(argv) == 0
    printed = {line.split(" ")[0] for line in capsys.readouterr().out.splitlines() if len(line) >= 10 and line[4] == ":"}

    missing = [golden[key] for key in golden if f"{key[0]:04x}:{key[1]:04x}" not in printed]
    assert not missing, f"{len(missing)} still unreached, first: {missing[:3]}"


def test_a_seed_that_does_not_decode_is_reported(tmp_path, capsys):
    """A caller's entry point that is not one is refused, not silently skipped.

    A seed that cannot be decoded means the caller's model of where a routine
    starts is wrong, which is worth a hard failure: quietly dropping it would
    turn a bad address into a listing that looks complete.
    """
    # One byte that needs a ModRM byte after it, so it cannot decode alone.
    flat = tmp_path / "truncated.bin"
    flat.write_bytes(bytes([0x00]))
    assert main([str(flat), "--seed", "0"]) == 2
    assert "does not decode" in capsys.readouterr().err


def test_a_seed_outside_the_image_is_reported(corpus, capsys):
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    assert main([str(target), "--segments", str(segments), "--seed", "0xFFFFFF"]) == 2
    assert "outside the image" in capsys.readouterr().err


def test_frame_mode_prints_a_routine_header(corpus, capsys):
    """`--frame` emits the reading step for a seeded routine."""
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    listing = corpus / "listing.txt"
    assert main([str(target), "--segments", str(segments), "--frame", "--seed", "0x0f8ae", "--end", "0x0f906"]) == 0
    out = capsys.readouterr().out
    assert "far procedure" in out
    assert "ret 10" in out
    assert "[bp+0x06] far pointer" in out
    assert "[bp+0x0e] word" in out
    assert "0x6eee" in out
    # Header lines are comments, so the output can be pasted into a listing.
    assert all(line.startswith(";") or not line.strip() for line in out.splitlines())


def test_frame_mode_flags_a_hidden_static_link(corpus, capsys):
    """`--frame` reports the slot that routine pops without reading."""
    target = corpus / TARGET_NAME
    segments = corpus / SEGMENTS_NAME
    assert main([str(target), "--segments", str(segments), "--frame", "--seed", "0x04e2", "--end", "0x0514"]) == 0
    out = capsys.readouterr().out
    assert "near procedure" in out
    assert "ret 4" in out
    assert "static link" in out
