"""Bounded TP6 procedure selection from TPU9 entry/code-block metadata.

This is a container reader, not code discovery. Literal pools are legal before
an entry inside its code block. Never linear-sweep those pools to find a BP
prologue, or search past the owning block for a convenient return instruction.
"""
from __future__ import annotations

import struct

from .decoder import Decoder, DecoderOptions
from .errors import Eof, UnexpectedEof

PROLOGUE = b'\x55\x89\xe5'
RECORD_SIZE = 8


def code_span(data: bytes) -> tuple[int, int]:
    """The absolute file bounds of the declared TPU9 code section."""
    if len(data) < 0x40 or data[:4] != b'TPU9':
        raise ValueError('not a complete TPU9 header')
    symbols, size = struct.unpack_from('<HH', data, 0x1c)
    start = (symbols + 15) & ~15
    if symbols < 0x40 or not size or start + size > len(data):
        raise ValueError('incomplete TPU9 code section')
    return start, start + size


def procedure_spans(data: bytes) -> tuple[tuple[int, int], ...]:
    """Local entry spans in file coordinates, bounded by their owning blocks.

    Entry and code-block records are eight bytes. An entry's block selector is
    an offset into the block table, NOT a code-section offset. Block sizes are
    cumulative; entry offsets are block-relative. Duplicate entry aliases are
    allowed. The next distinct entry in the same block also limits a span.

    Missing/invalid tables are errors, not permission to scan arbitrary bytes.
    This reads only TPU9 code geometry, not symbols, imports or relocations.
    """
    start, end = code_span(data)
    symbols = struct.unpack_from('<H', data, 0x1c)[0]
    entries_at, blocks_at, blocks_end = struct.unpack_from('<HHH', data, 0x0c)
    if not 0x40 <= entries_at <= blocks_at < blocks_end <= symbols:
        raise ValueError('invalid TPU9 entry/code-block table bounds')
    if (blocks_at - entries_at) % RECORD_SIZE or (blocks_end - blocks_at) % RECORD_SIZE:
        raise ValueError('partial TPU9 entry/code-block record')
    blocks = []
    running = 0
    for at in range(blocks_at, blocks_end, RECORD_SIZE):
        size = struct.unpack_from('<H', data, at + 2)[0]
        blocks.append((running, size))
        running += size
    if running != end - start:
        raise ValueError('TPU9 code-block sizes disagree with code section')
    offsets: dict[int, set[int]] = {}
    for at in range(entries_at, blocks_at, RECORD_SIZE):
        selector, offset = struct.unpack_from('<HH', data, at + 4)
        if (selector, offset) == (0xffff, 0xffff):
            continue  # Unassigned/external entry, including the usual entry 0.
        if selector % RECORD_SIZE or selector // RECORD_SIZE >= len(blocks):
            raise ValueError('TPU9 entry names an invalid code block')
        block = selector // RECORD_SIZE
        if offset >= blocks[block][1]:
            raise ValueError('TPU9 entry is outside its owning code block')
        offsets.setdefault(block, set()).add(offset)
    spans = []
    for block, values in offsets.items():
        base, size = blocks[block]
        ordered = sorted(values)
        for index, offset in enumerate(ordered):
            limit = ordered[index + 1] if index + 1 < len(ordered) else size
            spans.append((start + base + offset, start + base + limit))
    return tuple(sorted(spans))


def primary_span(data: bytes) -> tuple[int, int]:
    """Earliest declared local entry and its exclusive, metadata-owned end.

    The spelling PUSH BP / MOV BP,SP is required at the entry itself. This does
    not infer names, select by a matching byte pattern, or choose a later entry
    because the first one failed a reconstruction comparison.
    """
    spans = procedure_spans(data)
    if spans:
        start, end = spans[0]
        if end - start >= len(PROLOGUE) and data[start:start + 3] == PROLOGUE:
            return start, end
    raise ValueError('earliest declared TPU9 entry is not a BP-framed procedure')


def primary_routine(data: bytes) -> tuple[int, bytes]:
    """Decode the primary BP entry through its first complete RET/RETF.

    For controlled single-epilogue TP6 probes. This is NOT control-flow recovery
    for arbitrary assembly or multi-return functions. A missing return before
    the next entry/block is an error; adjacent carrier code cannot complete it.
    """
    start, limit = primary_span(data)
    code = data[start:limit]
    decoder = Decoder(code, DecoderOptions())
    position = 0
    try:
        while position < len(code):
            instruction = decoder.decode_next()
            if (not instruction.is_valid or not instruction.is_complete
                    or not 0 < instruction.length <= len(code) - position):
                raise ValueError('invalid instruction in TPU9 procedure')
            position += instruction.length
            if instruction.mnemonic.name in ('RET', 'RETF'):
                return start, bytes(code[:position])
    except (Eof, UnexpectedEof) as error:
        raise ValueError('incomplete TPU9 procedure instruction') from error
    raise ValueError('no complete return inside the TPU9 procedure span')
