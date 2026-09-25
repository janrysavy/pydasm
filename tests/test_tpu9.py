"""Synthetic container controls; no licensed compiler or game binary needed."""
import struct
import pytest
from pydasm.tpu9 import code_span, procedure_spans, primary_span, primary_routine

NEAR = bytes.fromhex('5589e55dc20600')
FAR = bytes.fromhex('5589e55dca0800')


def tpu(blocks, entries):
    """Minimal structurally valid header, local tables, and code section."""
    entries_at = 64
    records = [(0xffff, 0xffff), *entries]
    blocks_at = entries_at + 8 * len(records)
    blocks_end = blocks_at + 8 * len(blocks)
    data = bytearray((blocks_end + 15) & ~15)
    data[:4] = b'TPU9'
    struct.pack_into('<HHH', data, 0x0c, entries_at, blocks_at, blocks_end)
    struct.pack_into('<HH', data, 0x1c, blocks_end, sum(map(len, blocks)))
    for i, (selector, offset) in enumerate(records):
        struct.pack_into('<HH', data, entries_at + 8 * i + 4, selector, offset)
    for i, block in enumerate(blocks):
        struct.pack_into('<H', data, blocks_at + 8 * i + 2, len(block))
    return bytes(data) + b''.join(blocks)


@pytest.mark.parametrize('pool', [b'\x01L', b'\xff', bytes.fromhex('b85589e5'), b'\0' * 32])
@pytest.mark.parametrize('routine', [NEAR, FAR])
def test_metadata_skips_constants_even_when_a_sweep_loses_the_prologue(pool, routine):
    data = tpu([pool + routine], [(0, len(pool))])
    start, _ = code_span(data)
    assert primary_routine(data) == (start + len(pool), routine)


def test_block_selector_and_entry_offset_are_not_section_offsets():
    data = tpu([b'\x90\xc3', b'\x01L' + FAR], [(8, 2)])
    start, end = code_span(data)
    assert procedure_spans(data) == ((start + 4, end),)
    assert primary_routine(data) == (start + 4, FAR)


def test_unsorted_entries_and_aliases_still_select_the_earliest_entry():
    data = tpu([NEAR, FAR], [(8, 0), (0, 0), (0, 0)])
    start, _ = code_span(data)
    assert primary_routine(data) == (start, NEAR)
    assert len(procedure_spans(data)) == 2


@pytest.mark.parametrize('same_block', [True, False])
def test_adjacent_carrier_return_cannot_complete_an_unterminated_primary(same_block):
    broken = bytes.fromhex('5589e590')
    data = (tpu([broken + FAR], [(0, 0), (0, len(broken))]) if same_block
            else tpu([broken, FAR], [(0, 0), (8, 0)]))
    start, _ = code_span(data)
    assert primary_span(data) == (start, start + len(broken))
    with pytest.raises(ValueError, match='return'):
        primary_routine(data)


def test_undeclared_prologue_inside_literal_or_operand_is_not_an_entry():
    data = tpu([b'\x05' + NEAR + b'\x90\xc3'], [(0, 1 + len(NEAR))])
    with pytest.raises(ValueError, match='declared'):
        primary_routine(data)


@pytest.mark.parametrize('selector,offset', [(1, 0), (8, 0), (0, len(NEAR)),
                                             (0xffff, 0), (0, 0xffff)])
def test_invalid_entry_never_falls_back_to_scanning(selector, offset):
    with pytest.raises(ValueError):
        primary_routine(tpu([NEAR], [(selector, offset)]))


@pytest.mark.parametrize('offset,value', [(0x0c, 0), (0x0c, 65), (0x0e, 63),
                                         (0x10, 0xffff), (0x1c, 63), (0x1e, 0)])
def test_invalid_header_or_table_geometry_is_rejected(offset, value):
    data = bytearray(tpu([NEAR], [(0, 0)]))
    struct.pack_into('<H', data, offset, value)
    with pytest.raises(ValueError):
        primary_routine(bytes(data))


def test_block_sizes_must_cover_exactly_the_declared_code():
    data = bytearray(tpu([NEAR], [(0, 0)]))
    blocks_at = struct.unpack_from('<H', data, 0x0e)[0]
    struct.pack_into('<H', data, blocks_at + 2, len(NEAR) - 1)
    with pytest.raises(ValueError, match='sizes'):
        primary_routine(bytes(data))


@pytest.mark.parametrize('data', [b'', b'TPU9', tpu([FAR], [(0, 0)])[:-1],
                                  tpu([FAR[:-1]], [(0, 0)]),
                                  tpu([NEAR[:-1]], [(0, 0)]) + b'\0'])
def test_truncation_and_bytes_after_code_cannot_supply_a_return_operand(data):
    with pytest.raises(ValueError):
        primary_routine(data)


def test_bad_primary_prologue_is_not_replaced_by_a_later_carrier():
    data = tpu([b'\x90\xc3', FAR], [(0, 0), (8, 0)])
    with pytest.raises(ValueError, match='earliest declared'):
        primary_routine(data)
