"""Select enclosing TP6 routines without accepting byte-scan fallbacks."""
import pytest
from pydasm.tpu9 import code_span, primary_routine, primary_span
from test_tpu9 import tpu, NEAR, FAR


def test_select_later_declared_entry_not_the_earliest_helper():
    data = tpu([NEAR + FAR], [(0, 0), (0, len(NEAR))])
    assert primary_routine(data)[1] == NEAR
    assert primary_routine(data, code_offset=len(NEAR)) == (code_span(data)[0] + len(NEAR), FAR)


@pytest.mark.parametrize('offset', [-1, True, 1.0, '0', 0xffff, 1, 3])
def test_invalid_or_undeclared_offsets_cannot_select_bytes(offset):
    with pytest.raises(ValueError):
        primary_routine(tpu([NEAR], [(0, 0)]), code_offset=offset)


def test_an_undeclared_prologue_in_literal_data_is_not_a_routine():
    data = tpu([NEAR + FAR], [(0, len(NEAR))])
    with pytest.raises(ValueError, match='declared'):
        primary_routine(data, code_offset=0)


def test_selected_body_cannot_borrow_a_return_from_its_next_entry():
    data = tpu([b'\x55\x89\xe5' + FAR], [(0, 0), (0, 3)])
    with pytest.raises(ValueError, match='return'):
        primary_routine(data, code_offset=0)
    assert primary_routine(data, code_offset=3)[1] == FAR


def test_selection_uses_cumulative_code_offset_not_block_table_selector():
    data = tpu([b'\x00' * 11 + NEAR, b'\x00' * 5 + FAR],
               [(8, 5), (0, 11), (8, 5)])
    offset = 11 + len(NEAR) + 5
    assert primary_routine(data, code_offset=offset)[1] == FAR
    assert primary_span(data, code_offset=offset)[1] == code_span(data)[1]


def test_explicit_selection_does_not_fall_back_after_invalid_entry():
    data = tpu([b'\x90' + FAR], [(0, 0), (0, 1)])
    with pytest.raises(ValueError, match='BP-framed'):
        primary_routine(data, code_offset=0)
