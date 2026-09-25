"""Stack-only TP6 epilogues must retain their calling-convention evidence."""
import pytest
from pydasm.frame import analyse_frame

def frame(hex_bytes):
    code = bytes.fromhex(hex_bytes)
    return analyse_frame(code, 0, len(code))

@pytest.mark.parametrize('ret,discipline,pops', [
    ('c3', 'near', 0), ('c20600', 'near', 6),
    ('cb', 'far', 0), ('ca0400', 'far', 4),
])
def test_bp_frame_without_locals_needs_no_sp_reset(ret, discipline, pops):
    result = frame('55 89e5 5d ' + ret)
    assert result.has_bp_frame
    assert result.frame_size is None
    assert (result.return_discipline, result.pops) == (discipline, pops)

def test_no_locals_nested_procedure_keeps_unread_static_link():
    result = frame('55 89e5 8b4608 3b4606 5d c20600')
    assert (result.return_discipline, result.pops) == ('near', 6)
    assert [(a.offset, a.width, a.accessed_width) for a in result.arguments] == [
        (4, 2, 0), (6, 2, 2), (8, 2, 2)]
    assert any('hidden static link' in note for note in result.notes)

def test_allocated_frame_still_requires_the_observed_sp_reset():
    result = frame('55 89e5 83ec02 5d c20600')
    assert result.frame_size == 2
    assert result.return_discipline is None
    assert result.pops is None

def test_allocated_frame_with_sp_reset_still_works():
    result = frame('55 89e5 83ec02 89ec 5d c20600')
    assert (result.return_discipline, result.pops) == ('near', 6)

def test_zero_allocation_is_a_no_locals_frame():
    result = frame('55 89e5 83ec00 5d cb')
    assert (result.return_discipline, result.pops) == ('far', 0)

@pytest.mark.parametrize('code', ['55 89e5 58 c3', '5d c3', '55 89e5 c3'])
def test_missing_frame_or_wrong_pop_does_not_invent_an_epilogue(code):
    result = frame(code)
    assert result.return_discipline is None
    assert result.pops is None
