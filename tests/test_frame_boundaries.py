"""Bounded frame inference must not invent evidence outside a routine."""
import pytest

from pydasm.frame import analyse_frame


@pytest.mark.parametrize('return_opcode', ['c3', 'cb', 'c20000', 'ca0000'])
def test_parameterless_frame_has_no_zero_width_argument(return_opcode):
    image = bytes.fromhex('5589e589ec5d' + return_opcode)
    frame = analyse_frame(image, 0, len(image))
    assert frame.pops == 0
    assert frame.arguments == ()
    assert not any('static link' in note for note in frame.notes)


@pytest.mark.parametrize('end', [7, 8])
def test_truncated_return_cannot_borrow_bytes_past_requested_end(end):
    image = bytes.fromhex('5589e589ec5dca0400')
    frame = analyse_frame(image, 0, end)
    assert frame.return_discipline is None
    assert frame.pops is None
    assert frame.arguments == ()
    assert any('did not decode' in note for note in frame.notes)


@pytest.mark.parametrize(('start', 'end'), [(-1, 2), (3, 2), (0, 10)])
def test_invalid_image_interval_is_rejected(start, end):
    with pytest.raises(ValueError, match='range'):
        analyse_frame(bytes.fromhex('5589e589ec5dcb'), start, end)


def test_epilogue_requires_sp_bp_and_pop_bp_not_only_mnemonics():
    # A frame exists, but MOV AX,BX / POP AX is not its restoration sequence.
    image = bytes.fromhex('5589e589d858cb')
    frame = analyse_frame(image, 0, len(image))
    assert frame.has_bp_frame
    assert frame.return_discipline is None
    assert frame.pops is None


def test_complete_bounded_frame_still_reports_hidden_popped_word():
    image = b'\x90' + bytes.fromhex('5589e589ec5dca0200') + b'\x90'
    frame = analyse_frame(image, 1, len(image) - 1)
    assert frame.return_discipline == 'far'
    assert frame.pops == 2
    assert [(a.offset, a.width, a.accessed_width) for a in frame.arguments] == [(6, 2, 0)]
