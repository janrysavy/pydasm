"""Semantic comparisons can opt out of exporter operand reordering."""
import pytest
from pydasm import decode_one
from pydasm.ghidra import render_body


@pytest.mark.parametrize("encoding,expected", [
    ("8ec0", "MOV      ES, AX"),
    ("8ed0", "MOV      SS, AX"),
    ("8eda", "MOV      DS, DX"),
    ("8cc0", "MOV      AX, ES"),
    ("8cd0", "MOV      AX, SS"),
    ("8cda", "MOV      DX, DS"),
    ("8e1e3412", "MOV      DS, word ptr [0x1234]"),
    ("8c1e3412", "MOV      word ptr [0x1234], DS"),
    ("91", "XCHG     CX, AX"),
    ("368a45ff", "MOV      AL, byte ptr SS:[DI + -0x1]"),
    ("262e8b07", "MOV      AX, word ptr CS:[BX]"),
    ("d1e0", "SHL      AX, 0x1"),
    ("f3a4", "MOVSB.REP ES:DI, SI"),
    ("2eac", "LODSB    CS:SI"),
])
def test_decoded_order_retains_prefix_and_implied_operands(encoding, expected):
    ins = decode_one(bytes.fromhex(encoding))
    assert render_body(ins, 0, preserve_operand_order=True) == expected


def test_default_exporter_compatibility_is_unchanged():
    ins = decode_one(bytes.fromhex("8ec0"))
    assert render_body(ins, 0) == "MOV      AX, ES"
    assert render_body(ins, 0, preserve_operand_order=False) == render_body(ins, 0)
