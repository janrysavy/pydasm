"""Decoded prefix bytes must retain their x86 meaning in default NASM output."""
from copy import deepcopy

import pytest

from pydasm import decode_one
from pydasm.nasm_formatter import NasmFormatter, FormatOptions


@pytest.mark.parametrize("raw, expected", [
    ("36c47f08", "les di,[ss:bx+8]"),
    ("26c47f08", "les di,[es:bx+8]"),
    ("2ec47f08", "les di,[cs:bx+8]"),
    ("3ec47e08", "les di,[ds:bp+8]"),
    ("36a10010", "mov ax,[ss:1000h]"),
    ("2636c47f08", "les di,[ss:bx+8]"),
    ("3626c47f08", "les di,[es:bx+8]"),
    ("36a4", "ss movsb"),
    ("3ea4", "ds movsb"),
    ("f3a4", "rep movsb"),
    ("f2a6", "repne cmpsb"),
    ("f3a6", "repe cmpsb"),
    ("f2f3a6", "repe cmpsb"),
    ("f3f2a6", "repne cmpsb"),
    ("f0360107", "lock add [ss:bx],ax"),
    ("36d7", "ss xlatb"),
    # STOS/SCAS have a fixed ES destination; SS must not replace it.
    ("36aa", "stosb"),
    ("36ae", "scasb"),
    ("f336aa", "rep stosb"),
    ("f390", "nop"),
])
def test_default_formatter_preserves_prefix_semantics(raw, expected):
    instruction = decode_one(bytes.fromhex(raw))
    before = deepcopy(instruction)
    assert NasmFormatter().format_instruction(instruction) == expected
    assert instruction == before, "formatting must not rewrite the decoded record"


@pytest.mark.parametrize("raw, expected", [
    ("36c47f08", "les di,[ds:bx+8]"),
    ("f3a4", "movsb"),
    ("f0360107", "add [ds:bx],ax"),
])
def test_reference_prefix_omissions_are_explicit(raw, expected):
    assert NasmFormatter().format_instruction(
        decode_one(bytes.fromhex(raw)), FormatOptions(legacy_prefixes=True)
    ) == expected


def test_cli_nasm_uses_semantic_prefixes(tmp_path, capsys):
    from pydasm.cli import main
    target = tmp_path / "prefix.bin"
    target.write_bytes(bytes.fromhex("36c47f08"))
    assert main([str(target), "--nasm", "--segment", "0"]) == 0
    assert "les di,[ss:bx+8]" in capsys.readouterr().out
