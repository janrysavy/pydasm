"""The generators reproduce the committed tables from the reference source.

`pydasm/i808x/decode_table.py` and `pydasm/_mnemonics.py` are generated, and the
check that matters is not that they are *complete* -- `test_tables.py` covers
that -- but that re-running the generator produces the same file. A table that
was hand-edited after generation would still be complete and would still decode,
while quietly disagreeing with the implementation it claims to be a port of.

These tests need the reference source, so they skip when it is not checked out.
Set `MARTY_DASM_SRC` to point at it, or clone it beside this repo.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"


def reference_source() -> Path | None:
    """Locate the marty_dasm checkout the tables were generated from."""
    env = os.environ.get("MARTY_DASM_SRC")
    candidates = []
    if env:
        candidates.append(Path(env))
    candidates.append(ROOT.parent / "marty_dasm")
    candidates.append(Path.home() / "AppData/Local/Temp/marty_dasm")
    candidates.append(Path("/tmp/marty_dasm"))
    for base in candidates:
        if (base / "crates" / "marty_dasm" / "src" / "i808X" / "decode.rs").is_file():
            return base / "crates" / "marty_dasm" / "src"
    return None


def load_generator(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = reference_source()
requires_reference = pytest.mark.skipif(
    REFERENCE is None, reason="marty_dasm source not available (set MARTY_DASM_SRC)"
)


@requires_reference
def test_decode_table_is_up_to_date():
    generator = load_generator("gen_decode_table")
    rows = generator.parse((REFERENCE / "i808X" / "decode.rs").read_text(encoding="utf-8"))
    assert len(rows) == 352

    from pydasm.i808x.decode_table import DECODE

    assert len(DECODE) == len(rows)
    for index, (expected, actual) in enumerate(zip(rows, DECODE)):
        opcode, grp, gdr, mc, xi, mnemonic, operand1, operand2 = expected
        assert actual.opcode == opcode, f"row {index}: opcode"
        assert actual.grp == grp, f"row {index}: group"
        assert actual.gdr.value == gdr, f"row {index}: GDR"
        assert actual.mc == mc, f"row {index}: microcode index"
        assert actual.xi == xi, f"row {index}: Xi"
        assert actual.mnemonic.name == mnemonic, f"row {index}: mnemonic"
        # The operands are the part a hand-edit would silently swap.
        assert actual.operand1_simple_name == _template_name(operand1), f"row {index}: operand1"
        assert actual.operand2_simple_name == _template_name(operand2), f"row {index}: operand2"
        assert _register_of(actual.operand1) == _register_of(operand1), f"row {index}: op1 register"
        assert _register_of(actual.operand2) == _register_of(operand2), f"row {index}: op2 register"


@requires_reference
def test_mnemonic_table_is_up_to_date():
    generator = load_generator("gen_mnemonics")
    variants, strings, _fallback = generator.parse(
        (REFERENCE / "mnemonic.rs").read_text(encoding="utf-8")
    )

    from pydasm._mnemonics import MNEMONIC_STR, Mnemonic

    assert [m.name for m in Mnemonic] == variants
    for name, text in strings.items():
        assert MNEMONIC_STR[Mnemonic[name]] == text, name


def _template_name(operand: str) -> str:
    """The generator's spelling: `fixed8(Register8.AL)` -> `FIXED8`."""
    return operand.split("(")[0].upper()


def _register_of(operand) -> str | None:
    """The register name a fixed-register operand carries, if any.

    Works on both sides of the comparison: the generator's `fixed8(Register8.AL)`
    string and the built `FixedOperand` object.
    """
    if isinstance(operand, str):
        return operand.split(".")[-1].rstrip(")") if "(" in operand else None
    register = getattr(operand, "register", None)
    return None if register is None else register.name
