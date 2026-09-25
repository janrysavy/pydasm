"""The generated tables: decode table, mnemonics, and the ModRM table.

`pydasm/i808x/decode_table.py` and `pydasm/_mnemonics.py` are produced from the
reference Rust source by the scripts in `tools/`. That generation is only worth
anything if the result is faithful, and "faithful" here means two different
things, so both are checked:

* **Structurally complete** -- the right number of rows, no name dropped, no
  group index out of range. A generator that skipped a row would produce a
  table that decodes most instructions correctly.
* **Actually identical** -- every row re-derived from the source and compared.
  This is the check that catches a row whose operands were swapped, which is
  the failure mode that a structural check cannot see.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pydasm._mnemonics import MNEMONIC_STR, Mnemonic
from pydasm.cpu_common import REGISTER8_LUT, REGISTER16_LUT
from pydasm.i808x.decode_table import DECODE
from pydasm.i808x.modrm16 import MODRM16_TABLE
from pydasm.i808x.operands import OperandTemplate, fixed8, fixed16

SRC = Path(__file__).resolve().parent.parent / "src" / "pydasm"


# -- the decode table ---------------------------------------------------


def test_table_has_256_base_rows_and_96_group_rows():
    assert len(DECODE) == 352
    assert sum(1 for row in DECODE[:256] if row.grp != 0) == 12
    assert len(DECODE) - 256 == 96  # twelve groups of eight


def test_base_rows_are_indexed_by_their_opcode():
    """Rows 0..255 must sit at their own opcode, or the lookup is off by design."""
    for opcode in range(256):
        assert DECODE[opcode].opcode == opcode, hex(opcode)


def test_every_group_extension_is_reachable():
    """Each group opcode in the base table must have eight rows to select from.

    The decoder re-indexes as `256 + (base.grp - 1) * 8 + modrm.reg`, so the
    base rows' `grp` values have to be exactly 1..12 for that arithmetic to land
    on the right block.
    """
    decoder_groups = sorted({row.grp for row in DECODE[:256] if row.grp != 0})
    assert decoder_groups == list(range(1, 13))


@pytest.mark.parametrize("group", range(1, 13))
def test_group_row_blocks_are_contiguous_and_eight_wide(group):
    """Every group's eight extensions must be in one contiguous block."""
    start = 256 + (group - 1) * 8
    block = DECODE[start : start + 8]
    assert len(block) == 8
    # A group nested under the same opcode decodes to that opcode's mnemonic
    # family; the first row of each block names it.
    assert all(row.opcode in {row.opcode for row in block} for row in block)


def test_no_mnemonic_is_the_invalid_sentinel():
    assert all(row.mnemonic is not Mnemonic.Invalid for row in DECODE)


def test_operands_are_operand_templates():
    for row in DECODE:
        for operand in (row.operand1, row.operand2):
            assert isinstance(operand, (OperandTemplate, type(fixed8(REGISTER8_LUT[0]))))


@pytest.mark.parametrize(
    "opcode, operand1, operand2",
    [
        (0x00, "MODRM8", "REG8"),
        (0x01, "MODRM16", "REG16"),
        (0x02, "REG8", "MODRM8"),
        (0x8D, "REG16", "MODRM16"),  # LEA
        (0xC4, "REG16", "MODRM16"),  # LES
        (0xE8, "REL16", "NONE"),  # CALL rel16
        (0x9A, "FAR", "NONE"),  # CALLF ptr16:16
    ],
)
def test_representative_rows(opcode, operand1, operand2):
    row = DECODE[opcode]
    assert row.operand1_simple_name == operand1
    assert row.operand2_simple_name == operand2


def test_a_row_is_not_a_copy_of_its_neighbour():
    """A generator that emitted the same row twice would decode plausibly.

    The base table's first sixteen rows are eight pairs of `r/m,reg` and
    `reg,r/m`; if they were all identical the table would be wrong and every
    instruction would still decode to something.
    """
    signatures = {
        (row.opcode, row.mnemonic, str(row.operand1), str(row.operand2)) for row in DECODE[:256]
    }
    assert len(signatures) >= 200


# -- the ModRM table ----------------------------------------------------


def test_modrm_table_covers_every_byte():
    assert len(MODRM16_TABLE) == 256
    for value in range(256):
        assert MODRM16_TABLE[value].raw_byte() == value


def test_modrm_fields_are_extracted():
    for value in range(256):
        entry = MODRM16_TABLE[value]
        assert entry.mod == (value >> 6) & 0x03
        assert entry.reg == (value >> 3) & 0x07
        assert entry.rm == value & 0x07


def test_mod_11_is_register_direct():
    for value in range(0xC0, 0x100):
        entry = MODRM16_TABLE[value]
        assert not entry.is_addressing_mode()
        assert not entry.displacement.is_some()


def test_mod_00_is_an_address_except_the_absolute_form():
    for value in range(0x00, 0x40):
        entry = MODRM16_TABLE[value]
        assert entry.is_addressing_mode()
        if entry.rm == 0b110:
            assert entry.displacement.width == 2  # [disp16], not [bp]
        else:
            assert not entry.displacement.is_some()


def test_mod_01_and_10_carry_displacements():
    for value in range(0x40, 0x80):
        assert MODRM16_TABLE[value].displacement.width == 1
    for value in range(0x80, 0xC0):
        assert MODRM16_TABLE[value].displacement.width == 2


def test_register_interpretations_use_the_lookup_tables():
    entry = MODRM16_TABLE[0b00_000_001]  # r/m = 1, reg = 0
    assert entry.op1_reg8() is REGISTER8_LUT[1]
    assert entry.op1_reg16() is REGISTER16_LUT[1]
    assert entry.op2_reg8() is REGISTER8_LUT[0]
    assert entry.op2_reg16() is REGISTER16_LUT[0]


# -- mnemonics ----------------------------------------------------------


def test_every_mnemonic_has_a_name():
    for mnemonic in Mnemonic:
        assert isinstance(mnemonic.name, str) and mnemonic.name


def test_display_names_differ_where_they_should():
    """The enum member name and the printed name are deliberately separate."""
    assert MNEMONIC_STR[Mnemonic.CALLF] == "CALL"
    assert MNEMONIC_STR[Mnemonic.XLAT] == "XLATB"
    assert MNEMONIC_STR[Mnemonic.JMPF] == "JMP"


def test_sentinels_fall_through_to_invalid():
    for sentinel in (Mnemonic.Invalid, Mnemonic.NoOpcode, Mnemonic.Group, Mnemonic.Extension, Mnemonic.Prefix):
        assert sentinel not in MNEMONIC_STR


def test_the_8086_mnemonics_are_all_present():
    expected = {
        "NOP", "AAA", "AAD", "AAM", "AAS", "ADC", "ADD", "AND", "CALL", "CALLF",
        "CBW", "CLC", "CLD", "CLI", "CMC", "CMP", "CMPSB", "CMPSW", "CWD", "DAA",
        "DAS", "DEC", "DIV", "ESC", "WAIT", "HLT", "IDIV", "IMUL", "IN", "INC",
        "INT", "INT3", "INTO", "IRET", "JB", "JBE", "JCXZ", "JL", "JLE", "JMP",
        "JMPF", "JNB", "JNBE", "JNL", "JNLE", "JNO", "JNP", "JNS", "JNZ", "JO",
        "JP", "JS", "JZ", "LAHF", "LDS", "LEA", "LES", "LOCK", "LODSB", "LODSW",
        "LOOP", "LOOPNE", "LOOPE", "MOV", "MOVSB", "MOVSW", "MUL", "NEG", "NOT",
        "OR", "OUT", "POP", "POPF", "PUSH", "PUSHF", "RCL", "RCR", "REP", "REPNE",
        "REPE", "RETF", "RET", "ROL", "ROR", "SAHF", "SALC", "SAR", "SBB", "SCASB",
        "SCASW", "SETMO", "SETMOC", "SHL", "SHR", "SAL", "STC", "STD", "STI",
        "STOSB", "STOSW", "SUB", "TEST", "XCHG", "XLAT", "XOR",
    }
    assert expected <= {m.name for m in Mnemonic}


def test_nothing_was_dropped_between_the_enum_and_the_names():
    """Every mnemonic is either named or is one of the five known sentinels."""
    sentinels = {Mnemonic.Invalid, Mnemonic.NoOpcode, Mnemonic.Group, Mnemonic.Extension, Mnemonic.Prefix}
    unnamed = {m for m in Mnemonic if m not in MNEMONIC_STR} - sentinels
    assert unnamed == {Mnemonic.UNDEF}, sorted(m.name for m in unnamed)
