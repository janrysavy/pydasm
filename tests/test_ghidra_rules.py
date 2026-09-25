"""The Ghidra renderer's individual rules, each stated on its own.

The corpus test proves the renderer matches Ghidra over 29,525 instructions, but
it proves it as a single assertion: when it breaks, it says a line differs, not
which rule broke. These tests take the rules apart so a failure names the one
that regressed, and so the rules are written down somewhere a reader can find
them without reading the corpus.

Every case here was taken from a real line of the corpus.
"""

from __future__ import annotations

import pytest

from pydasm import DecoderOptions, decode_one
from pydasm.ghidra import (
    format_number,
    format_pointer,
    ghidra_mnemonic,
    normalize,
    render_body,
)

#: A linear address in the load image, matching the corpus layout.
IP = 0x233A_0513


def body(encoding: bytes, address: int = IP) -> str:
    instruction = decode_one(encoding, DecoderOptions())
    return render_body(instruction, address).rstrip()


# -- address normalisation ----------------------------------------------


@pytest.mark.parametrize(
    "linear, expected",
    [
        (0x209B1, (0x2000, 0x09B1)),
        (0x10000, (0x1000, 0x0000)),
        (0xFFFFF, (0xF000, 0xFFFF)),
        (0x12345, (0x1000, 0x2345)),
    ],
)
def test_normalize_splits_at_a_64k_boundary(linear, expected):
    assert normalize(linear) == expected


def test_far_pointer_uses_the_relocated_segment_not_the_encoded_one():
    """`9A 41 04 57 20` is segment 0x2057, offset 0x0441 -- but both spell 0x209B1.

    The listing shows the linear address re-split, which is the same location
    and a different pair of numbers.
    """
    assert format_pointer((0x2057 << 4) + 0x0441) == "0x2000:09b1"


def test_far_pointer_has_no_second_0x():
    assert format_pointer(0x209B1) == "0x2000:09b1"


def test_near_branch_wraps_inside_its_segment():
    """`1000:494c CALL 0x1000:f807`, not `0x0000:f807`.

    A backward branch near the segment base stays in its segment; treating it
    as a linear address and re-normalising would move it to segment 0.
    """
    assert body(bytes([0xE8, 0xB8, 0xAE]), 0x1494C) == "CALL     0x1000:f807"


def test_forward_near_branch():
    """`233a:0518 JNZ 0x2000:38c2`, target = 0x238b8 + 2 + 8."""
    assert body(bytes([0x75, 0x08]), 0x238B8) == "JNZ      0x2000:38c2"


# -- number formatting ---------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [(0, "0x0"), (0x68, "0x68"), (0x76, "0x76"), (-1, "-0x1"), (-32, "-0x20")],
)
def test_number_style(value, expected):
    assert format_number(value) == expected


def test_small_immediate_is_hex_not_decimal():
    assert body(bytes([0xB0, 0x0A])) == "MOV      AL, 0xa"


# -- mnemonic spellings --------------------------------------------------


def test_condition_codes_use_the_complementary_name():
    """marty_dasm says JNBE; Ghidra says JA. Same instruction, same bytes."""
    instruction = decode_one(bytes([0x77, 0x00]), DecoderOptions())
    assert instruction.mnemonic.name == "JNBE"
    assert ghidra_mnemonic(instruction) == "JA"


def test_carry_flag_aliases():
    assert ghidra_mnemonic(decode_one(bytes([0x72, 0x00]), DecoderOptions())) == "JC"
    assert ghidra_mnemonic(decode_one(bytes([0x73, 0x00]), DecoderOptions())) == "JNC"


def test_nop_prints_without_operands():
    """0x90 is `XCHG AX, AX` in the table and a bare NOP in a listing."""
    assert body(bytes([0x90])) == "NOP"


def test_xchg_prints_accumulator_first():
    """0x92 encodes `XCHG DX, AX`; the listing reads the other way."""
    assert body(bytes([0x92])) == "XCHG     AX, DX"


def test_xchg_uses_the_rm_first_order():
    assert body(bytes([0x87, 0xDE])) == "XCHG     SI, BX"


# -- operand size qualifiers --------------------------------------------


def test_memory_operand_names_its_size():
    assert body(bytes([0x89, 0x46, 0xFC])) == "MOV      word ptr [BP + -0x4], AX"


def test_accumulator_form_needs_no_size():
    """`A3` names the accumulator in the opcode, so the width is already known."""
    assert body(bytes([0xA3, 0xBE, 0x65])) == "MOV      [0x65be], AX"


def test_les_needs_no_size():
    assert body(bytes([0xC4, 0x7E, 0x08])) == "LES      DI, [BP + 0x8]"


def test_lea_needs_no_size():
    assert body(bytes([0x8D, 0x7E, 0x08])) == "LEA      DI, [BP + 0x8]"


# -- displacements -------------------------------------------------------


def test_negative_byte_displacement_keeps_its_operator():
    """`[BP + -0x4]` -- the plus stays and the number is signed."""
    assert body(bytes([0x83, 0x7E, 0xFC, 0x05])) == "CMP      word ptr [BP + -0x4], 0x5"


def test_wide_displacement_prints_unsigned():
    """A 16-bit displacement is an address, so `+ 0xfefc` rather than `- 0x104`."""
    assert body(bytes([0x83, 0xBE, 0xFC, 0xFE, 0xB5])) == "CMP      word ptr [BP + 0xfefc], -0x4b"


def test_absolute_disp16_form_is_unsigned():
    """mod=00 r/m=110 addresses `[disp16]`, not `[bp]`."""
    assert body(bytes([0xC7, 0x06, 0x76, 0x00, 0x68, 0x00])) == "MOV      word ptr [0x76], 0x68"


# -- segment prefixes ----------------------------------------------------


def test_override_is_printed_inside_the_brackets():
    assert body(bytes([0x26, 0x8B, 0x5D, 0x08])) == "MOV      BX, word ptr ES:[DI + 0x8]"


def test_override_on_a_direct_address():
    assert body(bytes([0x26, 0xA1, 0x14, 0x00])) == "MOV      AX, ES:[0x14]"


def test_last_override_wins():
    """Two segment prefixes: the later one is the effective one."""
    assert body(bytes([0x26, 0x2E, 0x8B, 0x5D, 0x08])) == "MOV      BX, word ptr CS:[DI + 0x8]"


def test_far_indirect_omits_the_override():
    """`FF /3` and `FF /5` read a far pair; Ghidra drops the segment there."""
    assert body(bytes([0x26, 0xFF, 0x19])) == "CALLF    [BX + DI]"


# -- immediates ----------------------------------------------------------


def test_signed_immediate_group_prints_signed():
    """`83 /7` is CMP, which takes a signed imm8."""
    assert body(bytes([0x83, 0xFA, 0xFF])) == "CMP      DX, -0x1"


def test_unsigned_immediate_group_prints_unsigned():
    """`83 /6` is XOR, which takes an unsigned imm8. Same operand byte."""
    assert body(bytes([0x83, 0xF2, 0xFF])) == "XOR      DX, 0xffff"


# -- implied operands ----------------------------------------------------


def test_shift_by_one_prints_its_count():
    assert body(bytes([0xD1, 0xE0])) == "SHL      AX, 0x1"


def test_shift_by_cl_prints_its_count():
    assert body(bytes([0xD3, 0xE0])) == "SHL      AX, CL"


def test_mov_to_segment_register_from_register_reverses():
    assert body(bytes([0x8E, 0xDA])) == "MOV      DX, DS"


def test_mov_to_segment_register_from_memory_does_not_reverse():
    assert body(bytes([0x8E, 0x1E, 0x34, 0x12])) == "MOV      DS, word ptr [0x1234]"


def test_mov_from_segment_register_is_already_in_listing_order():
    assert body(bytes([0x8C, 0x1E, 0x34, 0x12])) == "MOV      word ptr [0x1234], DS"


# -- string operations ---------------------------------------------------


@pytest.mark.parametrize(
    "encoding, expected",
    [
        (bytes([0xA4]), "MOVSB    ES:DI, SI"),
        (bytes([0xA5]), "MOVSW    ES:DI, SI"),
        (bytes([0xAA]), "STOSB    ES:DI"),
        (bytes([0xAB]), "STOSW    ES:DI"),
        (bytes([0xAC]), "LODSB    SI"),
        (bytes([0xAD]), "LODSW    SI"),
        (bytes([0xAE]), "SCASB    ES:DI"),
    ],
)
def test_string_operands_are_written_out(encoding, expected):
    assert body(encoding) == expected


def test_source_segment_is_named_only_when_it_is_not_ds():
    """An unqualified `SI` already means DS, so DS is not spelled out."""
    assert body(bytes([0xAC])) == "LODSB    SI"
    assert body(bytes([0x2E, 0xAC])) == "LODSB    CS:SI"


@pytest.mark.parametrize(
    "encoding, expected",
    [
        (bytes([0xF3, 0xA4]), "MOVSB.REP ES:DI, SI"),
        (bytes([0xF3, 0xA6]), "CMPSB.REPE ES:DI, SI"),
        (bytes([0xF2, 0xAE]), "SCASB.REPNE ES:DI"),
        (bytes([0xF3, 0xAA]), "STOSB.REP ES:DI"),
    ],
)
def test_repeat_prefix_becomes_a_mnemonic_suffix(encoding, expected):
    """The REP family is spelled out on the mnemonic, not as a prefix."""
    assert body(encoding) == expected


# -- the layout itself ---------------------------------------------------


def test_operandless_mnemonic_keeps_its_padding():
    """`CBW` plus six spaces: the field is nine wide and nothing trims it."""
    rendered = render_body(decode_one(bytes([0x98]), DecoderOptions()), IP)
    assert rendered == "CBW      "
    assert rendered == "CBW".ljust(9)


def test_rep_suffixed_mnemonic_gets_a_separator():
    """`MOVSB.REP` fills the nine-column field, so the operand needs a space."""
    assert body(bytes([0xF3, 0xA4])) == "MOVSB.REP ES:DI, SI"
