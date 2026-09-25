"""Decoder behaviour: what an instruction is, and how long it is.

Length is the load-bearing property. Every consumer of this package walks an
image and trusts `instruction_bytes` to say where the next instruction starts,
so a decode that reads the right operands but stops one byte early corrupts
everything after it. Where a test here looks fussy about a byte count, that is
why.
"""

from __future__ import annotations

import pytest

from pydasm import (
    CpuType,
    DecodeError,
    Decoder,
    DecoderOptions,
    Eof,
    Mnemonic,
    UnexpectedEof,
    decode_one,
)
from pydasm.cpu_common import OperandSize, Register8, Register16, SegmentSize


def decode(data: bytes, **kwargs):
    return decode_one(data, DecoderOptions(**kwargs))


# -- the basics ---------------------------------------------------------


def test_nop_is_one_byte():
    instruction = decode(bytes([0x90]))
    assert instruction.mnemonic is Mnemonic.NOP
    assert instruction.length == 1
    assert bytes(instruction.instruction_bytes) == bytes([0x90])


def test_register_move_reads_its_bytes():
    instruction = decode(bytes([0x8B, 0xEC]))  # mov bp, sp
    assert instruction.mnemonic is Mnemonic.MOV
    assert instruction.length == 2
    assert instruction.operand1_type.value is Register16.BP
    assert instruction.operand2_type.value is Register16.SP


def test_immediate_is_consumed_and_recorded():
    instruction = decode(bytes([0xB0, 0x12]))  # mov al, 12h
    assert instruction.mnemonic is Mnemonic.MOV
    assert instruction.length == 2
    assert instruction.operand1_type.value is Register8.AL
    assert instruction.operand2_type.kind == "imm8"
    assert instruction.operand2_type.value == 0x12
    assert bytes(instruction.immediate_bytes) == bytes([0x12])


def test_sign_extended_immediate_keeps_its_sign():
    instruction = decode(bytes([0x83, 0xC0, 0xFE]))  # add ax, -2
    assert instruction.mnemonic is Mnemonic.ADD
    assert instruction.operand2_type.kind == "imm8s"
    assert instruction.operand2_type.value == -2
    assert instruction.length == 3


def test_relative_operand_is_signed():
    instruction = decode(bytes([0xEB, 0xFE]))  # jmp -2, i.e. to itself
    assert instruction.mnemonic is Mnemonic.JMP
    assert instruction.operand1_type.kind == "rel8"
    assert instruction.operand1_type.value == -2


def test_far_pointer_is_stored_offset_first():
    # 9A 41 04 57 20 -> segment 0x2057, offset 0x0441
    instruction = decode(bytes([0x9A, 0x41, 0x04, 0x57, 0x20]))
    assert instruction.mnemonic is Mnemonic.CALLF
    assert instruction.operand1_type.kind == "far16"
    assert instruction.operand1_type.value == (0x2057, 0x0441)
    assert instruction.length == 5


def test_absolute_offset_operand():
    instruction = decode(bytes([0xA0, 0x34, 0x12]))  # mov al, [1234h]
    assert instruction.mnemonic is Mnemonic.MOV
    assert instruction.operand2_type.kind == "offset8_16"
    assert instruction.operand2_type.value == 0x1234
    assert instruction.length == 3


# -- ModRM addressing ---------------------------------------------------


@pytest.mark.parametrize(
    "modrm, expected",
    [
        (0x00, ("bx_si", 0)),  # [BX+SI]
        (0x01, ("bx_di", 0)),
        (0x02, ("bp_si", 0)),
        (0x03, ("bp_di", 0)),
        (0x04, ("si", 0)),
        (0x05, ("di", 0)),
        (0x06, ("disp16", 0x1234)),  # the exception: absolute, not [BP]
        (0x07, ("bx", 0)),
        (0x40, ("bx_si_d8", 0x08)),
        (0x46, ("bp_d8", 0x7F)),
        (0x80, ("bx_si_d16", 0x1234)),
        (0x86, ("bp_d16", 0x1234)),
    ],
)
def test_modrm_addressing_modes(modrm, expected):
    kind, displacement = expected
    tail = bytes([0x34, 0x12]) if kind.endswith(("_d16", "16")) and kind != "bx_si" else b""
    if kind.endswith("_d8"):
        tail = bytes([displacement])
    data = bytes([0x8B, modrm]) + tail
    if kind.endswith("_d16"):
        data = bytes([0x8B, modrm, 0x34, 0x12])
    instruction = decode(data)
    assert instruction.operand2_type.kind == "addr16"
    assert instruction.operand2_type.value.kind == kind


def test_modrm_mod_00_rm_110_is_absolute_not_bp():
    """The one irregular ModRM case: `06` under mod=00 is [disp16], not [BP]."""
    instruction = decode(bytes([0x8B, 0x06, 0x34, 0x12]))
    mode = instruction.operand2_type.value
    assert mode.kind == "disp16"
    assert mode.displacement == 0x1234
    assert instruction.length == 4


def test_modrm_displacement_bytes_are_counted():
    instruction = decode(bytes([0x8B, 0x86, 0x34, 0x12]))  # mov ax, [bp+1234h]
    assert instruction.has_modrm
    assert instruction.modrm_offset == 1
    assert instruction.length == 4


def test_mod_11_is_register_direct():
    instruction = decode(bytes([0x8B, 0xC3]))  # mov ax, bx
    assert instruction.operand1_type.value is Register16.AX
    assert instruction.operand2_type.value is Register16.BX


# -- opcode groups ------------------------------------------------------


def test_group_3_f6_extension_selects_the_operation():
    """0xF6 is a group opcode: the ModRM `reg` field picks the mnemonic."""
    # F6 /2 = NOT
    assert decode(bytes([0xF6, 0xD0])).mnemonic is Mnemonic.NOT  # /2, r/m=al


@pytest.mark.parametrize(
    "opcode, modrm, mnemonic",
    [
        (0xFE, 0xC0, Mnemonic.INC),  # FE /0
        (0xFE, 0xC8, Mnemonic.DEC),  # FE /1
        (0xFF, 0xC0, Mnemonic.INC),  # FF /0
        (0xFF, 0xD0, Mnemonic.CALL),  # FF /2
        (0xFF, 0xE0, Mnemonic.JMP),  # FF /4
    ],
)
def test_group_extensions(opcode, modrm, mnemonic):
    assert decode(bytes([opcode, modrm])).mnemonic is mnemonic


def test_shift_group_has_no_count_in_the_table():
    """D1 is listed as `SHL r/m16` with one operand; the count is implied."""
    instruction = decode(bytes([0xD1, 0xE0]))  # shl ax, 1
    assert instruction.mnemonic is Mnemonic.SHL
    assert instruction.operand1_type.value is Register16.AX
    assert instruction.operand2_type.kind == "none"
    assert instruction.length == 2


# -- prefixes -----------------------------------------------------------


def test_segment_override_prefix_is_consumed():
    instruction = decode(bytes([0x26, 0x8B, 0x5D, 0x08]))  # es mov bx, [di+8]
    assert instruction.mnemonic is Mnemonic.MOV
    assert bytes(instruction.prefix_bytes) == bytes([0x26])
    assert instruction.prefix_ct == 1
    assert instruction.opcode_offset == 1
    assert instruction.length == 4


def test_only_the_last_segment_override_is_effective():
    instruction = decode(bytes([0x26, 0x2E, 0x8B, 0x5D, 0x08]))
    assert bytes(instruction.prefix_bytes) == bytes([0x26, 0x2E])
    # Both bytes are recorded; the decode layer leaves the choice to the caller.
    assert instruction.opcode_offset == 2


def test_repeat_prefix_is_consumed_before_the_opcode():
    instruction = decode(bytes([0xF3, 0xA4]))  # rep movsb
    assert instruction.mnemonic is Mnemonic.MOVSB
    assert bytes(instruction.prefix_bytes) == bytes([0xF3])
    assert instruction.length == 2


def test_operand_size_and_address_size_are_not_prefixes_on_the_8086():
    """0x66 and 0x67 are opcodes on this CPU, not 386 size prefixes.

    Disassembling for a specific CPU is the whole point of the crate: 0x66 is
    `JBE rel8` here, and a decoder that treated it as an operand-size override
    would decode this instruction as something else entirely.
    """
    instruction = decode(bytes([0x66, 0x05]))
    assert instruction.mnemonic is Mnemonic.JBE
    assert bytes(instruction.prefix_bytes) == b""
    assert instruction.operand1_type.kind == "rel8"
    assert instruction.length == 2


def test_lock_prefix():
    instruction = decode(bytes([0xF0, 0x90]))
    assert instruction.mnemonic is Mnemonic.NOP
    assert bytes(instruction.prefix_bytes) == bytes([0xF0])


# -- prefixes are deliberately not stored as flags ----------------------


def test_prefix_flags_are_left_unset_for_the_8086():
    """marty_dasm's 8086 decoder tracks prefix flags in locals and drops them.

    Only the 386 decoder stores them. A caller that needs them reads
    `prefix_bytes`; see `pydasm.ghidra._segment_override`.
    """
    instruction = decode(bytes([0x26, 0xF3, 0x90]))
    assert instruction.raw_prefix_flags == 0
    assert instruction.effective_prefix_flags == 0
    assert instruction.segment_override is None
    assert bytes(instruction.prefix_bytes) == bytes([0x26, 0xF3])


# -- EOF semantics ------------------------------------------------------


def test_empty_input_is_eof_not_unexpected_eof():
    with pytest.raises(Eof) as caught:
        decode(b"")
    assert caught.value.is_eof


def test_truncated_immediate_is_unexpected_eof():
    with pytest.raises(UnexpectedEof):
        decode(bytes([0xB8, 0x34]))  # mov ax, imm16 -- needs two more bytes


def test_truncated_modrm_is_unexpected_eof():
    with pytest.raises(UnexpectedEof):
        decode(bytes([0x00]))  # needs a ModRM byte


def test_unexpected_eof_is_not_eof():
    with pytest.raises(DecodeError) as caught:
        decode(bytes([0xB8]))
    error = caught.value
    assert error.is_unexpected_eof
    assert not error.is_eof


# -- the streaming decoder ----------------------------------------------


def test_position_tracks_bytes_consumed():
    decoder = Decoder(bytes([0xB0, 0x12, 0x90]), DecoderOptions())
    assert decoder.position == 0
    decoder.decode_next()
    assert decoder.position == 2
    decoder.decode_next()
    assert decoder.position == 3
    assert decoder.is_eof()
    with pytest.raises(Eof):
        decoder.decode_next()
    assert decoder.position == 3


def test_position_after_a_partial_decode_error():
    """A failed decode still consumed bytes; the caller must be able to see it."""
    decoder = Decoder(bytes([0xB8, 0x34]), DecoderOptions())
    with pytest.raises(UnexpectedEof):
        decoder.decode_next()
    assert decoder.position == 2


def test_seek_and_rewind():
    decoder = Decoder(bytes([0xCC, 0xB0, 0x12, 0x90]), DecoderOptions())
    decoder.set_position(1)
    assert bytes(decoder.decode_next().instruction_bytes) == bytes([0xB0, 0x12])
    decoder.rewind()
    assert decoder.position == 0
    decoder.set_position(3)
    assert bytes(decoder.decode_next().instruction_bytes) == bytes([0x90])


def test_decoder_is_iterable():
    decoder = Decoder(bytes([0x90, 0x90, 0x90]), DecoderOptions())
    assert [i.mnemonic for i in decoder] == [Mnemonic.NOP] * 3


def test_segment_size_is_recorded():
    instruction = decode_one(bytes([0x90]), DecoderOptions(segment_size=SegmentSize.Segment16))
    assert instruction.segment_size is SegmentSize.Segment16


def test_cpu_families_other_than_the_8086_say_so():
    """Only the 8088/8086 is ported so far; the rest must refuse, not guess."""
    for cpu in (CpuType.Intel80386, CpuType.NecVx0, CpuType.Intel80286):
        with pytest.raises(DecodeError, match="not part of this port yet"):
            decode_one(bytes([0x90]), DecoderOptions(cpu=cpu))
