"""Minimal MZ (.EXE) loading, including relocation.

This exists because it changes what a disassembly *is*. A DOS EXE stores far
pointers as segment values relative to the load segment, and the loader patches
them at load time by adding the segment the program actually landed at. Ghidra
applies those fixups before disassembling, so the segment field it reads back is
the relocated one.

The difference is not cosmetic. `9A 41 04 57 10` -- an unrelocated far call --
is listed by Ghidra as `CALLF 0x2000:09b1`, not `0x1057:0441`. Disassembling the
raw file gives the second and it looks perfectly plausible; only the relocation
table says it is wrong.

The relocation targets are *offsets within the load module*, which is why the
image this produces is directly comparable to a flat `nasm -f bin` build of the
same source: relocate a copy and decode that.
"""

from __future__ import annotations

from dataclasses import dataclass

#: A relocation entry is (offset, segment), each 16 bits, segment relative to load.
_RELOC_ENTRY_SIZE = 4
_HEADER_PARAGRAPHS_OFFSET = 0x08
_RELOC_COUNT_OFFSET = 0x06
_RELOC_TABLE_OFFSET = 0x18
_PAGE_SIZE = 512


@dataclass(frozen=True)
class MzImage:
    """A loaded (and relocated) DOS executable image."""

    #: The load module with relocations applied, as the DOS loader would build it.
    image: bytes
    #: The load module exactly as it sits in the file, before any fixups.
    raw: bytes
    #: Paragraph displacement the relocation table patches in.
    load_segment: int
    #: (linear load offset, segment) pairs from the file's relocation table.
    relocations: tuple[tuple[int, int], ...]
    header_size: int
    entry_cs: int
    entry_ip: int
    stack_ss: int
    stack_sp: int

    @property
    def entry_point(self) -> int:
        """Linear entry address within the load image."""
        return (self.entry_cs << 4) + self.entry_ip

    def relocate(self, load_segment: int) -> bytes:
        """Return the load module with every relocation patched for `load_segment`.

        The fixup *adds* the load segment to the word already at the target, it
        does not replace it: the linker left a program-relative segment there and
        the loader shifts it to where the program actually landed. The table
        entry's own segment field is not the value -- it is relative to the load
        segment too, and on this target it is always zero.
        """
        data = bytearray(self.raw)
        for offset, _segment in self.relocations:
            if offset + 2 > len(data):
                continue
            value = (int.from_bytes(data[offset : offset + 2], "little") + load_segment) & 0xFFFF
            data[offset] = value & 0xFF
            data[offset + 1] = value >> 8
        return bytes(data)


def load(data: bytes, load_segment: int = 0x1000) -> MzImage:
    """Parse an MZ executable and build its relocated load image.

    `load_segment` is the paragraph the program is assumed to have been loaded
    at, which is what the fixups are relative to. Ghidra's import uses 0x1000
    for this target, and the value matters: it is the difference between a
    listing that matches and one that merely looks right.
    """
    if len(data) < 0x1C or data[:2] != b"MZ":
        raise ValueError("not an MZ executable")

    last_page_bytes = int.from_bytes(data[0x02:0x04], "little")
    page_count = int.from_bytes(data[0x04:0x06], "little")
    reloc_count = int.from_bytes(data[_RELOC_COUNT_OFFSET:_RELOC_COUNT_OFFSET + 2], "little")
    header_size = int.from_bytes(
        data[_HEADER_PARAGRAPHS_OFFSET:_HEADER_PARAGRAPHS_OFFSET + 2], "little"
    ) * 16
    reloc_table = int.from_bytes(data[_RELOC_TABLE_OFFSET:_RELOC_TABLE_OFFSET + 2], "little")

    # The header's initial-register fields, in their documented order:
    # SS at 0x0E, SP at 0x10, IP at 0x14, CS at 0x16. The checksum sits at
    # 0x12, between SP and IP, which is the easy one to trip over.
    stack_ss = int.from_bytes(data[0x0E:0x10], "little")
    stack_sp = int.from_bytes(data[0x10:0x12], "little")
    entry_ip = int.from_bytes(data[0x14:0x16], "little")
    entry_cs = int.from_bytes(data[0x16:0x18], "little")

    declared = (page_count - 1) * _PAGE_SIZE + (last_page_bytes or _PAGE_SIZE)
    end = min(declared, len(data)) if declared else len(data)
    raw = data[header_size:end]

    # Each entry is a 16-bit offset *within a 16-bit segment*, plus that
    # segment. The segment field is not always zero -- reading the offset as a
    # bare load-module index works for the first 1,818 entries of this target
    # and then silently starts writing to the wrong place, because those
    # entries carry a segment of their own.
    relocations = []
    for index in range(reloc_count):
        at = reloc_table + index * _RELOC_ENTRY_SIZE
        if at + _RELOC_ENTRY_SIZE > len(data):
            break
        offset = int.from_bytes(data[at : at + 2], "little")
        segment = int.from_bytes(data[at + 2 : at + 4], "little")
        relocations.append(((segment << 4) + offset, segment))

    result = MzImage(
        image=b"",
        raw=raw,
        load_segment=load_segment,
        relocations=tuple(relocations),
        header_size=header_size,
        entry_cs=entry_cs,
        entry_ip=entry_ip,
        stack_ss=stack_ss,
        stack_sp=stack_sp,
    )
    return MzImage(
        image=result.relocate(load_segment),
        raw=result.raw,
        load_segment=load_segment,
        relocations=result.relocations,
        header_size=header_size,
        entry_cs=entry_cs,
        entry_ip=entry_ip,
        stack_ss=stack_ss,
        stack_sp=stack_sp,
    )


def load_file(path: str, load_segment: int = 0x1000) -> MzImage:
    with open(path, "rb") as handle:
        return load(handle.read(), load_segment)
