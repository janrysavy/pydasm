"""Static routine frames: what a routine's parameters and returns actually are.

This is the reading step of an ASM->Pascal reconstruction, done from the bytes
instead of by eye. Given a routine's extent it reports the frame size, the
argument slots and their widths, the locals, the globals touched and the call
sites -- the facts a routine header records, and the facts a declaration has to
agree with for the compiled layout to match the image.

**Arguments.** On this target a far routine's arguments start at `[bp+6]` (past
the saved BP and the 4-byte far return address) and a near routine's at
`[bp+4]`. The last argument ends at `6 + retf N`, so the extent comes from the
`ret` operand and the slots from the positive BP displacements. A slot's width
is the distance to the next slot, because Pascal hands arguments as a packed
run; where that disagrees with how the slot is actually read, the read wins and
the disagreement is reported.

**Locals are not typed.** That is deliberate, not an omission. The compiler
interleaves locals with the temporaries it spills, so a negative BP offset is
readable without being declarable: whether `[bp-4]` is a variable or a scratch
slot the code generator made is not decided by the bytes. `locals` therefore
reports the offsets and declines to name them -- the same distinction their
own model draws when it calls a hole a stand-in rather than a cell.

Everything here is a *reading of the bytes*. It is a sourced claim about what
the instructions do, not a proof that a particular Pascal declaration will
compile to them; only recompiling the reconstruction can settle that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .byte_reader import ByteReader
from .cpu_common import OperandSize, Register16
from .errors import Eof, UnexpectedEof
from .i808x import Intel808x
from .instruction import Instruction

#: Bytes between the first argument and BP, by return discipline: the saved BP
#: plus the return address (2 bytes near, 4 far).
ARGUMENT_BASE_NEAR = 4
ARGUMENT_BASE_FAR = 6

#: A far pointer read by LES/LDS is four bytes however its ModRM sizes it.
_FAR_POINTER_WIDTH = 4


@dataclass(frozen=True)
class Argument:
    """One stack argument slot."""

    offset: int
    #: Bytes, from the gap to the next slot (the last runs to the argument end).
    width: int
    #: The widest read the body actually performs on it.
    accessed_width: int
    kind: str

    @property
    def agrees(self) -> bool:
        """Whether the slot is read no wider than its derived size."""
        return self.accessed_width <= self.width

    def describe(self) -> str:
        width = {1: "byte", 2: "word", 4: "far pointer"}.get(self.width, f"{self.width} bytes")
        text = f"[bp+{self.offset:#04x}] {width}"
        if not self.agrees:
            text += (
                f"  (read {self.accessed_width} bytes, beyond its derived width"
                f" -- the next slot or the argument end is nearer than the read)"
            )
        return text


@dataclass
class RoutineFrame:
    """What a routine's bytes say about its interface."""

    start: int
    end: int
    #: `sub sp, N` in the prologue, if the routine has a BP frame.
    frame_size: Optional[int] = None
    has_bp_frame: bool = False
    #: `near` or `far`, from the epilogue's return.
    return_discipline: Optional[str] = None
    #: The `ret N` value: bytes of arguments the callee pops. None if the
    #: epilogue was not reached.
    pops: Optional[int] = None
    arguments: tuple[Argument, ...] = ()
    locals: tuple[int, ...] = ()
    #: DGROUP offsets the routine reads or writes directly.
    globals_touched: tuple[int, ...] = ()
    #: Near targets as linear addresses, far targets as (segment, offset).
    near_calls: tuple[int, ...] = ()
    far_calls: tuple[tuple[int, int], ...] = ()
    #: Anything the bytes show that a declaration has to know about.
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def argument_extent(self) -> Optional[tuple[int, int]]:
        """`(start, end)` of the argument run, or None if `pops` is unknown."""
        if self.pops is None:
            return None
        base = ARGUMENT_BASE_FAR if self.return_discipline == "far" else ARGUMENT_BASE_NEAR
        return base, base + self.pops

    def header_lines(self) -> list[str]:
        """The header a decoded routine carries, as text.

        Shaped to match the project's own routine headers so it can be reviewed
        beside them, not instead of them.
        """
        lines = [f"start={self.start:#07x} end={self.end:#07x}"]

        if self.return_discipline == "far":
            discipline = "far procedure"
        elif self.return_discipline == "near":
            discipline = "near procedure"
        else:
            discipline = "unknown (no epilogue reached)"
        if self.pops:
            discipline += f"; arguments popped by the callee (ret {self.pops})"
        lines.append(f"Type:    {discipline}")

        if self.arguments:
            lines.append("Params:")
            for argument in self.arguments:
                lines.append(f"         {argument.describe()}")
        elif self.return_discipline is not None:
            lines.append("Params:  none observed")

        if self.frame_size is not None:
            lines.append(f"Frame:   {self.frame_size:#x} bytes of locals/temporaries")
        if self.locals:
            offsets = ", ".join(f"[bp-{-o:#x}]" for o in self.locals)
            lines.append(f"Locals:  {offsets}  (offsets only -- not typed)")
        if self.globals_touched:
            offsets = ", ".join(f"{g:#06x}" for g in self.globals_touched)
            lines.append(f"Globals: {offsets}")
        for note in self.notes:
            lines.append(f"Note:    {note}")
        return lines


def _sizes_of(instruction: Instruction) -> list[tuple[str, object, OperandSize]]:
    return [
        (operand.kind, operand.value, operand.size)
        for operand in (instruction.operand1_type, instruction.operand2_type, instruction.operand3_type)
    ]


def analyse_frame(image: bytes, start: int, end: int) -> RoutineFrame:
    """Read a routine's frame from the bytes in `[start, end)`.

    The range must be exactly the routine: the epilogue is recognised as
    `mov sp,bp` / `pop bp` / `ret`, and a range that runs past the routine's end
    would pick up the next one's epilogue instead.

    Raises nothing on undecodable bytes -- it stops and reports what it saw, so
    a routine with a data table inside it yields a short reading and a note
    rather than an exception.
    """
    if not 0 <= start <= end <= len(image):
        raise ValueError("routine range must satisfy 0 <= start <= end <= image size")
    frame = RoutineFrame(start=start, end=end)
    # A partial final instruction must not consume the following routine.
    reader = ByteReader(image[:end])
    position = start

    # Widest read seen per BP-relative offset, and the access width that implied.
    positive: dict[int, int] = {}
    negative: set[int] = set()
    globals_touched: set[int] = set()
    near_calls: list[int] = []
    far_calls: list[tuple[int, int]] = []

    previous, before = None, None
    stopped_early = False

    while position < end:
        reader.position = position
        try:
            instruction = Intel808x.decode(reader)
        except (Eof, UnexpectedEof):
            stopped_early = True
            break

        mnemonic = instruction.mnemonic.name

        # Prologue.
        if (
            mnemonic == "MOV"
            and instruction.operand1_type.value is Register16.BP
            and instruction.operand2_type.value is Register16.SP
        ):
            frame.has_bp_frame = True
        if (
            mnemonic == "SUB"
            and instruction.operand1_type.value is Register16.SP
            and instruction.operand2_type.kind in ("imm8", "imm8s", "imm16")
        ):
            frame.frame_size = instruction.operand2_type.value

        # Epilogue: `mov sp,bp` then `pop bp` then the return.
        if (
            mnemonic in ("RET", "RETF")
            and previous is not None
            and previous.mnemonic.name == "POP"
            and previous.operand1_type.value is Register16.BP
            and before is not None
            and before.mnemonic.name == "MOV"
            and before.operand1_type.value is Register16.SP
            and before.operand2_type.value is Register16.BP
            and frame.has_bp_frame
        ):
            frame.return_discipline = "far" if mnemonic == "RETF" else "near"
            frame.pops = (
                instruction.operand1_type.value
                if instruction.operand1_type.kind in ("imm8", "imm16")
                else 0
            )

        for kind, value, size in _sizes_of(instruction):
            if kind == "addr16" and value.kind.startswith("bp"):
                offset = value.displacement
                if offset > 0:
                    # LES/LDS read a four-byte far pointer: the ModRM says
                    # 16-bit because that is the offset half, not the read.
                    width = (
                        _FAR_POINTER_WIDTH
                        if mnemonic in ("LES", "LDS")
                        else (1 if size is OperandSize.Operand8 else 2)
                    )
                    positive[offset] = max(positive.get(offset, 0), width)
                else:
                    negative.add(offset)
            elif kind == "addr16" and value.kind == "disp16":
                # mod=00 r/m=110 is a direct DGROUP address.
                globals_touched.add(value.displacement & 0xFFFF)

        if mnemonic == "CALL" and instruction.operand1_type.kind == "rel16":
            near_calls.append((position + instruction.length + instruction.operand1_type.value) & 0xFFFF)
        if mnemonic == "CALLF" and instruction.operand1_type.kind == "far16":
            far_calls.append(instruction.operand1_type.value)

        before, previous = previous, instruction
        position += max(1, instruction.length)

    if stopped_early:
        frame.notes = frame.notes + (f"bytes after {position:#07x} did not decode",)

    # Argument slots. The run the epilogue pops is `[base, base + pops)` and
    # Pascal hands arguments packed, so a slot *exists* where the run says it
    # does even when the body never reads it -- which is the normal shape of a
    # Turbo Pascal nested procedure's hidden static link. Deriving slots from
    # reads alone would drop those, so the run endpoints and the read offsets
    # are combined rather than either being trusted alone.
    if frame.pops is not None:
        base = ARGUMENT_BASE_FAR if frame.return_discipline == "far" else ARGUMENT_BASE_NEAR

        # The argument run's end is the furthest *read*, not `base + pops`. On
        # this target a routine often reads further than it pops: `ret 4` with
        # reads up to `[bp+0xa]` is a routine handed four words and popping one,
        # which is what a caller-cleaned or partially-popped call looks like.
        # Taking `pops` as the extent truncates those to a single slot.
        read_end = max((offset + width for offset, width in positive.items()), default=base)
        limit = max(base + frame.pops, read_end)

        boundaries = {base} | {offset for offset in positive if offset >= base}
        # In a parameterless routine base == limit: no slot exists there.
        starts = sorted(offset for offset in boundaries if offset < limit)
        arguments = []
        for index, offset in enumerate(starts):
            next_start = starts[index + 1] if index + 1 < len(starts) else limit
            width = max(0, next_start - offset)
            accessed = positive.get(offset, 0)
            arguments.append(
                Argument(
                    offset=offset,
                    width=width,
                    accessed_width=accessed,
                    kind={1: "byte", 2: "word", 4: "far pointer"}.get(width, "unknown"),
                )
            )
        frame.arguments = tuple(arguments)

        unread = [argument for argument in arguments if argument.accessed_width == 0]
        if unread:
            frame.notes = frame.notes + (
                "never read, but inside the popped run: "
                + ", ".join(f"[bp+{a.offset:#x}] ({a.width} bytes)" for a in unread)
                + " -- the shape of a nested procedure's hidden static link,"
                " which is still its caller's argument to supply",
            )

        # Reading past what the callee pops is a fact about the calling
        # convention, and it is the kind a declaration cannot express: the
        # routine is handed more than it removes, so the caller cleans up the
        # rest. Recorded rather than smoothed -- and it belongs in `notes` even
        # though the slots above are sized from the reads, because a reader
        # comparing `pops` against the argument count needs to see the mismatch.
        if read_end > base + frame.pops:
            frame.notes = frame.notes + (
                f"reads arguments up to [bp+{read_end - 1:#x}] but pops only"
                f" {frame.pops} byte(s) from [bp+{base:#x}]; the caller removes the"
                " rest, so the argument run is wider than the callee's own return",
            )

        outside = [offset for offset in positive if offset >= limit]
        if outside:
            frame.notes = frame.notes + (
                "reads "
                + ", ".join(f"[bp+{offset:#x}]" for offset in outside)
                + f" beyond the {frame.pops} byte(s) it pops -- an argument it is"
                " handed but does not pop, which a declaration cannot express as"
                " a plain parameter",
            )
        for argument in arguments:
            if not argument.agrees:
                frame.notes = frame.notes + (
                    f"[bp+{argument.offset:#x}] is read {argument.accessed_width} bytes wide"
                    f" but only {argument.width} remain before the next slot; the slot"
                    " boundary or the declared argument count is wrong",
                )

    frame.locals = tuple(sorted(negative))
    frame.globals_touched = tuple(sorted(globals_touched))
    frame.near_calls = tuple(near_calls)
    frame.far_calls = tuple(far_calls)
    return frame


def find_prologue_starts(image: bytes, pattern: bytes = b"\x55\x8b\xec") -> list[int]:
    """Offsets holding a `push bp` / `mov bp,sp` prologue.

    A *candidate* list, not an answer: the byte pattern also occurs inside
    instructions and in data. It exists because a sweep cannot enter a routine
    whose first byte no instruction boundary leads into, and something has to
    suggest where to look -- see `--seed` in the command line.
    """
    starts = []
    index = image.find(pattern)
    while index != -1:
        starts.append(index)
        index = image.find(pattern, index + 1)
    # 89 E5 is the alternate encoding of MOV BP,SP (8B EC above).
    index = image.find(b"\x55\x89\xe5")
    while index != -1:
        starts.append(index)
        index = image.find(b"\x55\x89\xe5", index + 1)
    return sorted(set(starts))


def call_targets_from_relocations(image: bytes, relocations) -> list[int]:
    """Far-call targets implied by the image's own relocation table.

    Every relocated far pointer in this target's code is a call to another
    segment, and the offset is the two bytes in front of the segment word. That
    makes the relocation table a source of entry points that needs no
    disassembly and no external tool -- which is what makes it the honest
    starting point for the offline workflow.

    Returns file offsets into `image`.
    """
    image_size = len(image)
    targets = set()
    for offset, _segment in relocations:
        if offset < 2 or offset + 2 > image_size:
            continue
        segment = int.from_bytes(image[offset : offset + 2], "little")
        pointer_offset = int.from_bytes(image[offset - 2 : offset], "little")
        linear = ((segment << 4) + pointer_offset) & 0xFFFFF
        for candidate in (linear - 0x10000, linear):
            if 0 <= candidate < image_size:
                targets.add(candidate)
    return sorted(targets)


__all__ = [
    "ARGUMENT_BASE_FAR",
    "ARGUMENT_BASE_NEAR",
    "Argument",
    "RoutineFrame",
    "analyse_frame",
    "call_targets_from_relocations",
    "find_prologue_starts",
]
