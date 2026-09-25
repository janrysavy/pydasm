#!/usr/bin/env python3
"""Check the decoder against the SingleStepTests hardware suites.

    python tools/check_sst.py <dir-of-json.gz> [--limit N] [--quiet]
    python tools/check_sst.py --make-corpus <dir> -o tests/data/sst_8088.json

The suites (`SingleStepTests/8088`, `SingleStepTests/8086`) are recordings of
real silicon: each test gives the bytes at CS:IP, the CPU state before, the state
after one instruction, and the instruction's own assembly text. They are the
strongest outside check available here, because the answers come from an AMD
D8088 and an Intel P80C86A rather than from another disassembler.

**What is checked, and what is not.** These are *execution* tests and pydasm is
a *disassembler*, so the comparison has to be drawn carefully. Three properties
are read out of each test:

1. **Instruction length**, for every instruction where the length is recoverable
   from the recorded IP. It is *not* recoverable for a control transfer, because
   IP then holds a target rather than the next instruction -- see below.
2. **Branch and jump targets.** For a relative transfer the recorded IP after
   the instruction is the target (if taken) or the next address (if not), and the
   decoder's computed target must be one of those two. This is the one property
   that checks the decoder's arithmetic on a displacement rather than just its
   width.
3. **Effective address.** Where the instruction wrote memory, the physical
   address the hardware wrote to is compared against the address the decoder
   computes from its ModRM byte, the segment override prefix, and the initial
   register file. This exercises the whole addressing mechanism: the mod/rm
   table, displacement widths, and which base register implies which segment.

The suite also records each test's assembly text in `name`. That is the *test
author's* rendering, not the decoder's, so it is parsed to classify the
instruction (does it transfer control, and how) rather than compared as text.

**Why control flow needs care.** A linear check of `IP_after - IP_before ==
length` is wrong for any instruction that transfers control, and it is wrong for
most of them in a way that looks like a decoder bug: `JO 001Fh` records an IP
delta of 0x1F, and `CALLF word [ds:bx+di]` records whatever the callee's offset
happened to be. Those instructions are classified and checked against their
target instead. Indirect transfers through memory (`FF /2`, `/3`, `/4`, `/5`),
returns and interrupts genuinely cannot be checked from the recorded state
without emulating, so they are counted as skipped rather than as passes.

Nothing here checks *semantics*: the decoder is not asked to predict the final
register file, because it does not execute.
"""
from __future__ import annotations

import argparse
import collections
import glob
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pydasm import DecoderOptions, decode_one  # noqa: E402
from pydasm.errors import DecodeError  # noqa: E402
from pydasm.ghidra import _segment_override  # noqa: E402

_SEGMENT_KEYS = {"ds": "ds", "ss": "ss", "es": "es", "cs": "cs"}

#: Mnemonics whose IP delta is a target, with the target computable from the
#: decoded displacement.
_RELATIVE = frozenset(
    {
        "JO", "JNO", "JB", "JNB", "JZ", "JNZ", "JBE", "JNBE",
        "JS", "JNS", "JP", "JNP", "JL", "JNL", "JLE", "JNLE",
        "JCXZ", "LOOP", "LOOPE", "LOOPNE", "JMP",
    }
)

#: Transfers whose destination is not derivable from the recorded state without
#: emulating the instruction: calls, returns, interrupts, and any jump whose
#: target is not a displacement.
_OPAQUE_TRANSFER = frozenset(
    {"CALL", "CALLF", "JMPF", "RET", "RETF", "IRET", "INT", "INT3", "INTO", "HLT"}
)

#: Instructions whose memory operand is a *source*: they read it and write
#: somewhere else (`PUSH` writes the stack), so the recorded write is not the
#: operand's address and the address check does not apply. Pure reads like `CMP`
#: need no entry here -- they write nothing, so there is no recorded write to
#: compare against.
_READS_OPERAND = frozenset({"PUSH"})

#: Instructions that raise an interrupt instead of advancing IP when their
#: operands are out of range: `DIV`/`IDIV` divide by zero or overflow the
#: quotient, and `AAM`/`AAD` divide by their own immediate. When the recorded IP
#: is not the next instruction, it belongs to the handler, and there is no
#: length to read out of it.
_MAY_FAULT = frozenset({"DIV", "IDIV", "AAM", "AAD"})


def effective_address(instruction, regs: dict, operand: int = 1) -> int | None:
    """The physical address a memory operand denotes, or None if not memory.

    `operand` selects which one: the destination is operand 1 for a store, but
    for `mov ax,[bp+8]` the memory reference is operand 2.
    """
    chosen = {1: instruction.operand1_type, 2: instruction.operand2_type}[operand]
    if chosen.kind != "addr16":
        return None
    operand = chosen
    mode = operand.value

    override = _segment_override(instruction)
    segment_register = override if override is not None else mode.base_register()
    segment = regs[_SEGMENT_KEYS[segment_register.name.lower()]]

    kind = mode.kind
    if kind.endswith("_d8"):
        kind = kind[:-3]
    elif kind.endswith("_d16"):
        kind = kind[:-4]

    offset = mode.displacement & 0xFFFF
    for part in kind.split("_"):
        if part in ("bx", "bp", "si", "di"):
            offset = (offset + regs[part]) & 0xFFFF
    return ((segment << 4) + offset) & 0xFFFFF


def classify(instruction) -> str:
    """How the instruction's IP delta has to be interpreted."""
    mnemonic = instruction.mnemonic.name

    # A near jump or call is opaque unless its target is a displacement: through
    # a register (`jmp sp`) or through memory, the destination is not in the
    # record. Checking `rel8`/`rel16` rather than `addr16` is what catches the
    # register form, which a memory-only test misses.
    if mnemonic in ("CALL", "JMP") and instruction.operand1_type.kind not in ("rel8", "rel16"):
        return "opaque"
    if mnemonic in _OPAQUE_TRANSFER:
        return "opaque"
    if mnemonic in _RELATIVE and instruction.operand1_type.kind in ("rel8", "rel16"):
        return "relative"
    if mnemonic in _MAY_FAULT:
        return "faults"
    return "linear"


def check(stream, stats: collections.Counter, failures: list, show: int) -> None:
    for test in stream:
        stats["tests"] += 1
        raw = bytes(test["bytes"])
        before = test["initial"]["regs"]
        after = test["final"]["regs"]

        try:
            instruction = decode_one(raw, DecoderOptions())
        except DecodeError:
            index = 0
            while index < len(raw) and raw[index] in (0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3):
                index += 1
            stats["undecodable"] += 1
            stats[f"undecodable op {raw[index]:02X}"] += 1
            continue
        stats["decoded"] += 1

        if "ip" not in after:
            # The hardware recorded no expectation for this form. The suite marks
            # these with an empty final state, so they are skipped, not passed.
            stats["no expectation recorded"] += 1
            continue

        delta = (after["ip"] - before["ip"]) & 0xFFFF
        mode = classify(instruction)

        if mode == "opaque":
            # No length or target is recoverable from IP alone.
            stats["skipped: opaque transfer"] += 1
        elif mode == "relative":
            # Compared as absolute addresses, not deltas: IP after a taken
            # branch is the target itself, so `after` must equal one of the two
            # addresses the branch could have gone to. Comparing the *delta*
            # against the target -- the obvious mistake -- is a type error that
            # reports every taken branch as a mismatch.
            taken = (before["ip"] + instruction.length + instruction.operand1_type.value) & 0xFFFF
            not_taken = (before["ip"] + instruction.length) & 0xFFFF
            if after["ip"] == taken:
                stats["relative target ok (taken)"] += 1
            elif after["ip"] == not_taken:
                stats["relative not taken, length ok"] += 1
            else:
                stats["TARGET MISMATCH"] += 1
                if len(failures) < show:
                    failures.append(
                        ("target", raw.hex(" "), instruction.mnemonic.name,
                         f"taken={taken:#06x} not_taken={not_taken:#06x}", f"after={after['ip']:#06x}")
                    )
        elif mode == "faults":
            # `DIV` and friends advance linearly only when they do not fault, and
            # the record does not say whether they did. A matching delta is still
            # evidence; a mismatching one is the handler's address and is not.
            if delta == instruction.length:
                stats["length ok"] += 1
            else:
                stats["skipped: instruction faulted"] += 1
        else:
            if delta == instruction.length:
                stats["length ok"] += 1
            else:
                stats["LENGTH MISMATCH"] += 1
                if len(failures) < show:
                    failures.append(
                        ("length", raw.hex(" "), instruction.mnemonic.name,
                         instruction.length, delta)
                    )
                continue

        # Effective address, where the instruction wrote its memory operand.
        if mode != "linear" or instruction.mnemonic.name in _READS_OPERAND:
            continue
        if instruction.operand1_type.kind != "addr16":
            continue
        writes = {address & 0xFFFFF for address, _ in test["final"]["ram"]}
        if not writes:
            continue
        stats["memory writes checked"] += 1
        physical = effective_address(instruction, before)

        # The suite records only the bytes that *changed*, and it records them
        # per byte. A 16-bit write whose low byte kept its value therefore shows
        # up as a single byte at `address + 1`, which is not a different address
        # -- it is the same write, half of it invisible. A near miss by one is
        # accepted for a word operand for that reason and no other; the narrow
        # tolerance is what keeps this from masking a genuine off-by-one, which
        # would move by 2 or by the operand's stride.
        width = 2 if instruction.operand1_type.size.name == "Operand16" else 1
        candidates = {physical}
        if width == 2:
            candidates.add((physical + 1) & 0xFFFFF)

        if candidates & writes:
            stats["address ok"] += 1
        else:
            stats["ADDRESS MISMATCH"] += 1
            if len(failures) < show:
                failures.append(
                    ("address", raw.hex(" "), instruction.mnemonic.name,
                     f"{physical:#07x}", " ".join(f"{w:#07x}" for w in sorted(writes)))
                )


def make_corpus(files: list[str], out: Path, per_file: int) -> None:
    """Freeze a compact subset of the suite so the tests need no download.

    The suites are ~900 MB of gzip and ~15 GB expanded, which is not something a
    test run should require. Each opcode file contributes an evenly spaced sample
    rather than its first N tests, so a form that only goes wrong at particular
    register values is still represented, and the `cycles` and `hash` fields are
    dropped because nothing here reads them.

    Sampling loses the repeat coverage -- a bug that shows up in one test in
    ten thousand will not be in the sample. The full run is what proves the
    decoder; this corpus is what keeps the proof runnable.
    """
    kept = []
    for path in files:
        with gzip.open(path) as handle:
            tests = json.load(handle)
        step = max(1, len(tests) // per_file)
        for test in tests[::step][:per_file]:
            kept.append(
                {
                    "name": test.get("name", ""),
                    "bytes": test["bytes"],
                    "initial": {"regs": test["initial"]["regs"], "ram": test["initial"]["ram"]},
                    "final": {"regs": test["final"]["regs"], "ram": test["final"]["ram"]},
                }
            )
    out.write_text(json.dumps(kept, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {out} ({len(kept)} tests, {out.stat().st_size / 1e6:.1f} MB)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path, nargs="?", help="directory of *.json.gz")
    parser.add_argument("--limit", type=int, default=None, help="per-file test limit")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--show", type=int, default=12, help="mismatches to print")
    parser.add_argument("--make-corpus", metavar="DIR", type=Path, default=None)
    parser.add_argument("--per-file", type=int, default=25, help="tests per file in a corpus")
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    if args.make_corpus is not None:
        files = sorted(glob.glob(str(args.make_corpus / "*.json.gz")))
        if not files:
            print(f"no *.json.gz under {args.make_corpus}", file=sys.stderr)
            return 2
        make_corpus(files, args.output or Path("tests/data/sst_corpus.json"), args.per_file)
        return 0

    if args.suite is None:
        parser.error("a suite directory is required (or use --make-corpus)")
    files = sorted(glob.glob(str(args.suite / "*.json.gz")))
    if not files:
        print(f"no *.json.gz under {args.suite}", file=sys.stderr)
        return 2

    stats: collections.Counter = collections.Counter()
    failures: list[tuple] = []
    for index, path in enumerate(files):
        with gzip.open(path) as handle:
            tests = json.load(handle)
        if args.limit is not None:
            tests = tests[: args.limit]
        check(tests, stats, failures, args.show)
        if not args.quiet and index % 40 == 0:
            print(f"  {index:3d}/{len(files)}  tests={stats['tests']:>10,}", flush=True)

    print()
    print(f"files                     : {len(files)}")
    print(f"tests                     : {stats['tests']:,}")
    print(f"  no expectation recorded : {stats['no expectation recorded']:,}")
    print(f"  undecodable             : {stats['undecodable']:,}")
    if stats["undecodable"]:
        gaps = {k[len("undecodable op "):]: v for k, v in stats.items() if k.startswith("undecodable op ")}
        print(f"    by opcode             : {dict(sorted(gaps.items()))}")
    print()
    print(f"length checked            : {stats['length ok'] + stats['LENGTH MISMATCH']:,}")
    print(f"  length ok               : {stats['length ok']:,}")
    print(f"  LENGTH MISMATCH         : {stats['LENGTH MISMATCH']:,}")
    print(f"relative checked          : {stats['relative target ok (taken)'] + stats['relative not taken, length ok'] + stats['TARGET MISMATCH']:,}")
    print(f"  target ok               : {stats['relative target ok (taken)'] + stats['relative not taken, length ok']:,}")
    print(f"  TARGET MISMATCH         : {stats['TARGET MISMATCH']:,}")
    print(f"skipped (opaque transfer) : {stats['skipped: opaque transfer']:,}")
    print(f"skipped (faulted)         : {stats['skipped: instruction faulted']:,}")
    print(f"memory writes checked     : {stats['memory writes checked']:,}")
    print(f"  address ok              : {stats['address ok']:,}")
    print(f"  ADDRESS MISMATCH        : {stats['ADDRESS MISMATCH']:,}")

    if failures:
        print("\nexamples:")
        for failure in failures:
            print(f"   {failure[0]:8s} bytes={failure[1]:22s} {failure[2]:8s} {failure[3]} != {failure[4]}")

    bad = stats["LENGTH MISMATCH"] + stats["TARGET MISMATCH"] + stats["ADDRESS MISMATCH"]
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
