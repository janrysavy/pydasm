# pydasm

A Python port of [marty_dasm](https://github.com/dbalsom/marty_dasm)'s 8088/8086
disassembler, with a **Ghidra-compatible output mode**.

The decoder is the port: same decode table, same prefix and ModRM handling, same
operand resolution. On top of it sit two renderers:

| Renderer | Purpose | Verified against |
| --- | --- | --- |
| `pydasm.ghidra` | a byte-anchored Ghidra listing format | 29,525 lines of real Ghidra output |
| `pydasm.nasm_formatter` | marty_dasm's own NASM style | 23,418 cases from the reference Rust crate |

It runs with no Java and no Ghidra, which is the point: the decode and the
formatting are deterministic functions of the image bytes and a caller-supplied
address. The one thing it does not do is *find* code -- see
[Coverage](#coverage-and-its-limit).

Both are exact, not approximate. See **Verification** below for what that means
and how to reproduce it.

## Install

No dependencies beyond the standard library. Python 3.11 or newer (the decoder
uses `match` and `X | Y` type syntax).

```bash
python -m pytest          # 208 tests, under three seconds
```

## Use

### Library

```python
from pydasm import Decoder, DecoderOptions, decode_one
from pydasm.ghidra import render_line
from pydasm.nasm_formatter import NasmFormatter, FormatOptions

instruction = decode_one(bytes([0x8B, 0xEC]))     # mov bp, sp
print(instruction.mnemonic.name)                   # MOV
print(instruction.operand1_type.value)             # Register16.BP
print(instruction.length)                          # 2

# Ghidra-style, at a linear address
print(render_line(instruction, 0x233A, 0x0513, 0x233A0513))
# 233a:0513 MOV      BP, SP ; bytes=89 E5 len=2

# marty_dasm NASM style
print(NasmFormatter().format_instruction(instruction, FormatOptions(ip=0x513)))
# mov bp,sp
```

Walking an image, with the position available after a partial failure:

```python
decoder = Decoder(image, DecoderOptions())
while True:
    try:
        instruction = decoder.decode_next()
    except Eof:
        break                    # clean end of input
    except UnexpectedEof:
        # an instruction was started and ran off the end; decoder.position
        # says how far it got
        break
    ...
```

### Command line

```bash
python -m pydasm GAME.EXE                 # Ghidra-style listing (MZ is relocated)
python -m pydasm GAME.EXE --nasm          # NASM style
python -m pydasm IMAGE.BIN --segment 0    # flat binary, no relocation
python -m pydasm GAME.EXE --start 0x5c --end 0x78

# Name a routine entry the sweep cannot reach on its own (repeatable).
python -m pydasm GAME.EXE --seed 0x065d --seed 0x0af3

# Read a routine's interface from its bytes, for a Pascal reconstruction.
python -m pydasm GAME.EXE --frame --seed 0x0f8ae --end 0x0f906
# ; Type:    far procedure; arguments popped by the callee (ret 10)
# ; Params:
# ;          [bp+0x06] far pointer
# ;          [bp+0x0a] far pointer
# ;          [bp+0x0e] word
# ; Globals: 0x6eee
```

### Reading a routine's interface

`pydasm.frame.analyse_frame(image, start, end)` derives the facts a routine
header records, from the bytes rather than by eye: the frame size, the argument
slots and their widths, the locals, the globals touched, and the call sites.

Two routines are pinned against headers written by hand and independently
decoded in the target project, and both reproduce exactly --
one a far procedure with a word and two far pointers, the other a near function
whose `[bp+0x04]` is a nested procedure's hidden static link: a slot the caller
supplies and the callee pops *without reading*, which a derivation built from
reads alone silently drops.

What it deliberately does not do is type the locals. The compiler interleaves
variables with the temporaries it spills, so a negative BP offset is readable
without being declarable. `locals` reports offsets and declines to name them --
the same line the target project draws when it calls a hole a stand-in rather
than a cell.

## What "Ghidra-compatible" means here

The requirement was byte-exact output against Ghidra's disassembler, as used by
a real reverse-engineering pipeline whose listings come from a byte-anchored
Ghidra exporter. That exporter's line format is:

```
<seg>:<off> <mnemonic padded to 9><operands> ; bytes=<hex pairs> len=<n>
```

Reproducing it needs more than the instruction text. Three things in particular
are easy to get subtly wrong, and all three are the kind that look right in a
spot check:

**The bytes are post-relocation.** Ghidra applies the MZ fixups before
disassembling, so a far pointer's segment field is the *loaded* one. `9A 41 04
57 10` in the file is listed as `CALLF 0x2000:09b1`, not `0x1057:0441`.
Disassembling the raw file gives plausible wrong answers. `pydasm.mz` implements
the relocation; the corpus test asserts every listed byte string against the
relocated image, independently of any decoding.

**Far pointers are linear, then re-split; the address column is per block.**
These are two different things and both look like `ssss:oooo`. A far *operand*
renders as `0x2000:09b1` because that and the encoded `0x2057:0441` spell linear
0x209B1 -- Ghidra prints the normalised pair. Relative branches are different
again: they are intra-segment, so they wrap within 64K and keep their segment.

The address *column*, meanwhile, is a property of the load layout: the segments
are paragraph-aligned blocks and a byte is its block's segment plus the offset
inside it. A byte at file offset `0x0F840` is `1f84:0000` in a listing, not the
linear re-split `1000:f840`. Getting this wrong is invisible in the first block,
which is why the map is supplied rather than computed arithmetically. See
`pydasm/segments.py` and `--segments`.

**Memory operand sizes are shown only when they are not already implied.**
`MOV word ptr [BP + -0x4], AX` needs the `word`; `MOV [0x65be], AX` does not,
because the accumulator opcode already fixes the width.

Smaller rules the corpus pinned down: the mnemonic field is nine columns and its
trailing spaces are kept; `XCHG AX, r16` prints accumulator-first; the shift
group prints its implied count; `83 /7` (CMP) prints a signed immediate while
`83 /6` (XOR) prints it zero-extended, which comes from Ghidra's own SLEIGH spec;
string operations print their implicit `ES:DI`/`SI` operands and spell the REP
family as a mnemonic suffix (`MOVSB.REP`).

## Verification

Both renderers are checked against captured output from the real tools, not
against a reading of their documentation.

| Check | Cases | Result |
| --- | --- | --- |
| **AMD D8088 hardware recordings** | **2,411,530 lengths + 379,245 targets + 590,109 addresses** | **0 mismatches** |
| **Intel P80C86A hardware recordings** | **527,128 lengths + 75,845 targets + 167,887 addresses** | **0 mismatches** |
| Ghidra listing, whole lines | 29,525 | exact |
| NASM style, against the Rust crate | 23,418 | exact |
| Decode table vs. the Rust source | 352 rows | exact |
| Mnemonic enum vs. the Rust source | 209 variants | exact |

The first two rows are the strongest evidence available here, because they are
not comparisons against another program. Ghidra and marty_dasm could share a
misreading of the 8086 and every other row would still pass; the
[SingleStepTests](https://github.com/SingleStepTests) suites answer to the
silicon — an AMD D8088 (8441DMA) and an Intel P80C86A-2, recorded by the same
author as marty_dasm.

What they check, and what they cannot:

| Property | How it is read from the recording | Result |
| --- | --- | --- |
| Instruction length | the IP advance, for instructions that do not transfer control | 0 mismatches |
| Branch / jump target | the IP after, against the target the decoder computes | 0 mismatches |
| Effective address | the address the hardware wrote, against the decoder's ModRM + override + registers | 0 mismatches |

They do **not** check mnemonics — `pydasm.ghidra` and `pydasm.nasm_formatter`
both pass, and the recording has no opinion on which is right. And they cannot
check semantics: pydasm does not execute, so the final register file is never
predicted. Roughly 9% of tests are skipped for that reason (indirect calls,
returns, interrupts and faulting instructions, where the recorded IP is a
handler or a callee rather than the next instruction) — counted as skips, never
as passes.

The hardware corpora are sampled and committed, so `pytest` needs no download.
To run the suites in full, see **[docs/hardware-tests.md](docs/hardware-tests.md)**
— it covers fetching them, the four traps that make a correct decoder look
broken, how to read a failure, and the runtime and disk cost:

```bash
python tools/check_sst.py /path/to/8088/v2
python tools/check_sst.py /path/to/8086/v1
```

`pytest` runs without Java or Rust. The Ghidra corpus is not distributed — see
`NOTICE` — so the tests that use it skip unless you supply one; everything else,
including the hardware recordings, always runs:

```bash
python -m pytest -q                        # 177 pass, 34 skip
PYDASM_CORPUS=/path/to/corpus python -m pytest -q   # 211 pass
```

The Ghidra corpus is a set of instruction addresses plus expected text rather
than a linear sweep, because Ghidra decodes where its analysis found code and
leaves the rest undefined. A sweep would decode data as instructions and
disagree with the listing for reasons that say nothing about the renderer.

To regenerate either corpus, see [`tools/README.md`](tools/README.md).

## Coverage and its limit

The port decodes bytes it is given. It does not locate code: that is the analysis
layer, and it is deliberately not ported.

Measured against the target, decoding the whole image and comparing to the
captured Ghidra listing:

| | Instructions reached | Byte-identical |
| --- | --- | --- |
| Linear sweep | 29,441 / 29,525 (99.72%) | 29,441 |
| Sweep + `--seed` at the 84 entries | **29,525 / 29,525** | **29,525, 0 mismatches** |

The 84 a sweep misses are routine prologues whose first byte no instruction
boundary leads into, because the bytes before them are data or padding. Naming
the entry is enough -- they render identically. Entries come from things the
project already has offline: the MZ relocation table (which alone yields 113
far-call targets), the unit map, or any decoded routine header.

So: **the decode and the output format need nothing but Python; the list of
entry points has to come from somewhere else.** For this target the relocation
table and the existing unit listings supply it.

## The gated corpus

Four test files need a third-party DOS binary and a Ghidra listing taken over it:

| File | Needs the corpus |
| --- | --- |
| `test_ghidra_corpus.py` | all of it |
| `test_mz.py` | the MZ relocation tests |
| `test_frame.py` | the routine-frame readings |
| `test_cli.py`, `test_segments.py` | the tests driven by a real listing |

**Neither file is distributed.** A byte-anchored Ghidra listing carries the bytes
it decoded — the one this was developed against reproduced 86% of its load
image, including the program's text — so shipping the listing would republish
the binary. See **[NOTICE](NOTICE)**.

Those tests skip cleanly without it. To run them, supply a directory:

| File | What it is |
| --- | --- |
| `target.EXE` | the image |
| `listing.txt` | a listing for it, in the format in `docs/hardware-tests.md` |
| `segments.json` | its load layout, from `tools/gen_segments.py` |

```bash
PYDASM_CORPUS=/path/to/corpus python -m pytest -q
```

## Scope

Ported: the **Intel 8088/8086** family only (`CpuType.Intel808x`). The other CPU
types in the reference crate raise a clear error rather than guessing.

Two deliberate departures from a literal transliteration, both documented at
their call sites:

* **Prefix flags are not stored.** marty_dasm's 8086 decoder tracks
  `raw_prefix_flags`, `effective_prefix_flags` and `segment_override` in locals
  and never assigns them to the instruction -- only its 386 decoder does. The
  port mirrors that, so the NASM formatter drops prefixes exactly as the
  reference does. The Ghidra renderer derives what it needs from
  `prefix_bytes`, which is populated.

* **`AddressOffset16` is a tagged record, not an enum.** In Rust it is an enum
  whose variants carry data; Python enums cannot, so it is a small frozen
  dataclass with the same field names.

## Layout

```
src/pydasm/
  byte_reader.py       fixed-width little-endian reads over a cursor
  cpu_common.py        registers, sizes, operand types, addressing modes
  errors.py            DecodeError / Eof / UnexpectedEof
  decoder.py           the streaming Decoder
  instruction.py       the decoded-instruction record
  mz.py                MZ loading and relocation
  ghidra.py            the Ghidra-compatible renderer
  nasm_formatter.py    marty_dasm's own NASM renderer
  cli.py               python -m pydasm
  mnemonic.py          mnemonic behaviour (predicates, overrides)
  _mnemonics.py        GENERATED: mnemonic enum + display strings
  i808x/
    decode.py          the 8088/8086 decoder
    decode_table.py    GENERATED: the 352-row decode table
    modrm16.py         the 16-bit ModRM byte
    operands.py        operand templates and resolution
    gdr.py             the Group Decode ROM
tools/                 table generators, oracle capture, differential checks
tests/data/            the committed golden corpora
```

Generated files carry a header saying so and are covered by
`tests/test_generated_tables_match_source.py`, which re-derives them from the
reference source when a marty_dasm checkout is available.

## Licence

The ported code derives from marty_dasm, which is MIT licensed
(Copyright 2022-2025 Daniel Balsom). See `LICENSE`.
