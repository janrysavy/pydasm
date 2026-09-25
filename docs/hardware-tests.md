# Running the SingleStepTests hardware suites

How to check the decoder against real 8088 and 8086 silicon, from a clean
machine, in about ten minutes of setup and two minutes per suite thereafter.

This is the strongest evidence the project has. Every other check here compares
the decoder to *another program* — marty_dasm, Ghidra — and two programs can
share a misreading of the 8086. These answer to the part.

## What the suites are

[SingleStepTests/8088](https://github.com/SingleStepTests/8088) and
[SingleStepTests/8086](https://github.com/SingleStepTests/8086) are recordings of
real CPUs, made with Arduino8088 / ArduinoX86 and MartyPC by Daniel Balsom — the
same author as marty_dasm. Each test is one instruction:

| Field | Meaning |
| --- | --- |
| `name` | the test author's assembly text, e.g. `"add word [es:di], dx"` |
| `bytes` | the instruction's bytes, at CS:IP |
| `initial` | registers, RAM and prefetch queue before |
| `final` | what changed after |
| `cycles` | per-cycle bus state |
| `hash`, `idx` | identity |

The versions used here:

| Suite | Path | CPU | Files | Tests | Size |
| --- | --- | --- | --- | --- | --- |
| 8088 | `v2` | AMD D8088 (8441DMA), 1982 | 323 | 3,007,000 | 727 MB |
| 8086 | `v1` | Intel P80C86A-2 | 323 | 646,000 | 174 MB |

The 8086 suite is uniform: 323 files of 2,000. The 8088 suite is not, because a
few instruction families ship fewer cases to keep the archive manageable:

| Files | Tests each | Which |
| --- | --- | --- |
| 290 | 10,000 | everything else |
| 16 | 5,000 | shift/rotate by CL (`D2`, `D3` × 8 extensions) |
| 10 | 2,000 | string instructions (`A4`–`A7`, `AA`–`AF`) |
| 7 | 1,000 | flag instructions (`F5`, `F8`–`FD`) |

The 8088 suite is the primary one; the 8086 suite is supplementary and covers bus
and prefetch behaviour specifically. Both are needed for the claim this project
makes, because they are different parts.

## What the check proves, and what it cannot

This is the part worth reading before trusting a green run. These are
*execution* tests; pydasm is a *disassembler*. Three properties are read out of
each recording:

| # | Property | How it is read | Strength |
| --- | --- | --- | --- |
| 1 | **Instruction length** | the IP advance, for instructions that do not transfer control | a decoder one byte out fails; a wrong length corrupts everything after it |
| 2 | **Branch / jump target** | the IP after, against the target computed from the displacement | checks the decoder's *arithmetic* on a displacement, not just its width |
| 3 | **Effective address** | the physical address the hardware wrote, against the decoder's ModRM + segment override + initial registers | exercises the mod/rm table, displacement widths, and which base register implies which segment |

**Not proved: mnemonics.** The recordings contain no mnemonic. `pydasm.ghidra`
prints `MOV      DX, DS` for `8E DA` and the NASM formatter prints `mov dx,ds`;
the hardware has no opinion about which is right. Mnemonic spelling is pinned by
the Ghidra and NASM corpora instead — see the main README.

**Not proved: semantics.** pydasm does not execute, so the final register file is
never predicted. 215,464 of the 3,007,000 8088 tests (7.2%) are skipped for
exactly this reason -- 189,996 opaque transfers and 25,468 faulting
instructions. They are counted as skips, never as passes.

## The four traps

Every one of these produced a confident *false* report of a decoder bug during
development. They are the reason this document exists.

### 1. `IP_after − IP_before` is not the length for a control transfer

It is the length only for instructions that fall through. For a relative branch
it is the *target* when taken — `JO 001Fh` records a delta of `0x1F`. An
instruction must be classified before its IP delta can be read:

| Class | Instructions | How to read the delta |
| --- | --- | --- |
| `linear` | everything not below | delta == length |
| `relative` | `Jcc`, `LOOP*`, `JCXZ`, `JMP rel*` | compare `after.ip` against the taken **and** not-taken addresses |
| `opaque` | `CALL`, `CALLF`, `RET*`, `INT*`, `INTO`, `HLT`, and any `JMP` whose operand is not a displacement | nothing follows — skip |
| `faults` | `DIV`, `IDIV`, `AAM`, `AAD` | on a fault IP goes to the handler; a mismatch is not evidence |

`opaque` includes `FF /4` `jmp sp` — an indirect jump through a *register*, not
only through memory. Classifying on `operand.kind != "addr16"` catches both;
classifying on memory alone misses the register form.

### 2. Compare addresses, not deltas

The target check must compare `after.ip` against an absolute address. Comparing
the *delta* against the target is a type error that reports every taken branch
as a failure — 198,278 of them, in the first run of this checker.

### 3. `final.ram` records only the bytes that changed, per byte

A 16-bit write whose low byte kept its value appears as a single byte at
`address + 1`. That is not a different address; it is the same write with half of
it invisible. Accept `address + 1` as a match **only** for a word operand, and
keep the tolerance that narrow — a genuine off-by-one moves by 2 or by the
operand's stride, not by 1.

### 4. `PUSH` reads its memory operand and writes the stack

The recorded write is at the stack pointer, not the operand's address, so the
address check does not apply. Instructions whose memory operand is a *source*
are excluded. Pure reads such as `CMP` need no entry: they write nothing, so
there is no recorded write to compare against.

### Also: an empty `final.regs` is not a pass

The suite marks forms whose behaviour is undefined on the part with an empty
final state — 761 of the 3,007,000 8088 tests, 156 of the 8086 ones. Count them
as skipped.

## Running it

### Get the suites

They are large and are not vendored into this repository. Either clone:

```bash
git clone --depth 1 https://github.com/SingleStepTests/8088
git clone --depth 1 https://github.com/SingleStepTests/8086
```

Or fetch only the JSON, which is much smaller than a clone:

```bash
gh api "repos/SingleStepTests/8088/contents/v2" --jq '.[].name' > files.txt
mkdir -p v2
while read -r f; do
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/SingleStepTests/8088/contents/v2/$f" > "v2/$f"
done < files.txt
```

Two things to know about that loop:

- **`-H "Accept: application/vnd.github.raw"` is required.** The plain contents
  API returns an empty `content` for files over 1 MB, which silently produces
  zero-byte downloads. That failure looks like a parsing error later, not like a
  download error.
- **`files.txt` has 324 entries but only 323 are tests.** The extra is
  `metadata.json`, which `check_sst.py` ignores.

The loop is serial and takes a few minutes. `xargs -P 8` parallelises it:

```bash
printf '%s\n' "$(cat files.txt)" | xargs -P 8 -I{} sh -c \
  'gh api -H "Accept: application/vnd.github.raw" \
     "repos/SingleStepTests/8088/contents/v2/{}" > "v2/{}"'
```

For the 8086 suite, substitute `8086` for the repo and `v1` for the directory.

### Run the check

```bash
python tools/check_sst.py /path/to/8088/v2
python tools/check_sst.py /path/to/8086/v1
```

The exit status is non-zero if any length, target or address mismatched, so it
drops straight into CI.

| Flag | Effect |
| --- | --- |
| `--quiet` | suppress the per-40-file progress line |
| `--limit N` | only the first N tests of each file — for a quick smoke run |
| `--show N` | how many mismatch examples to print (default 12) |

Expected output, and the numbers to compare a new run against. The 8088 suite:

```
files                     : 323
tests                     : 3,007,000
  no expectation recorded : 761
  undecodable             : 0

length checked            : 2,411,530
  length ok               : 2,411,530
  LENGTH MISMATCH         : 0
relative checked          : 379,245
  target ok               : 379,245
  TARGET MISMATCH         : 0
skipped (opaque transfer) : 189,996
skipped (faulted)         : 25,468
memory writes checked     : 590,109
  address ok              : 590,109
  ADDRESS MISMATCH        : 0
```

And the 8086 suite:

```
files                     : 323
tests                     : 646,000
  no expectation recorded : 156
  undecodable             : 0

length checked            : 527,128
  length ok               : 527,128
  LENGTH MISMATCH         : 0
relative checked          : 75,845
  target ok               : 75,845
  TARGET MISMATCH         : 0
skipped (opaque transfer) : 37,999
skipped (faulted)         : 4,872
memory writes checked     : 167,887
  address ok              : 167,887
  ADDRESS MISMATCH        : 0
```

**`undecodable: 0` is a claim, not a formality.** Every opcode the suite
provides decodes. If a run reports undecodable tests, the checker prints how many
per opcode byte, which is what identifies a gap in the decode table.

### Run the regression tests

The repository carries evenly spaced samples of both suites, so the ordinary
test run needs no download:

```bash
python -m pytest tests/test_singlestep.py -q
```

To regenerate the samples after re-downloading:

```bash
python tools/check_sst.py --make-corpus /path/to/8088/v2 --per-file 12 -o tests/data/sst_8088.json
python tools/check_sst.py --make-corpus /path/to/8086/v1 --per-file 12 -o tests/data/sst_8086.json
```

Sampling trades coverage for a runnable proof: an evenly spaced sample will miss
a bug that appears in one test in ten thousand. **The full run is what proves the
decoder; the corpus is what keeps the proof runnable.** Re-run the full suites
after any change to the decoder, the ModRM table, or the operand resolver.

## Reading a failure

The examples block names the bytes, the mnemonic, what the checker computed and
what the hardware recorded:

```
examples:
   address  bytes=26 01 15    ADD      0x0fa79 != 0x0fa7a
   target   bytes=75 08       JNZ      taken=0x233c2 not_taken=0x233ba != after=0x233c2
   length   bytes=8B 46 08    MOV      3 != 4
```

Before concluding the decoder is wrong, check the failure against the four traps
above in order — three of the four produce a signal that looks exactly like a
decoder bug:

1. Is the mnemonic a control transfer? Then a length mismatch is expected and
   the classifier should have caught it.
2. Is the address off by exactly one for a word operand? Then the low byte was
   unchanged and the write is correct.
3. Is the mnemonic `PUSH`? Then the recorded write is the stack.
4. Is the mnemonic `DIV`, `IDIV`, `AAM` or `AAD`? Then it may have faulted.

Only after those four does a mismatch mean the decoder. To tell a real failure
from a reporting artefact, find the test in the suite by its `hash` and read the
`cycles` array: the bus states show which address was written and when.

## Cost

| | Time | Space |
| --- | --- | --- |
| 8088 suite | ~1.8 min | 727 MB |
| 8086 suite | ~36 s | 174 MB |
| Both, per full run | ~2.5 min | — |
| `pytest tests/test_singlestep.py` | 0.2 s | 3.2 MB (committed) |
| `pytest tests/` (all of it) | 0.5 s | + 3.2 MB |

Parsing the JSON dominates the runtime, not decoding: roughly 0.16 s to parse
10,000 tests against 0.06 s to check them. PyPy is not installed in the
environment this was developed in, and would not help much for that reason —
gzip and JSON parsing are not where the wins are. If a full run in CI ever
becomes too slow, converting the JSON to a packed binary format is the lever, not
a faster interpreter.

## Keeping this honest

If a run reports zero mismatches, confirm it actually ran:

- `tests` should be **3,007,000** for the 8088 suite and **646,000** for the
  8086. These are exact, not approximate: a run that read fewer files will show
  a smaller number.
- `length ok` should be 2,411,530 (8088) or 527,128 (8086).
- `undecodable` should be 0.

A checker that silently skipped everything would print three zeros and a small
`tests` count. That is why `tests/test_singlestep.py` asserts floors on
`length ok`, `address ok` and the number of opcode bytes covered — a corpus that
collapsed to one opcode would pass the mismatch assertions vacuously, and the
floors are what stop it.
