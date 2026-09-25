# tools

Generators and oracle capture. None of this is needed to *use* pydasm or to run
the test suite -- the golden corpora are committed -- but it is what makes the
port verifiable rather than merely plausible.

## Two kinds of script

**Generators** produce Python source from the reference Rust source. They exist
because the alternative is transcribing 352 decode-table rows by hand, and a
transcription error in an operand column produces instructions that decode to
something reasonable with their operands swapped. Nobody would notice until an
instruction came out backwards in a place that mattered.

| Script | Writes | From |
| --- | --- | --- |
| `gen_decode_table.py` | `src/pydasm/i808x/decode_table.py` | `marty_dasm/src/i808X/decode.rs` |
| `gen_mnemonics.py` | `src/pydasm/_mnemonics.py` | `marty_dasm/src/mnemonic.rs` |

```bash
python tools/gen_decode_table.py /path/to/marty_dasm/crates/marty_dasm/src/i808X/decode.rs
python tools/gen_mnemonics.py    /path/to/marty_dasm/crates/marty_dasm/src/mnemonic.rs
python tools/gen_segments.py     /path/to/project/segments.json -o corpus/segments.json
```

`gen_segments.py` is the same idea applied to the load layout rather than to the
instruction set. The address column of a listing is built from the segment
model -- a byte is its block's segment plus the offset inside it -- and
generating the map from the project's own `segments.json` keeps the port on the
model that produced the listings instead of on a second guess at it.

`tests/test_generated_tables_match_source.py` re-derives both tables with the
same parsers and compares every row, so a hand-edit to a generated file fails
the suite. It skips when no checkout is present; set `MARTY_DASM_SRC` to point
at one.

**Oracle capture** runs the real tool and records its output as the corpus the
tests assert against. One needs Java and Ghidra, the other a Rust toolchain.
Neither is needed to run the tests.

| Script | Writes | Needs |
| --- | --- | --- |
| `capture_ghidra_listing.sh` | `tests/data/listing.txt` | Java + a Ghidra install |
| `capture_nasm_oracle.sh` | `tests/data/nasm_{cases,expected}.txt` | Rust + a marty_dasm checkout |
| `gen_segments.py` | a segment-map JSON | a project's `segments.json` |
| `check_sst.py --make-corpus` | `tests/data/sst_{8088,8086}.json` | the SingleStepTests suites |

```bash
tools/capture_ghidra_listing.sh /path/to/ghidra_12.1.3_PUBLIC
tools/capture_nasm_oracle.sh    /path/to/marty_dasm
```

`capture_nasm_oracle.sh` writes a small `examples/nasm_dump.rs` driver into the
checkout -- that is the only modification it makes to it.

## Differential checks

These are what you run when a corpus test fails and you want to know *which*
lines diverged and how. Both exit non-zero on any difference.

```bash
python tools/compare_ghidra.py                 # 29,525 lines
python tools/compare_nasm.py                   # 23,418 cases
python tools/compare_ghidra.py <listing.txt> <target.EXE>

# The SingleStepTests hardware suites, in full.
python tools/check_sst.py /path/to/8088/v2     # 3,007,000 tests
python tools/check_sst.py /path/to/8086/v1     #   646,000 tests
```

`check_sst.py` is a checker rather than a capture: the SingleStepTests suites are
published and versioned, so there is nothing to freeze but a sample. It reads
three properties out of each recording -- instruction length, relative branch
target, and the physical address a memory write lands on -- and its module
docstring explains why control transfers, faulting instructions and indirect
jumps have to be classified before any of the three can be read off IP.

Running the suites, fetching them, and reading a failure are documented in
`docs/hardware-tests.md`.

Divergences are grouped by (reason, mnemonic) with one example each, so a single
root cause shows up as one entry with a count rather than as hundreds of lines.

## The corpora

`tests/data/` holds:

| File | What it is |
| --- | --- |
| `target.EXE` | the target, which both Ghidra-anchored checks are anchored to |
| `listing.txt` | 29,525 lines of Ghidra output over the relocated image |
| `nasm_cases.txt` | `IP HEXBYTES` lines covering every opcode |
| `nasm_expected.txt` | what the reference Rust crate printed for each |

The target is a third-party DOS binary, which is why it is not distributed.
It is committed here so the corpora are self-contained and the tests are
reproducible; it is not needed by the library itself.

## Why the corpora are wide

The Ghidra corpus is what one real pipeline actually decoded, which is a real
workload but a narrow one: 74 distinct mnemonics and 157 distinct leading
opcodes. It never exercises, for instance, `DAA`, `XLAT`, `INT`, `WAIT`, or the
80186 block.

The NASM corpus exists to cover that gap. It sweeps all 256 opcodes against a
spread of ModRM bytes and repeats each case at several instruction pointers,
including ones near the top of a segment where a relative branch overflows it.
That is where the two errors the corpus caught lived: a branch target rendered
as an unsigned 20-bit number instead of wrapping in 16 bits, and a forward
branch near a segment base rendered into the wrong segment.
