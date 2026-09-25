# TPU9 procedure boundaries

`pydasm.tpu9` reads the code geometry of Turbo Pascal 6 units. It uses the
TPU9 entry and code-block tables, not a sweep over the whole code section.
It has no compiler, emulator, Ghidra, or third-party package dependency.

```python
from pathlib import Path
from pydasm.tpu9 import primary_routine, procedure_spans
from pydasm import Decoder, DecoderOptions

product = Path("PROBE.TPU").read_bytes()
file_offset, code = primary_routine(product)
decoder = Decoder(code, DecoderOptions())
```

A string literal can precede an entry in the same code block. For example,
`01 4C` is a one-character Pascal string, not the start of an ADD instruction.
A linear decoder started there can consume the next procedure's PUSH BP as
an operand and miss its real entry. Entry metadata supplies the correct seed.

The parser checks the symbol/code extents, table bounds and record alignment,
code-block size sum, block selectors, and block-relative entry offsets.
Duplicate aliases are accepted; the all-FFFF unassigned entry is ignored.
Invalid tables never enable a raw byte-search fallback.

`procedure_spans` returns absolute file-coordinate intervals bounded by the
owning block and the next distinct entry in that block. `primary_span` selects
the earliest local entry and requires PUSH BP / MOV BP,SP at that exact entry.
It will not substitute a later carrier if the primary entry has a bad prologue.
`primary_routine` decodes within that interval through its first complete
RET/RETF. It rejects a truncated instruction or missing return; a return in
another entry, block, symbol table, or trailer cannot complete the procedure.

This API is for controlled, single-epilogue BP-framed probes. It is not a full
TPU symbol/relocation reader, named-routine selector, arbitrary code finder,
or control-flow reconstruction for multi-return assembly. Those callers must
use their own authoritative entry/extent information and the normal decoder.

`tests/test_tpu9.py` contains synthetic positive and adversarial controls, so
these guarantees are testable without redistributing a vendor or game binary.
