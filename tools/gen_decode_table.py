#!/usr/bin/env python3
"""Generate `pydasm/i808x/decode_table.py` from marty_dasm's Rust DECODE array.

The decode table is 352 hand-written rows. Transcribing it by hand invites the
kind of silent operand-swap that no test would notice until an instruction came
out with its operands the wrong way round, so it is parsed out of the reference
source instead. Re-run this when the upstream table changes:

    python tools/gen_decode_table.py <path-to>/marty_dasm/src/i808X/decode.rs
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# `inst!( ... )` rows. The operand templates never contain a comma, so a plain
# split on commas recovers the arguments exactly.
ROW_RE = re.compile(r"inst!\((.*?)\),\s*$")

OT_SIMPLE = {
    "NoOperand": "NONE",
    "ModRM8": "MODRM8",
    "ModRM16": "MODRM16",
    "Register8": "REG8",
    "Register16": "REG16",
    "SegmentRegister": "SREG",
    "Immediate8": "IMM8",
    "Immediate16": "IMM16",
    "Immediate8SignExtended": "IMM8SE",
    "Relative8": "REL8",
    "Relative16": "REL16",
    "Offset8": "OFF8",
    "Offset16": "OFF16",
    "FarAddress": "FAR",
}

FIXED_RE = re.compile(r"FixedRegister(8|16)\(Register(?:8|16)::(\w+)\)")


def operand(text: str) -> str:
    text = text.strip()
    if not text.startswith("Ot::"):
        raise ValueError(f"unrecognised operand template: {text!r}")
    body = text[4:]
    fixed = FIXED_RE.fullmatch(body)
    if fixed:
        width, name = fixed.group(1), fixed.group(2)
        return f"fixed{width}(Register{width}.{name})"
    if body not in OT_SIMPLE:
        raise ValueError(f"unrecognised operand template: {text!r}")
    return OT_SIMPLE[body]


def parse(source: str) -> list[tuple]:
    start = source.index("pub const DECODE")
    start = source.index("[", start)
    # The array literal ends at the first line that is exactly `];`.
    end = source.index("\n];", start)
    block = source[start:end]

    rows = []
    for line in block.splitlines():
        if "inst!(" not in line:
            continue
        match = ROW_RE.search(line)
        if match is None:
            raise ValueError(f"could not parse row: {line!r}")
        args = [a.strip() for a in match.group(1).split(",")]
        if len(args) == 8:
            op, grp, gdr, mc, xi, mnem, op1, op2 = args
        elif len(args) == 7:
            op, grp, gdr, mc, mnem, op1, op2 = args
            xi = None
        else:
            raise ValueError(f"row has {len(args)} args: {line!r}")
        rows.append(
            (
                int(op, 16),
                int(grp),
                int(gdr, 2),
                int(mc, 16),
                xi,
                mnem,
                operand(op1),
                operand(op2),
            )
        )
    return rows


HEADER = '''"""The i808X decode table, generated from marty_dasm by tools/gen_decode_table.py.

Do not edit by hand. Rows 0..255 are the base opcode table; rows 256.. are the
twelve opcode *groups*, which the decoder reaches by re-indexing on the ModRM
'reg' field:

    index = 256 + (base.grp - 1) * 8 + modrm.op_extension()

A row's `grp` field is only meaningful on the base rows -- the group rows are
reached positionally, and their own `grp` values are irrelevant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .._mnemonics import Mnemonic
from ..cpu_common import Register8, Register16
from .gdr import GdrEntry
from .operands import OperandTemplate as Ot, fixed16, fixed8


@dataclass(frozen=True)
class InstTemplate:
    opcode: int
    grp: int
    gdr: GdrEntry
    mc: int
    xi: Optional[str]
    mnemonic: Mnemonic
    operand1: Ot
    operand2: Ot

    @staticmethod
    def _template_name(operand: Ot) -> str:
        """The template's own name, whether it carries a register or not."""
        return getattr(operand, "template", operand).name

    @property
    def operand1_simple_name(self) -> str:
        return self._template_name(self.operand1)

    @property
    def operand2_simple_name(self) -> str:
        return self._template_name(self.operand2)


DECODE: tuple[InstTemplate, ...] = (
'''

FOOTER = ")\n\nassert len(DECODE) == 352, len(DECODE)\n"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1]).read_text(encoding="utf-8")
    rows = parse(src)

    base = rows[:256]
    groups = rows[256:]
    if len(base) != 256:
        raise SystemExit(f"expected 256 base rows, parsed {len(base)}")

    out = [HEADER]
    for op, grp, gdr, mc, xi, mnem, op1, op2 in rows:
        xi_lit = f'"{xi}"' if xi else "None"
        o1 = op1 if op1.startswith("fixed") else f"Ot.{op1}"
        o2 = op2 if op2.startswith("fixed") else f"Ot.{op2}"
        out.append(
            f"    InstTemplate(0x{op:02X}, {grp:2d}, GdrEntry(0x{gdr:04X}), 0x{mc:03X}, "
            f"{xi_lit:7s}, Mnemonic.{mnem}, {o1}, {o2}),\n"
        )
    out.append(FOOTER)

    dest = Path(__file__).resolve().parent.parent / "src" / "pydasm" / "i808x" / "decode_table.py"
    dest.write_text("".join(out), encoding="utf-8")
    print(f"wrote {dest} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
