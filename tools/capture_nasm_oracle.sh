#!/usr/bin/env bash
# Regenerate tests/data/nasm_expected.txt from the marty_dasm crate itself.
#
# The NASM corpus is checked against the reference Rust implementation rather
# than against a reading of its source, so the oracle has to be built and run.
# This needs a Rust toolchain and a marty_dasm checkout; the tests do not.
#
#   tools/capture_nasm_oracle.sh <marty_dasm-checkout>
set -euo pipefail

CHECKOUT="${1:?usage: capture_nasm_oracle.sh <marty_dasm-checkout>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

# The driver is kept here and copied in, so the checkout stays pristine.
cat > "$CHECKOUT/crates/marty_dasm/examples/nasm_dump.rs" <<'RUST'
// Print marty_dasm's own NASM formatting for `IP HEXBYTES` lines on stdin.
// Used as the oracle for the Python port's NASM formatter.
use marty_dasm::prelude::*;
use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let line = line.trim();
        if line.is_empty() { continue; }
        let mut parts = line.splitn(2, ' ');
        let ip_text = parts.next().unwrap();
        let hex = parts.next().unwrap_or("");
        let ip = u32::from_str_radix(ip_text, 16).unwrap();
        let bytes: Vec<u8> = hex.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        let opts = DecoderOptions { cpu: CpuType::Intel808x, segment_size: SegmentSize::Segment16 };
        let mut dec = Decoder::new(std::io::Cursor::new(bytes.clone()), opts);
        match dec.decode_next() {
            Ok(inst) => {
                let fopts = FormatOptions { ip, ..Default::default() };
                let mut out = String::new();
                NasmFormatter.format_instruction(&inst, &fopts, &mut out);
                println!("{}\t{}", inst.instruction_bytes.len(), out);
            }
            Err(e) => println!("ERR\t{}", e),
        }
    }
}
RUST

cd "$CHECKOUT"
cargo build --example nasm_dump -p marty_dasm

BIN="$CHECKOUT/target/debug/examples/nasm_dump"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"

python "$ROOT/tools/gen_nasm_corpus.py" > "$ROOT/tests/data/nasm_cases.txt"
"$BIN" < "$ROOT/tests/data/nasm_cases.txt" > "$ROOT/tests/data/nasm_expected.txt"

echo "wrote $ROOT/tests/data/nasm_cases.txt ($(wc -l < "$ROOT/tests/data/nasm_cases.txt") cases)"
echo "wrote $ROOT/tests/data/nasm_expected.txt"
