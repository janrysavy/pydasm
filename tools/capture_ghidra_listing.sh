#!/usr/bin/env bash
# Capture a byte-anchored Ghidra listing for an image, to use as an oracle.
#
#   tools/capture_ghidra_listing.sh <ghidra-dir> <target.EXE> <exporter.java> [start end]
#
# <ghidra-dir> is an unpacked Ghidra release (the one containing
# support/analyzeHeadless). <exporter.java> is a GhidraScript that prints the
# listing in the format `pydasm.ghidra` renders; it is not distributed with this
# repository, because it belongs to whoever wrote it -- pass your own.
#
# The listing is written to stdout. Redirect it into your corpus directory:
#
#   tools/capture_ghidra_listing.sh ~/ghidra ./target.EXE ./export.java \
#       > corpus/listing.txt
#
# The exporter must emit one line per instruction in this shape, which is what
# `pydasm.ghidra` reproduces:
#
#   <seg>:<off> <mnemonic padded to 9><operands> ; bytes=<hex pairs> len=<n>
#
# It is invoked as `<exporter> image:<start> image:<end> 0`, where `image:0xN`
# names an offset into the load image.
set -euo pipefail

if [ $# -lt 3 ]; then
    sed -n '2,20p' "$0" >&2
    exit 2
fi

GHIDRA_DIR="$1"
TARGET="$2"
EXPORTER="$3"
START="${4:-0x0}"
END="${5:-}"

[ -f "$GHIDRA_DIR/support/analyzeHeadless" ] || {
    echo "no analyzeHeadless under $GHIDRA_DIR" >&2
    exit 2
}
[ -f "$TARGET" ] || { echo "no such target: $TARGET" >&2; exit 2; }
[ -f "$EXPORTER" ] || { echo "no such exporter: $EXPORTER" >&2; exit 2; }

# Default the end to the whole image. The load image excludes the MZ header, so
# the file size is an upper bound that will not truncate anything.
if [ -z "$END" ]; then
    END="$(stat -c%s "$TARGET" 2>/dev/null || stat -f%z "$TARGET")"
    END=$(printf '0x%x' "$END")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SCRIPT_DIR="$WORK/scripts"
PROJECT_DIR="$WORK/project"
STAGE="$WORK/stage"
mkdir -p "$SCRIPT_DIR" "$PROJECT_DIR" "$STAGE"
cp "$EXPORTER" "$SCRIPT_DIR/"
cp "$TARGET" "$STAGE/$(basename "$TARGET")"
NAME="$(basename "$TARGET")"
CLASS="$(basename "$EXPORTER" .java)"

# Import without analysis, then analyze and export. Two invocations, because the
# export needs the analysis to have found the code.
"$GHIDRA_DIR/support/analyzeHeadless" "$PROJECT_DIR" capture \
    -import "$STAGE/$NAME" -noanalysis < /dev/null > "$WORK/import.log" 2>&1

"$GHIDRA_DIR/support/analyzeHeadless" "$PROJECT_DIR" capture \
    -process "$NAME" -analysisTimeoutPerFile 300 -max-cpu 4 \
    -scriptPath "$SCRIPT_DIR" \
    -postScript "$CLASS.java" "image:$START" "image:$END" 0 \
    < /dev/null > "$WORK/export.log" 2>&1

# Strip the headless log prefix and the script tag; keep the listing lines.
sed -E "s/^INFO  ${CLASS}\\.java> //; s/ \\(GhidraScript\\) *$//" "$WORK/export.log" \
    | grep -E "^[0-9a-f]{4}:[0-9a-f]{4} "
