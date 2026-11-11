#!/bin/bash
# make_sha256sums.sh — regenerate pack/SHA256SUMS over every file in the pack
# except SHA256SUMS itself and the clean-reproduction outputs
# (outputs/fresh-clone-*), which are generated after the digest is made and
# are verified instead by the comparison in outputs/fresh-clone-compare.txt.
# Usage: make_sha256sums.sh   (run from anywhere; operates on the pack root)
set -eu
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
find . -type f ! -name SHA256SUMS ! -path './outputs/fresh-clone-*' | sort | xargs sha256sum > SHA256SUMS
echo "SHA256SUMS: $(wc -l < SHA256SUMS) files"
