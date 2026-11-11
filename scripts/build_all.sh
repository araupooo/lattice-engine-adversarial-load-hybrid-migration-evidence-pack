#!/bin/bash
# build_all.sh — build the pinned stack from pack/fixtures/:
#   liboqs 0.16.0 (optimized, OQS_OPT_TARGET=auto) and oqs-provider 0.12.0
#   against it, plus the liboqs ML-KEM-768 size/timing harness (src/bench_kem.c).
# Only ONE build is needed here (unlike the lattice-integration pack, which
# compared reference vs optimized builds): this assessment compares the
# hybrid group against the classical fallback on the same optimized build.
# Usage: build_all.sh [workdir]
# workdir defaults to <task>/work. Skips the build when the provider .so
# and the bench binary already exist (set FORCE_BUILD=1 to rebuild).
# Logs go to <workdir>/build-*.log.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
mkdir -p "$WORK"
# Absolutize WORK: this script cds into it and then still uses "$WORK/..."
# paths, so a relative WORK would double-nest (work/work). Absolute is safe.
WORK="$(cd "$WORK" && pwd)"
cd "$WORK"

if [ "${FORCE_BUILD:-0}" != "1" ] && [ -f "$WORK/oqs-opt-mod/oqsprovider.so" ] \
   && [ -f "$WORK/bench_kem" ]; then
  echo "build_all: provider .so and bench binary already present; skipping (FORCE_BUILD=1 to rebuild)"
  exit 0
fi

set -e
[ -d liboqs-0.16.0 ] || tar xzf "$PACK/fixtures/liboqs-0.16.0.tar.gz"
[ -d oqs-provider-0.12.0 ] || tar xzf "$PACK/fixtures/oqs-provider-0.12.0.tar.gz"

echo "=== liboqs optimized build (OQS_OPT_TARGET=auto) ==="
cmake -S liboqs-0.16.0 -B build-opt \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$WORK/install-opt" > build-opt-cmake.log 2>&1
cmake --build build-opt -j2 > build-opt-make.log 2>&1
cmake --install build-opt > build-opt-install.log 2>&1

echo "=== oqs-provider build (opt) ==="
rm -rf "oqsbuild-opt"
liboqs_DIR="$WORK/install-opt" cmake -S oqs-provider-0.12.0 -B "oqsbuild-opt" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$WORK/oqs-opt" > "build-oqs-opt-cmake.log" 2>&1
cmake --build "oqsbuild-opt" -j2 > "build-oqs-opt-make.log" 2>&1
# NOTE: cmake --install writes oqsprovider.so into the system OpenSSL
# modules directory, not the prefix. Use the .so straight from the build
# tree instead (same approach as the lattice-integration pack).
mkdir -p "$WORK/oqs-opt-mod"
cp "oqsbuild-opt/lib/oqsprovider.so" "$WORK/oqs-opt-mod/oqsprovider.so"
echo "=== oqs-provider (opt) ready: $WORK/oqs-opt-mod/oqsprovider.so ==="

echo "=== bench harness ==="
cc -O2 -I"$WORK/install-opt/include" "$PACK/src/bench_kem.c" \
  -L"$WORK/install-opt/lib" -loqs -lcrypto -o "$WORK/bench_kem"
echo "build_all: DONE"
sha256sum "$WORK/oqs-opt-mod/oqsprovider.so"
