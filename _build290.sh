#!/usr/bin/env bash
# Build + targeted test gate for the #290 delivery-shape capture change.
# Writes everything to _build290.log on the NFS share so the result is
# readable directly from the Windows mount (no ssh polling).
set -o pipefail
export CARGO_TARGET_DIR=/mnt/FlareTraining/santh-archive/cargo-target
cd /media/mukund-thiru/SanthData/Santh/software/wafrift || { echo "STATUS=FAIL cd"; exit 1; }

echo "=== $(date -u) build290 start ==="

echo "=== BUILD wafrift-cli ==="
cargo build -j4 -p wafrift-cli 2>&1 | tail -n 40
B=${PIPESTATUS[0]}

echo "=== TEST wafrift-evolution + wafrift-grammar (lib) ==="
cargo test -j4 -p wafrift-evolution -p wafrift-grammar --lib 2>&1 | tail -n 50
T1=${PIPESTATUS[0]}

echo "=== TEST wafrift-cli (lib) ==="
cargo test -j4 -p wafrift-cli --lib 2>&1 | tail -n 60
T2=${PIPESTATUS[0]}

echo "=== COMPILE wafrift-cli integration tests (--no-run) ==="
cargo test -j4 -p wafrift-cli --no-run 2>&1 | tail -n 25
T3=${PIPESTATUS[0]}

echo "RESULT BUILD=$B TEST_EVO_GRAMMAR=$T1 TEST_CLI_LIB=$T2 COMPILE_INT=$T3"
if [ "$B" -eq 0 ] && [ "$T1" -eq 0 ] && [ "$T2" -eq 0 ] && [ "$T3" -eq 0 ]; then
  echo "STATUS=PASS"
else
  echo "STATUS=FAIL"
fi
echo "=== $(date -u) build290 done ==="
