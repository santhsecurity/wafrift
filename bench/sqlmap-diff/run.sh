#!/usr/bin/env bash
# bench/sqlmap-diff/run.sh
#
# Compare wafrift vs sqlmap --tamper=all against ModSecurity CRS PL=4.
# Produces four lists: wafrift_only / sqlmap_only / both / neither.
#
# Prerequisites:
#   - Docker + docker compose
#   - wafrift binary (cargo build --release -p wafrift-cli)
#   - sqlmap in PATH (or Docker; see SQLMAP_DOCKER below)
#
# Usage:
#   bench/sqlmap-diff/run.sh [--sqlmap-docker]
#
# The --sqlmap-docker flag uses the official sqlmapproject/sqlmap image
# instead of a locally-installed sqlmap.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${REPO_ROOT}/bench/sqlmap-diff/results"
WAFRIFT_BIN="${REPO_ROOT}/target/release/wafrift"
CORPUS_DIR="${REPO_ROOT}/wafrift-bench/corpus"
COMPOSE_FILE="${REPO_ROOT}/wafrift-bench/targets/modsec-pl4/docker-compose.yml"
WAF_URL="http://127.0.0.1:18084"
DATE="$(date -u +%Y%m%d-%H%M%S)"

SQLMAP_DOCKER=0
for arg in "$@"; do
    [ "$arg" = "--sqlmap-docker" ] && SQLMAP_DOCKER=1
done

mkdir -p "${RESULTS_DIR}"

echo "[1/5] Checking prerequisites..."
if [ ! -f "${WAFRIFT_BIN}" ]; then
    echo "  Building wafrift..."
    cargo build --release -p wafrift-cli --manifest-path "${REPO_ROOT}/Cargo.toml"
fi

if [ "${SQLMAP_DOCKER}" -eq 1 ]; then
    SQLMAP_CMD="docker run --rm --network host -v /tmp/sqlmap-out:/tmp/sqlmap-out sqlmapproject/sqlmap"
elif command -v sqlmap &>/dev/null; then
    SQLMAP_CMD="sqlmap"
else
    echo "ERROR: sqlmap not found. Install sqlmap or pass --sqlmap-docker."
    echo "  Install: pip install sqlmap"
    echo "  Docker:  $0 --sqlmap-docker"
    exit 1
fi

echo "[2/5] Bringing up ModSecurity CRS PL=4..."
docker compose -f "${COMPOSE_FILE}" up -d
echo "  Waiting for WAF to be ready..."
for i in $(seq 1 30); do
    if curl -sf "${WAF_URL}/" -o /dev/null 2>/dev/null; then
        break
    fi
    sleep 2
done

echo "[3/5] Running wafrift bench (SQL corpus, heavy+equiv-cegis)..."
WAFRIFT_OUT="${RESULTS_DIR}/${DATE}-wafrift-pl4-sql.json"
"${WAFRIFT_BIN}" bench-waf \
    --base-url "${WAF_URL}" \
    --corpus "${CORPUS_DIR}" \
    --class sql \
    --evade \
    --strategies heavy,equiv-cegis \
    --format json \
    --output "${WAFRIFT_OUT}"
echo "  wafrift output: ${WAFRIFT_OUT}"

echo "[4/5] Running sqlmap --tamper=all against SQL corpus..."
SQLMAP_RESULTS_DIR="${RESULTS_DIR}/${DATE}-sqlmap"
mkdir -p "${SQLMAP_RESULTS_DIR}"

# Extract payloads from wafrift corpus TOML files.
# Each payload is tested against the WAF via sqlmap using --tamper=all.
PAYLOAD_LIST="${SQLMAP_RESULTS_DIR}/payloads.txt"
python3 - << 'PYEOF'
import glob, sys, os

corpus_dir = os.environ.get("CORPUS_DIR", "wafrift-bench/corpus/sql")
results_dir = os.environ.get("SQLMAP_RESULTS_DIR", "/tmp/sqlmap-results")
payload_file = os.path.join(results_dir, "payloads.txt")

try:
    import tomllib
except ImportError:
    import tomli as tomllib

cases = []
for toml_file in sorted(glob.glob(os.path.join(corpus_dir, "**/*.toml"), recursive=True)):
    try:
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)
        for case in data.get("case", []):
            cid = case.get("id", "")
            payload = case.get("payload", "")
            if cid and payload:
                cases.append((cid, payload))
    except Exception as e:
        pass

with open(payload_file, "w") as f:
    for cid, payload in cases:
        f.write(f"{cid}\t{payload}\n")

print(f"Extracted {len(cases)} SQL corpus cases to {payload_file}")
PYEOF

SQLMAP_BYPASS="${SQLMAP_RESULTS_DIR}/sqlmap_bypassed.txt"
touch "${SQLMAP_BYPASS}"

# For each payload, run sqlmap and check if any tamper bypasses the WAF.
PAYLOAD_LIST="${SQLMAP_RESULTS_DIR}/payloads.txt"
CORPUS_DIR="${CORPUS_DIR}" SQLMAP_RESULTS_DIR="${SQLMAP_RESULTS_DIR}" python3 - << 'PYEOF'
import subprocess, os, urllib.parse, sys

payload_file = os.path.join(os.environ["SQLMAP_RESULTS_DIR"], "payloads.txt")
bypass_file = os.path.join(os.environ["SQLMAP_RESULTS_DIR"], "sqlmap_bypassed.txt")
waf_url = "http://127.0.0.1:18084"
sqlmap_out = "/tmp/sqlmap-out"
os.makedirs(sqlmap_out, exist_ok=True)

sqlmap_docker = os.environ.get("SQLMAP_DOCKER", "0") == "1"
if sqlmap_docker:
    base_cmd = ["docker", "run", "--rm", "--network", "host",
                f"-v{sqlmap_out}:{sqlmap_out}", "sqlmapproject/sqlmap"]
else:
    base_cmd = ["sqlmap"]

bypassed = []
with open(payload_file) as f:
    lines = [l.rstrip("\n") for l in f if l.strip()]

for i, line in enumerate(lines):
    parts = line.split("\t", 1)
    if len(parts) != 2:
        continue
    cid, payload = parts
    encoded = urllib.parse.quote(payload, safe="")
    url = f"{waf_url}/get?q={encoded}"
    cmd = base_cmd + [
        "--url", url,
        "--param-filter=q",
        "--tamper=all",
        "--batch",
        "--technique=B",
        "--dbms=mysql",
        "--level=1",
        "--risk=1",
        f"--output-dir={sqlmap_out}/{cid}",
        "--disable-coloring",
        "--quiet",
    ]
    print(f"  [{i+1}/{len(lines)}] {cid}: ", end="", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        # sqlmap exits 0 and prints "parameter 'q' appears to be injectable"
        if "appears to be injectable" in result.stdout or "appears to be vulnerable" in result.stdout:
            bypassed.append(cid)
            print("BYPASS")
        else:
            print("blocked")
    except subprocess.TimeoutExpired:
        print("timeout")
    except Exception as e:
        print(f"error: {e}")

with open(bypass_file, "w") as f:
    for cid in bypassed:
        f.write(cid + "\n")
print(f"\nsqlmap bypassed: {len(bypassed)} / {len(lines)}")
PYEOF

echo "[5/5] Computing diff..."
DIFF_OUT="${RESULTS_DIR}/${DATE}-diff"
mkdir -p "${DIFF_OUT}"

SQLMAP_BYPASS="${SQLMAP_RESULTS_DIR}/sqlmap_bypassed.txt"
WAFRIFT_OUT="${WAFRIFT_OUT}" \
SQLMAP_BYPASS="${SQLMAP_BYPASS}" \
DIFF_OUT="${DIFF_OUT}" \
python3 - << 'PYEOF'
import json, os

wafrift_json = os.environ["WAFRIFT_OUT"]
sqlmap_bypass_file = os.environ["SQLMAP_BYPASS"]
diff_out = os.environ["DIFF_OUT"]

with open(wafrift_json) as f:
    data = json.load(f)

wafrift_bypassed = set()
for result in data.get("results", []):
    evaded = result.get("evaded", {})
    if evaded.get("variants_bypassed", 0) > 0:
        wafrift_bypassed.add(result.get("case_id", ""))

sqlmap_bypassed = set()
with open(sqlmap_bypass_file) as f:
    for line in f:
        cid = line.strip()
        if cid:
            sqlmap_bypassed.add(cid)

all_cases = {r.get("case_id", "") for r in data.get("results", [])}

wafrift_only = wafrift_bypassed - sqlmap_bypassed
sqlmap_only = sqlmap_bypassed - wafrift_bypassed
both = wafrift_bypassed & sqlmap_bypassed
neither = all_cases - wafrift_bypassed - sqlmap_bypassed

def write_list(path, items):
    with open(path, "w") as f:
        for item in sorted(items):
            f.write(item + "\n")

write_list(os.path.join(diff_out, "wafrift_only.txt"), wafrift_only)
write_list(os.path.join(diff_out, "sqlmap_only.txt"), sqlmap_only)
write_list(os.path.join(diff_out, "both.txt"), both)
write_list(os.path.join(diff_out, "neither.txt"), neither)

summary = {
    "total_cases": len(all_cases),
    "wafrift_bypassed": len(wafrift_bypassed),
    "sqlmap_bypassed": len(sqlmap_bypassed),
    "wafrift_only": len(wafrift_only),
    "sqlmap_only": len(sqlmap_only),
    "both": len(both),
    "neither": len(neither),
}

with open(os.path.join(diff_out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=2)

print("\n=== Diff summary ===")
print(f"  Total SQL cases:       {summary['total_cases']}")
print(f"  wafrift bypassed:      {summary['wafrift_bypassed']}")
print(f"  sqlmap bypassed:       {summary['sqlmap_bypassed']}")
print(f"  wafrift only:          {summary['wafrift_only']}  <- superset claim")
print(f"  sqlmap only:           {summary['sqlmap_only']}  <- regressions to fix if >0")
print(f"  both bypass:           {summary['both']}")
print(f"  neither bypass:        {summary['neither']}")
print(f"\nResults in: {diff_out}")
PYEOF

echo ""
echo "Done. Tear down the WAF stack when finished:"
echo "  docker compose -f ${COMPOSE_FILE} down"
