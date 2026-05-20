#!/usr/bin/env python3
"""Render the public bypass-rate scoreboard from `bench-waf` JSON results.

Input: a directory containing one JSON per (WAF stack × bench run) in the
shape produced by `wafrift bench-waf --format json`. Each file is
expected to have a top-level `by_class` map keyed by payload class
(`sql`, `xss`, `cmdi`, …) with `bypass_rate` / `raw_block_rate` /
`cases` / `evaded_bypassed` / `evaded_total` per entry.

Output (stdout): Markdown — one canonical (WAF × class) bypass-rate
table + a one-line summary row per WAF and a "how to reproduce" block.

File name → WAF stack inference: the first hyphenated segment that
matches a known stack wins (so both
`modsec-pl1-allstrats-2026-05-19.json` and
`honest-modsec-pl1-equiv-cegis-0.2.16.json` map to `modsec-pl1`).
Multiple files for the same stack: pick the most recent by mtime — the
intent is "the latest run wins," not "average across history."

Run locally after a bench:

    wafrift-bench/scripts/render-scoreboard.py wafrift-bench/results/ \
        > docs/SCOREBOARD.md

Or in CI: see `.github/workflows/bench.yml` (the `scoreboard` job).

Designed for zero extra dependencies — only stdlib.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

KNOWN_STACKS = [
    "modsec-pl1",
    "modsec-pl2",
    "modsec-pl3",
    "modsec-pl4",
    "coraza",
    "bunkerweb",
    "naxsi",
]

# Display order for the column headers — fixed so column drift between
# runs doesn't shuffle the table. Classes not present in any result are
# omitted from the rendered table.
CANONICAL_CLASSES = [
    "sql",
    "xss",
    "cmdi",
    "ssti",
    "path",
    "ldap",
    "xxe",
    "ssrf",
    "nosql",
    "log4shell",
]


def infer_stack(path: pathlib.Path) -> Optional[str]:
    """Return the WAF stack name a result file represents, or None."""
    stem = path.stem.lower()
    for stack in KNOWN_STACKS:
        if stack in stem:
            return stack
    return None


def latest_per_stack(result_dir: pathlib.Path) -> Dict[str, pathlib.Path]:
    """For each known stack, pick the most recently modified result file."""
    picks: Dict[str, Tuple[float, pathlib.Path]] = {}
    for path in sorted(result_dir.glob("*.json")):
        stack = infer_stack(path)
        if stack is None:
            continue
        mtime = path.stat().st_mtime
        if stack not in picks or picks[stack][0] < mtime:
            picks[stack] = (mtime, path)
    return {stack: path for stack, (_, path) in picks.items()}


def load_by_class(path: pathlib.Path) -> Dict[str, Dict[str, float]]:
    """Return the `by_class` map, or {} if the file is not a bench result."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            blob = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"warn: skipping {path.name}: {e}", file=sys.stderr)
        return {}
    by_class = blob.get("by_class")
    if not isinstance(by_class, dict):
        return {}
    return by_class


def fmt_pct(v: float) -> str:
    """Format a 0..1 ratio as a percentage with one decimal."""
    return f"{v * 100:.1f}"


def fmt_cell(entry: Optional[Dict[str, float]]) -> str:
    """Render one (stack, class) cell. Distinguishes:
    - `—` : class not exercised by this stack's run at all
    - `0.0` : exercised, no bypass
    - `12.3` : verified bypass rate (percent)
    """
    if entry is None:
        return "—"
    bypass = entry.get("bypass_rate")
    cases = entry.get("cases")
    if bypass is None or cases in (None, 0):
        return "—"
    return fmt_pct(float(bypass))


def render_scoreboard(latest: Dict[str, pathlib.Path]) -> str:
    """Build the markdown scoreboard from the latest per-stack results."""
    per_stack: Dict[str, Dict[str, Dict[str, float]]] = {
        stack: load_by_class(path) for stack, path in latest.items()
    }
    classes_present = [
        c for c in CANONICAL_CLASSES if any(c in by_class for by_class in per_stack.values())
    ]
    # Stacks present, in canonical order (so the column always starts modsec-pl1).
    stacks_present = [s for s in KNOWN_STACKS if s in per_stack]

    if not stacks_present:
        return _no_results_message()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines: List[str] = []
    lines.append("# WafRift bypass scoreboard")
    lines.append("")
    lines.append(
        f"_Generated {now} from `wafrift-bench/results/` via "
        "`wafrift-bench/scripts/render-scoreboard.py`. Numbers are the "
        "**verified-bypass** rate per payload class — oracle-gated, "
        "transport-reached, no inflation. Cell = % of variants for that "
        "class that wafrift found a working bypass for; `—` = class "
        "not exercised on that stack._"
    )
    lines.append("")

    # Header: class | stack1 | stack2 | ...
    header = ["class"] + stacks_present
    sep = ["---"] + [":---:"] * len(stacks_present)
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join(sep) + " |")
    for cls in classes_present:
        row = [cls]
        for stack in stacks_present:
            row.append(fmt_cell(per_stack[stack].get(cls)))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # Per-stack summary row.
    lines.append("## Per-stack roll-up")
    lines.append("")
    lines.append("| stack | classes exercised | total variants | total bypassed | overall rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for stack in stacks_present:
        by_class = per_stack[stack]
        classes_n = sum(1 for c in classes_present if c in by_class and by_class[c].get("cases"))
        total_variants = int(sum(by_class[c].get("evaded_total", 0) for c in by_class))
        total_bypassed = int(sum(by_class[c].get("evaded_bypassed", 0) for c in by_class))
        rate = (total_bypassed / total_variants * 100.0) if total_variants > 0 else 0.0
        lines.append(
            f"| {stack} | {classes_n} | {total_variants:,} | {total_bypassed:,} | {rate:.1f}% |"
        )
    lines.append("")

    # Source files used.
    lines.append("## Source")
    lines.append("")
    lines.append("Latest result file picked per stack:")
    lines.append("")
    for stack in stacks_present:
        lines.append(f"- `{latest[stack].name}` -> **{stack}**")
    lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("# Bring up one stack")
    lines.append("wafrift-bench/scripts/up.sh modsec-pl4")
    lines.append("")
    lines.append("# Run the full bench with verified-bypass gating")
    lines.append("cargo run --release -p wafrift-cli -- bench-waf \\")
    lines.append("    --base-url http://127.0.0.1:18084 \\")
    lines.append("    --corpus wafrift-bench/corpus \\")
    lines.append("    --evade --variants 20 \\")
    lines.append(
        "    --strategies heavy,mcts,smuggling,content-type,redos,hill-climb,sim-anneal,tabu,novelty,map-elites,differential \\"
    )
    lines.append("    --oracle-gate \\")
    lines.append("    --format json \\")
    lines.append("    --output wafrift-bench/results/modsec-pl4-$(date -u +%Y%m%d).json")
    lines.append("")
    lines.append("# Re-render the scoreboard")
    lines.append("wafrift-bench/scripts/render-scoreboard.py wafrift-bench/results/ \\")
    lines.append("    > docs/SCOREBOARD.md")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _no_results_message() -> str:
    return (
        "# WafRift bypass scoreboard\n"
        "\n"
        "_No bench results found. Run a bench first — see "
        "[wafrift-bench/README.md](../wafrift-bench/README.md)._\n"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "results_dir",
        type=pathlib.Path,
        help="Directory of bench-waf JSON output files.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=pathlib.Path,
        default=None,
        help="Write to this file instead of stdout.",
    )
    args = parser.parse_args(argv)
    if not args.results_dir.is_dir():
        print(f"error: {args.results_dir} is not a directory", file=sys.stderr)
        return 2
    latest = latest_per_stack(args.results_dir)
    md = render_scoreboard(latest)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(md, encoding="utf-8")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
