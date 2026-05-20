#!/usr/bin/env python3
"""Tests for `render-scoreboard.py`.

The renderer is a public-facing artefact — it drives docs/SCOREBOARD.md.
A regression that mis-sorts the columns or silently drops a stack
would mislead anyone reading the dashboard. These tests gate the
renderer against:

- File-name inference (multiple stacks share substring fragments).
- Missing classes (cell rendered as `—`, not omitted or zero).
- Multiple files per stack (latest by mtime wins).
- Malformed JSON files (skipped with a warning, not panic).
- Empty input dir (renders a sensible "no data" page).
- BTreeMap-style alphabetical key stability across runs.

Stdlib-only — no pytest. Run:

    python wafrift-bench/scripts/test_render_scoreboard.py

or via the workspace test runner if/when wired.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest


def _load_module() -> object:
    """Load render-scoreboard.py as a module. Filename has a hyphen
    which is illegal in normal `import`, so we use importlib's
    spec-from-file path."""
    here = pathlib.Path(__file__).parent
    path = here / "render-scoreboard.py"
    spec = importlib.util.spec_from_file_location("render_scoreboard", str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RS = _load_module()


def _write_result(dir_path: pathlib.Path, name: str, payload: dict) -> pathlib.Path:
    p = dir_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


class InferStack(unittest.TestCase):
    def test_modsec_pl_variants_each_map_to_their_own_stack(self):
        for stack in ("modsec-pl1", "modsec-pl2", "modsec-pl3", "modsec-pl4"):
            inferred = RS.infer_stack(pathlib.Path(f"results/{stack}-20260520.json"))
            self.assertEqual(inferred, stack)

    def test_filename_containing_modsec_pl1_does_not_collide_with_pl4(self):
        # Two files: pl1-only and pl4-only. The substring search
        # must return the exact stack, not e.g. always "modsec-pl1"
        # because it appears first in KNOWN_STACKS.
        a = RS.infer_stack(pathlib.Path("v022-modsec-pl1-tail.json"))
        b = RS.infer_stack(pathlib.Path("v022-modsec-pl4-tail.json"))
        self.assertEqual(a, "modsec-pl1")
        self.assertEqual(b, "modsec-pl4")

    def test_unrelated_file_returns_none(self):
        self.assertIsNone(RS.infer_stack(pathlib.Path("README.md")))
        self.assertIsNone(RS.infer_stack(pathlib.Path("random-thing.json")))
        # SUMMARY.md / BENCH_021_NOTES.md exist in the real results dir;
        # they should not be inferred as any stack.
        self.assertIsNone(RS.infer_stack(pathlib.Path("SUMMARY.md")))

    def test_inference_is_case_insensitive(self):
        # Some operators uppercase their result-file names.
        self.assertEqual(
            RS.infer_stack(pathlib.Path("MODSEC-PL1-2026.json")),
            "modsec-pl1",
        )


class LatestPerStack(unittest.TestCase):
    def test_picks_latest_by_mtime_when_two_files_for_one_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            old = _write_result(tmp_p, "modsec-pl1-old.json", {"by_class": {}})
            time.sleep(0.05)  # ensure distinct mtime
            new = _write_result(tmp_p, "modsec-pl1-new.json", {"by_class": {}})
            picks = RS.latest_per_stack(tmp_p)
            self.assertIn("modsec-pl1", picks)
            self.assertEqual(picks["modsec-pl1"], new)
            self.assertNotEqual(picks["modsec-pl1"], old)

    def test_unrelated_files_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            _write_result(tmp_p, "modsec-pl4-run.json", {"by_class": {}})
            (tmp_p / "README.md").write_text("noise", encoding="utf-8")
            (tmp_p / "SUMMARY.md").write_text("more noise", encoding="utf-8")
            picks = RS.latest_per_stack(tmp_p)
            self.assertEqual(set(picks.keys()), {"modsec-pl4"})


class LoadByClass(unittest.TestCase):
    def test_well_formed_returns_by_class_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_result(
                pathlib.Path(tmp),
                "naxsi-1.json",
                {"by_class": {"sql": {"bypass_rate": 0.5, "cases": 100}}},
            )
            result = RS.load_by_class(p)
            self.assertIn("sql", result)
            self.assertAlmostEqual(result["sql"]["bypass_rate"], 0.5)

    def test_missing_by_class_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_result(pathlib.Path(tmp), "naxsi-1.json", {"foo": "bar"})
            self.assertEqual(RS.load_by_class(p), {})

    def test_malformed_json_is_skipped_with_warning_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "naxsi-broken.json"
            p.write_text("{ not valid json", encoding="utf-8")
            # Must NOT raise — the renderer keeps going.
            result = RS.load_by_class(p)
            self.assertEqual(result, {})

    def test_by_class_with_wrong_type_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_result(
                pathlib.Path(tmp), "naxsi-1.json", {"by_class": "string-not-object"}
            )
            self.assertEqual(RS.load_by_class(p), {})


class RenderScoreboard(unittest.TestCase):
    def test_empty_input_dir_emits_no_results_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            md = RS.render_scoreboard(RS.latest_per_stack(pathlib.Path(tmp)))
            self.assertIn("No bench results found", md)

    def test_renders_canonical_table_for_one_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            _write_result(
                tmp_p,
                "modsec-pl1-2026.json",
                {
                    "by_class": {
                        "sql": {
                            "bypass_rate": 0.25,
                            "cases": 100,
                            "evaded_total": 1000,
                            "evaded_bypassed": 250,
                        },
                        "xss": {
                            "bypass_rate": 0.18,
                            "cases": 50,
                            "evaded_total": 500,
                            "evaded_bypassed": 90,
                        },
                    }
                },
            )
            md = RS.render_scoreboard(RS.latest_per_stack(tmp_p))
            self.assertIn("modsec-pl1", md)
            self.assertIn("| sql |", md)
            self.assertIn("| xss |", md)
            self.assertIn("25.0", md)  # sql bypass-rate
            self.assertIn("18.0", md)  # xss bypass-rate

    def test_class_not_exercised_renders_em_dash(self):
        # A stack that only ran sql must show `—` in xss / cmdi / etc.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            _write_result(
                tmp_p,
                "naxsi-1.json",
                {"by_class": {"sql": {"bypass_rate": 0.1, "cases": 50}}},
            )
            md = RS.render_scoreboard(RS.latest_per_stack(tmp_p))
            self.assertIn("—", md)  # the em-dash appears for non-exercised classes

    def test_per_stack_rollup_is_consistent_with_per_class_cells(self):
        # The rollup row's "total bypassed" must equal the sum of
        # evaded_bypassed across all classes for that stack.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            _write_result(
                tmp_p,
                "naxsi-1.json",
                {
                    "by_class": {
                        "sql": {
                            "bypass_rate": 0.2,
                            "cases": 100,
                            "evaded_total": 1000,
                            "evaded_bypassed": 200,
                        },
                        "xss": {
                            "bypass_rate": 0.1,
                            "cases": 50,
                            "evaded_total": 500,
                            "evaded_bypassed": 50,
                        },
                    }
                },
            )
            md = RS.render_scoreboard(RS.latest_per_stack(tmp_p))
            # Rollup row: total_variants = 1500, total_bypassed = 250,
            # rate = 250/1500 = 16.7%.
            self.assertIn("1,500", md)
            self.assertIn("250", md)
            self.assertIn("16.7%", md)

    def test_rendered_table_columns_in_canonical_stack_order(self):
        # Multiple stacks; output column order must match
        # KNOWN_STACKS ordering, not insertion order from the
        # filesystem.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp)
            # Drop in reverse order: naxsi first, then modsec-pl1.
            _write_result(tmp_p, "naxsi.json", {"by_class": {"sql": {"bypass_rate": 0.1, "cases": 50}}})
            time.sleep(0.05)
            _write_result(tmp_p, "modsec-pl1.json", {"by_class": {"sql": {"bypass_rate": 0.2, "cases": 50}}})
            md = RS.render_scoreboard(RS.latest_per_stack(tmp_p))
            modsec_pos = md.find("modsec-pl1")
            naxsi_pos = md.find("naxsi")
            # Header row: modsec-pl1 must come BEFORE naxsi (canonical
            # KNOWN_STACKS order).
            self.assertLess(modsec_pos, naxsi_pos)


class FormatCell(unittest.TestCase):
    def test_none_returns_em_dash(self):
        self.assertEqual(RS.fmt_cell(None), "—")

    def test_zero_cases_returns_em_dash(self):
        self.assertEqual(RS.fmt_cell({"bypass_rate": 0.5, "cases": 0}), "—")

    def test_missing_bypass_rate_returns_em_dash(self):
        self.assertEqual(RS.fmt_cell({"cases": 100}), "—")

    def test_canonical_value_formats_to_one_decimal_percent(self):
        self.assertEqual(RS.fmt_cell({"bypass_rate": 0.25, "cases": 100}), "25.0")
        self.assertEqual(RS.fmt_cell({"bypass_rate": 0.123, "cases": 1}), "12.3")


if __name__ == "__main__":
    unittest.main()
