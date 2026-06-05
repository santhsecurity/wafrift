//! Criterion benchmarks for wafrift-grammar SQL hot paths.
//!
//! Run with:
//! ```bash
//! ssh work-linux 'cd /media/mukund-thiru/SanthData/Santh/software/wafrift && \
//!   cargo bench -p wafrift-grammar -- sql_mutate_hot_paths'
//! ```
//!
//! # Baselines (measured before optimization commit):
//!
//! sql_mutate/budget_32:
//!   tautology_20b   18.8 µs   union_select_55b  54.6 µs   time_blind_45b  27.9 µs
//!   error_based_70b 43.7 µs   stacked_50b       45.1 µs   complex_200b    82.2 µs
//!
//! sql_mutate/budget_64:
//!   tautology_20b   28.3 µs   union_select_55b  89.6 µs   time_blind_45b  56.5 µs
//!   error_based_70b 73.3 µs   stacked_50b       77.5 µs   complex_200b   139.9 µs
//!
//! anti_rig_gate/mutate_budget_1 (gate setup cost, budget=1 isolates gate):
//!   union_structured    14.2 µs → 13.4 µs (-3.5%)
//!   time_blind_structured  6.89 µs → 6.53 µs (-7.6%)
//!   error_based_structured 8.52 µs   tautology_no_gate  5.97 µs
//!
//! featurize (pre-optimization baseline, work-linux criterion):
//!   tautology_20b   192 ns   union_select_55b  291 ns
//!   complex_200b    569 ns   comment_split     230 ns
//!
//! featurize (after direct-index + single-pass normalize, same hardware):
//!   union_select_55b  275 ns (-5.5%)   complex_200b  493 ns (-13.4%)
//!   comment_split     214 ns (-7.0%)
//!   Note: absolute ns vary ±30 ns with CPU load/temperature.
//!
//! waf_model/learn (absolute times, work-linux; varies with machine load):
//!   samples_8  ~2.7–4.8 µs   samples_32  ~10–16 µs   samples_128  ~42–72 µs
//!
//! Hot paths targeted:
//!   1. `grammar::sql::mutate` — full mutation pass over SQL payloads at various
//!      `max_mutations` budgets.  Calls strip_sql_comments_ws + is_structured_attack
//!      + significant_tokens + retain inside the anti-rig gate on every call.
//!   2. `strip_sql_comments_ws` (indirectly via mutate) — two-pass impl:
//!      builds String byte-by-byte, then calls to_ascii_lowercase() as second pass.
//!      Optimized to single-pass with inline lowercase.
//!   3. `is_structured_attack` — called once per mutate() for the anti-rig gate.
//!      + `significant_tokens` — old code called strip_sql_comments_ws(payload) twice.
//!      After opt: single strip, result shared between the two callers.
//!   4. `featurize` — CEGIS inner loop: called per candidate × per sort/synthesize.
//!      Old: `set(name)` did FEATURES.iter().position() (O(37)) × ~20 calls = ~740
//!      string comparisons per featurize. Optimized to direct compile-time index writes.
//!      Also: two String allocations (lowercase + block-comment strip) collapsed to one.
//!   5. `WafModel::learn` — perceptron fitting over (features, blocked) samples.
//!      Benchmarked to validate no regression from code changes. No net optimization
//!      applied (pre-pad approach had +2.5% overhead for small sample counts).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use wafrift_grammar::grammar::sql::mutate;
use wafrift_grammar::grammar::equiv::wafmodel::{FEATURES, WafModel, featurize};

// ── Realistic payloads ───────────────────────────────────────────────────────

/// Classic SQLi tautology (WHERE-clause, ~20 bytes).
const TAUTOLOGY: &str = "' OR 1=1--";

/// UNION-based exfiltration (structured, ~55 bytes).
const UNION_SELECT: &str = "' UNION SELECT username,password,NULL FROM users--";

/// Time-blind injection (structured, ~45 bytes).
const TIME_BLIND: &str = "'; IF(1=1,WAITFOR DELAY '0:0:5',0)--";

/// Error-based exfiltration (structured, ~70 bytes).
const ERROR_BASED: &str =
    "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--";

/// Stacked query (structured, ~50 bytes).
const STACKED: &str = "'; DROP TABLE users; INSERT INTO log VALUES(1)--";

/// Long payload with many mutation targets (~200 bytes).
const COMPLEX: &str =
    "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE \
     username='admin')='a' UNION SELECT NULL,NULL,NULL FROM \
     information_schema.tables WHERE table_schema=database()--";

// ── sql::mutate benchmarks ───────────────────────────────────────────────────

fn bench_sql_mutate(c: &mut Criterion) {
    let mut group = c.benchmark_group("sql_mutate");

    let payloads: &[(&str, &str)] = &[
        ("tautology_20b", TAUTOLOGY),
        ("union_select_55b", UNION_SELECT),
        ("time_blind_45b", TIME_BLIND),
        ("error_based_70b", ERROR_BASED),
        ("stacked_50b", STACKED),
        ("complex_200b", COMPLEX),
    ];

    for (name, payload) in payloads {
        // Budget 32: typical scan budget per payload.
        group.bench_with_input(
            BenchmarkId::new("budget_32", name),
            payload,
            |b, p| {
                b.iter(|| {
                    let r = mutate(black_box(p), black_box(32));
                    black_box(r)
                });
            },
        );
        // Budget 64: aggressive mutation mode.
        group.bench_with_input(
            BenchmarkId::new("budget_64", name),
            payload,
            |b, p| {
                b.iter(|| {
                    let r = mutate(black_box(p), black_box(64));
                    black_box(r)
                });
            },
        );
    }
    group.finish();
}

// ── anti-rig gate sub-benchmarks ─────────────────────────────────────────────
//
// The gate calls `is_structured_attack` and `significant_tokens` (both pub(crate),
// not exposed for benchmarking). We measure them indirectly through `mutate()` with
// a tight budget (1) so the mutation loop cost is minimal and the gate dominates.

fn bench_anti_rig_gate(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_rig_gate");

    // Structured attacks always trigger the gate.
    for (name, payload) in &[
        ("union_structured", UNION_SELECT),
        ("time_blind_structured", TIME_BLIND),
        ("error_based_structured", ERROR_BASED),
    ] {
        group.bench_with_input(
            BenchmarkId::new("mutate_budget_1", name),
            payload,
            |b, p| {
                b.iter(|| {
                    // Budget 1 isolates the gate setup cost (is_structured + significant_tokens
                    // + the one-element retain) vs the full mutation loop.
                    let r = mutate(black_box(p), black_box(1));
                    black_box(r)
                });
            },
        );
    }

    // Non-structured: gate does NOT fire (is_structured returns false).
    group.bench_with_input(
        BenchmarkId::new("mutate_budget_1", "tautology_no_gate"),
        &TAUTOLOGY,
        |b, p| {
            b.iter(|| {
                let r = mutate(black_box(p), black_box(1));
                black_box(r)
            });
        },
    );
    group.finish();
}

// ── featurize benchmarks ─────────────────────────────────────────────────────
//
// featurize is the CEGIS inner-loop kernel. With 13 arms × 4 variants = 52
// candidates and a pool sort + synthesize pass per CEGIS iteration, featurize
// runs O(100) times per `run_equiv_cegis` call. It used to call
// FEATURES.iter().position() ~20 times per invocation (O(37) each = ~740
// string comparisons). Optimized to direct compile-time index writes.

fn bench_featurize(c: &mut Criterion) {
    let mut group = c.benchmark_group("featurize");

    let payloads: &[(&str, &str, usize)] = &[
        ("tautology_20b", TAUTOLOGY, 7),    // query arm
        ("union_select_55b", UNION_SELECT, 0), // multipart_file arm
        ("complex_200b", COMPLEX, 3),       // json_no_ct arm
        ("comment_split", "1' UNION/**/SELECT a,b FROM users-- -", 1), // comment-stripping path
    ];

    for (name, payload, arm) in payloads {
        group.bench_with_input(
            BenchmarkId::new("featurize", name),
            &(*payload, *arm),
            |b, (p, a)| {
                b.iter(|| {
                    let v = featurize(black_box(p), black_box(*a));
                    black_box(v)
                });
            },
        );
    }
    group.finish();
}

// ── WafModel::learn benchmarks ────────────────────────────────────────────────
//
// learn() is called after every counterexample (CEGIS phase 2) and once at
// the end of every `run_equiv_cegis` call. Realistic sample counts: 8 (early
// phase 1), 32 (full budget=32 run), 128 (large engagement).

fn bench_waf_model_learn(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf_model");
    let ui = FEATURES.iter().position(|x| *x == "has_union").unwrap();
    let si = FEATURES.iter().position(|x| *x == "has_select").unwrap();

    for &n in &[8usize, 32, 128] {
        // Build label-consistent samples: blocked iff has_union OR has_select.
        let samples: Vec<(Vec<f64>, bool)> = (0..n)
            .map(|k| {
                let mut x = vec![0.0; FEATURES.len()];
                // Alternate which feature is set.
                let set_union = k % 3 == 0;
                let set_sel = k % 5 == 0;
                if set_union {
                    x[ui] = 1.0;
                }
                if set_sel {
                    x[si] = 1.0;
                }
                (x, set_union || set_sel)
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("learn", format!("samples_{n}")),
            &samples,
            |b, s| {
                b.iter(|| {
                    let m = WafModel::learn(black_box(s), black_box(30));
                    black_box(m)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_sql_mutate, bench_anti_rig_gate, bench_featurize, bench_waf_model_learn);
criterion_main!(benches);
