//! Criterion benchmarks for the wafrift-encoding hot paths.
//!
//! Run with:
//! ```bash
//! ssh work-linux 'cd /media/mukund-thiru/SanthData/Santh/software/wafrift && \
//!   cargo bench -p wafrift-encoding -- encoding_hot_paths'
//! ```
//!
//! # Baselines (measured before optimization commit):
//!
//! url_encode:
//!   encode/sql_40b      567 ns  encode_lower/sql_40b  648 ns  double_encode/sql_40b  983 ns
//!   encode/xss_50b      556 ns  encode_lower/xss_50b  604 ns  double_encode/xss_50b  994 ns
//!   encode/long_200b   2129 ns  encode_lower/long_200b 2211 ns
//!   encode/unreserved_30b 401 ns
//!
//! case_alternation:
//!   case_alternate/sql_40b    142 ns   random_case/sql_40b    179 ns
//!   case_alternate/long_200b  365 ns   random_case/long_200b  497 ns
//!
//! space_replacement:
//!   space_to_comment/sql_40b        153 ns   space_to_random_blank/sql_40b    171 ns
//!   space_to_comment/long_200b      409 ns   space_to_random_blank/long_200b  489 ns
//!
//! Hot paths targeted:
//!   1. `url_encode` — called on every payload in the encoding chain.
//!      `UNRESERVED.contains(&b)` is O(66) linear scan per byte.
//!      Optimized to O(1) 256-entry lookup table.
//!   2. `case_alternate` — `.collect::<String>()` started with cap 0, may realloc.
//!      After opt: `with_capacity(payload.len())` + push loop.
//!   3. `random_case_alternate` — duplicates FNV fold over bytes then iterates chars.
//!      After opt: canonical `fnv1a_64()` + pre-sized output.
//!   4. `space_to_random_blank` — same duplicate-FNV pattern as random_case.
//!   5. `encode_layered` (3-strategy chain) — end-to-end pipeline cost (benefits from 1-4).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use wafrift_encoding::encoding::{encode_layered, strategy::Strategy};

// ── Realistic payload sizes ──────────────────────────────────────────────────

/// Typical SQLi payload (≈40 bytes, mostly reserved/special chars).
const SQL_PAYLOAD: &str = "' OR 1=1 UNION SELECT NULL,NULL,NULL--";

/// Typical XSS payload (≈50 bytes, mix of reserved and unreserved).
const XSS_PAYLOAD: &str = "<script>alert(document.cookie)</script>";

/// Long payload with many spaces (stress-tests space-replacement paths, ≈200 bytes).
const LONG_SPACED: &str = "SELECT id, username, password FROM users WHERE username='admin' OR 1=1 \
     UNION SELECT table_name, column_name, NULL FROM information_schema.columns--";

/// Short unreserved-heavy payload (most bytes pass through unchanged, ≈30 bytes).
const UNRESERVED_PAYLOAD: &str = "username=admin&password=letmein123";

// ── url_encode benchmarks ────────────────────────────────────────────────────

fn bench_url_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_encode");

    let cases: &[(&str, &str)] = &[
        ("sql_40b", SQL_PAYLOAD),
        ("xss_50b", XSS_PAYLOAD),
        ("long_200b", LONG_SPACED),
        ("unreserved_30b", UNRESERVED_PAYLOAD),
    ];

    for (name, payload) in cases {
        group.bench_with_input(BenchmarkId::new("encode", name), payload, |b, p| {
            b.iter(|| {
                let r = wafrift_encoding::encoding::strategy::encode(
                    black_box(p.as_bytes()),
                    black_box(Strategy::UrlEncode),
                );
                black_box(r)
            });
        });
        group.bench_with_input(BenchmarkId::new("encode_lower", name), payload, |b, p| {
            b.iter(|| {
                let r = wafrift_encoding::encoding::strategy::encode(
                    black_box(p.as_bytes()),
                    black_box(Strategy::UrlEncodeLower),
                );
                black_box(r)
            });
        });
        group.bench_with_input(BenchmarkId::new("double_encode", name), payload, |b, p| {
            b.iter(|| {
                let r = wafrift_encoding::encoding::strategy::encode(
                    black_box(p.as_bytes()),
                    black_box(Strategy::DoubleUrlEncode),
                );
                black_box(r)
            });
        });
    }
    group.finish();
}

// ── case alternation benchmarks ──────────────────────────────────────────────

fn bench_case_alternation(c: &mut Criterion) {
    let mut group = c.benchmark_group("case_alternation");

    for (name, payload) in &[("sql_40b", SQL_PAYLOAD), ("long_200b", LONG_SPACED)] {
        group.bench_with_input(BenchmarkId::new("case_alternate", name), payload, |b, p| {
            b.iter(|| {
                let r = wafrift_encoding::encoding::strategy::encode(
                    black_box(p.as_bytes()),
                    black_box(Strategy::CaseAlternation),
                );
                black_box(r)
            });
        });
        group.bench_with_input(BenchmarkId::new("random_case", name), payload, |b, p| {
            b.iter(|| {
                let r = wafrift_encoding::encoding::strategy::encode(
                    black_box(p.as_bytes()),
                    black_box(Strategy::RandomCase),
                );
                black_box(r)
            });
        });
    }
    group.finish();
}

// ── space-replacement benchmarks ─────────────────────────────────────────────

fn bench_space_replacement(c: &mut Criterion) {
    let mut group = c.benchmark_group("space_replacement");

    for (name, payload) in &[("sql_40b", SQL_PAYLOAD), ("long_200b", LONG_SPACED)] {
        group.bench_with_input(
            BenchmarkId::new("space_to_comment", name),
            payload,
            |b, p| {
                b.iter(|| {
                    let r = wafrift_encoding::encoding::strategy::encode(
                        black_box(p.as_bytes()),
                        black_box(Strategy::SpaceToComment),
                    );
                    black_box(r)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("space_to_random_blank", name),
            payload,
            |b, p| {
                b.iter(|| {
                    let r = wafrift_encoding::encoding::strategy::encode(
                        black_box(p.as_bytes()),
                        black_box(Strategy::SpaceToRandomBlank),
                    );
                    black_box(r)
                });
            },
        );
    }
    group.finish();
}

// ── layered encoding chain benchmarks ────────────────────────────────────────

fn bench_encode_layered(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_layered");

    // Realistic 2-strategy chains from the escalation playbook.
    let chains: &[(&str, &[Strategy])] = &[
        (
            "url_case",
            &[Strategy::UrlEncode, Strategy::CaseAlternation],
        ),
        (
            "case_url",
            &[Strategy::CaseAlternation, Strategy::UrlEncode],
        ),
        (
            "case_space_url",
            &[
                Strategy::CaseAlternation,
                Strategy::SpaceToComment,
                Strategy::UrlEncode,
            ],
        ),
        (
            "url_double_url",
            &[Strategy::UrlEncode, Strategy::DoubleUrlEncode],
        ),
    ];

    for (chain_name, chain) in chains {
        group.bench_with_input(
            BenchmarkId::new("sql_40b", chain_name),
            &(SQL_PAYLOAD, *chain),
            |b, (payload, chain)| {
                b.iter(|| {
                    let r = encode_layered(black_box(payload.as_bytes()), black_box(chain));
                    black_box(r)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("long_200b", chain_name),
            &(LONG_SPACED, *chain),
            |b, (payload, chain)| {
                b.iter(|| {
                    let r = encode_layered(black_box(payload.as_bytes()), black_box(chain));
                    black_box(r)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_url_encode,
    bench_case_alternation,
    bench_space_replacement,
    bench_encode_layered,
);
criterion_main!(benches);
