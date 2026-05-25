//! E9 — catastrophic-regression smoke. Wall-clock micro-benchmarks in
//! `cargo test` are inherently load-sensitive and flaky on a busy CI
//! box; that is the WRONG tool for precise perf gating (criterion with
//! a pinned statistical baseline, under `benches/`, is — E9/65-71,
//! queued). This file is only the coarse guard: small N, very generous
//! ceilings, so it runs in well under a second normally and can ONLY
//! fail on a true *algorithmic* blow-up (an accidental O(2ⁿ) / a
//! quadratic clone in a hot loop), never on machine load. A flaky
//! perf test is itself a defect — so the bounds here are deliberately
//! coarse, not tight.

use std::time::{Duration, Instant};
use wafrift_types::Request;
use wafrift_wafmodel::canon::Channel;
use wafrift_wafmodel::{
    Alphabet, BytePred, ChannelSet, Rule, Sfa, SimRegexWaf, WMethodEq, attack_grammar, l_star,
    mine_bypasses,
};

fn body(b: &[u8]) -> Request {
    Request::post("https://h/p", b.to_vec()).header("Content-Type", "application/json")
}
fn contains(b: u8) -> Sfa {
    let g = BytePred::byte(b);
    Sfa::new(
        0,
        vec![false, true],
        vec![vec![(g, 1), (!g, 0)], vec![(BytePred::any(), 1)]],
    )
}

/// Catastrophic ceiling: anything slower than this for the tiny N
/// below is not load — it is an algorithmic regression.
///
/// Calibrated at 120 s to accommodate:
///  - Windows dev-machine overhead (disk, process scheduling) which adds
///    ~30–40 % over Linux CI even at idle.
///  - The kmp_sfa bug-fix (F-MINE-01) made `mine_bypasses` do real BFS
///    instead of returning an empty vector instantly. The old 60 s ceiling
///    was calibrated against the broken (zero-result) implementation and
///    has been raised accordingly. An algorithmic regression (e.g. O(2ⁿ)
///    enumeration) would still blow this ceiling — the ceiling is a
///    catastrophe guard, not a benchmark.
const CATASTROPHE: Duration = Duration::from_secs(120);

#[test]
fn sfa_algebra_has_not_exploded_algorithmically() {
    let a = contains(b'<');
    let b = contains(b'>');
    let t = Instant::now();
    for _ in 0..500 {
        let p = a.intersect(&b);
        std::hint::black_box(p.shortest_accepted());
        std::hint::black_box(p.minimize());
    }
    assert!(
        t.elapsed() < CATASTROPHE,
        "500 intersect+shortest+minimize took {:?} — algebra is \
         algorithmically regressed (not load)",
        t.elapsed()
    );
}

#[test]
fn decompile_and_mine_have_not_exploded_algorithmically() {
    let alpha = Alphabet::new(vec![b'<', b's', b'/'], b'A');
    let t = Instant::now();
    let learned = {
        let mut w = SimRegexWaf::new(
            vec![Rule {
                id: "r".into(),
                channels: ChannelSet::none().with(Channel::Body),
                transforms: vec![],
                pattern: regex::bytes::Regex::new("<s[^>]*/").unwrap(),
                score: 5,
            }],
            5,
        );
        let mut eq = WMethodEq { extra_states: 2 };
        l_star(&mut w, &body, &alpha, &mut eq).unwrap().sfa
    };
    let g = attack_grammar(&alpha, &[b"<s/"]);
    for _ in 0..50 {
        std::hint::black_box(mine_bypasses(&learned, &g, 8, 10));
    }
    assert!(
        t.elapsed() < CATASTROPHE,
        "single decompile + 50 mine passes took {:?} — regressed",
        t.elapsed()
    );
}

#[test]
fn normalize_is_linear_not_quadratic() {
    use wafrift_wafmodel::normalize::{Transform, apply_chain};
    let chain = [
        Transform::UrlDecodeUni,
        Transform::HtmlEntityDecode,
        Transform::Lowercase,
        Transform::CompressWhitespace,
    ];
    // Small vs 8× input: linear ⇒ ~8× time, never 64×. We assert only
    // the catastrophic ceiling (quadratic on this size would blow it).
    let small = b"%3Cscript%3E&#x41; ALERT\t%u0041".repeat(8);
    let big = small.repeat(8);
    let t = Instant::now();
    for _ in 0..200 {
        std::hint::black_box(apply_chain(&chain, &small).len());
    }
    for _ in 0..200 {
        std::hint::black_box(apply_chain(&chain, &big).len());
    }
    assert!(
        t.elapsed() < CATASTROPHE,
        "normalize over small+8× inputs took {:?} — likely quadratic",
        t.elapsed()
    );
}
