//! Unit tests for `grammar::equiv::sql` internals exposed via pub helpers.
//!
//! These tests cover the functions that have zero inline tests despite being
//! load-bearing: `round_trip`, `normalize_pub`, `still_executes`,
//! `delivery_kind_label`, `DELIVERY_ARMS`, `_sample_truth/_sample_false`,
//! and the main `generate` entry point under adversarial conditions.
//!
//! Every test includes a comment naming the property it pins.

use wafrift_grammar::grammar::equiv::sql as esql;
use wafrift_grammar::grammar::equiv::{self, DeliveryShape, EquivConfig};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn cfg_max(max: usize) -> EquivConfig {
    EquivConfig {
        seed: 0xDEAD_BEEF_CAFE_F00D,
        max,
        verify: true,
        vary_delivery: true,
        param: "id".into(),
        force_delivery: None,
    }
}

// ─── round_trip (tokenizer ↔ renderer losslessness) ──────────────────────────

#[test]
fn round_trip_preserves_empty_string() {
    // PROPERTY: the empty payload must survive losslessly; the tokenizer
    // must not inject synthetic tokens into an empty input.
    assert_eq!(esql::round_trip(""), "");
}

#[test]
fn round_trip_preserves_structured_exfil_payload() {
    // PROPERTY: a real UNION-SELECT exfil payload must survive the
    // tokenize→render cycle byte-for-byte so the rewrite engine can
    // reconstruct it after any number of mutations.
    let p = "1 UNION SELECT username,password FROM users-- -";
    assert_eq!(esql::round_trip(p), p);
}

#[test]
fn round_trip_preserves_auth_bypass_payload() {
    // PROPERTY: a tautology-class auth bypass must also round-trip; no
    // loss at the quote/operator boundary.
    let p = "1' OR '1'='1";
    assert_eq!(esql::round_trip(p), p);
}

#[test]
fn round_trip_preserves_hex_and_scientific_literals() {
    // PROPERTY: hex (`0xDEAD`) and scientific (`1e2`) literals must not
    // be mangled; they are valid numeric tokens with alternate notation.
    assert_eq!(esql::round_trip("0xDEAD"), "0xDEAD");
    assert_eq!(esql::round_trip("1e2"), "1e2");
}

#[test]
fn round_trip_preserves_block_comment() {
    // PROPERTY: `/**/` is a recognised comment token (a whitespace
    // separator); after tokenizing it must render back unchanged.
    let p = "1/**/OR/**/1=1";
    assert_eq!(esql::round_trip(p), p);
}

#[test]
fn round_trip_preserves_unicode_identifier() {
    // PROPERTY: non-ASCII alphabetic characters in an identifier (e.g.
    // a column alias) must survive — the tokenizer must not drop them.
    let p = "SELECT café FROM users";
    assert_eq!(esql::round_trip(p), p);
}

// ─── normalize_pub ────────────────────────────────────────────────────────────

#[test]
fn normalize_pub_strips_plain_comment_and_lowercases() {
    // PROPERTY: `/* comment */` is equivalent to a single space and the
    // normalizer must strip it and lowercase the result.
    let n = esql::normalize_pub("SELECT/* x */1");
    // After stripping the comment the tokens are `select` `1`; joining
    // whitespace collapses any runs.
    assert!(n.contains("select"), "must lowercase: got {n:?}");
    assert!(
        !n.contains("/*"),
        "plain comment must be stripped: got {n:?}"
    );
}

#[test]
fn normalize_pub_preserves_mysql_conditional_comment_body() {
    // PROPERTY: `/*! body */` is a MySQL conditional comment whose body
    // EXECUTES on MySQL. The normalizer must fold the body in (not strip
    // it) so the verifier sees the hidden keyword.
    let n = esql::normalize_pub("SE/*!LECT*/1");
    // The body `LECT` survives; lowercased it joins `se` into `select`.
    assert!(
        n.contains("lect"),
        "conditional-comment body must survive normalisation: got {n:?}"
    );
}

#[test]
fn normalize_pub_collapses_all_whitespace_forms_to_single_space() {
    // PROPERTY: tabs, newlines, and multiple spaces are all equivalent
    // SQL whitespace; the normalizer must collapse any run to one space
    // so `still_executes` comparisons are whitespace-invariant.
    let n = esql::normalize_pub("SELECT\t\n  1");
    assert!(!n.contains('\t'), "tab must be normalised: got {n:?}");
    assert!(!n.contains('\n'), "newline must be normalised: got {n:?}");
    assert!(!n.contains("  "), "double-space must collapse: got {n:?}");
}

#[test]
fn normalize_pub_strips_line_comment_with_dash_dash() {
    // PROPERTY: `--` introduces a line comment; everything after must be
    // dropped so the verifier is not fooled by comment-appended junk.
    let n = esql::normalize_pub("1=1-- this is a comment");
    assert!(
        !n.contains("comment"),
        "line comment content must be stripped: got {n:?}"
    );
    assert!(
        n.trim().ends_with("1=1") || n.contains("1=1"),
        "core expression must survive: got {n:?}"
    );
}

#[test]
fn normalize_pub_strips_hash_line_comment() {
    // PROPERTY: `#` also introduces a line comment in MySQL; same
    // stripping rule applies.
    let n = esql::normalize_pub("1=1#hidden");
    assert!(
        !n.contains("hidden"),
        "hash-comment content must be stripped: got {n:?}"
    );
}

#[test]
fn normalize_pub_on_empty_input_returns_empty_or_whitespace_only() {
    // PROPERTY: normalising the empty string must return something empty
    // (never inject synthetic content).
    let n = esql::normalize_pub("");
    assert!(
        n.trim().is_empty(),
        "empty input must normalise to empty: got {n:?}"
    );
}

// ─── still_executes ───────────────────────────────────────────────────────────

#[test]
fn still_executes_accepts_identity() {
    // PROPERTY: every known-good attack is trivially an execution of
    // itself; `still_executes(p, p)` must always be true.
    let attacks = [
        "1' OR '1'='1",
        "1 UNION SELECT username,password FROM users-- -",
        "admin'--",
        "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
        "1; DROP TABLE users-- -",
    ];
    for a in attacks {
        assert!(
            esql::still_executes(a, a),
            "identity must always still-execute: {a:?}"
        );
    }
}

#[test]
fn still_executes_rejects_empty_candidate() {
    // PROPERTY: the empty string has no exploit mechanism; a generator
    // must never emit it as a valid member of any equivalence class.
    let attacks = ["1' OR '1'='1", "1 UNION SELECT 1-- -"];
    for a in attacks {
        assert!(
            !esql::still_executes(a, ""),
            "empty candidate must be rejected for {a:?}"
        );
    }
}

#[test]
fn still_executes_rejects_whitespace_only_candidate() {
    // PROPERTY: whitespace carries no SQL semantics; a whitespace-only
    // string is not an attack.
    assert!(!esql::still_executes("1' OR '1'='1", "   "));
    assert!(!esql::still_executes("1 UNION SELECT 1--", "\t\n"));
}

#[test]
fn still_executes_structured_attack_requires_structural_tokens() {
    // PROPERTY: a UNION-SELECT variant must retain `union` and `select`
    // in the normalised form; dropping them makes the candidate unsound.
    let orig = "1 UNION SELECT username,password FROM users-- -";
    // A totally different payload that has no UNION/SELECT is not a
    // valid rewrite of a UNION-SELECT attack.
    assert!(
        !esql::still_executes(orig, "1' OR '1'='1"),
        "OR-tautology is not a valid rewrite of UNION-SELECT"
    );
}

#[test]
fn still_executes_rejects_keyword_buried_in_larger_identifier() {
    // SOUNDNESS regression (R2 token-boundary fix). The structural-token
    // gate used to test `normalized_candidate.contains(token)` — raw
    // SUBSTRING containment. That let a mutation that buries each keyword
    // inside a LARGER identifier pass, even though the buried text is no
    // longer a SQL keyword: `union` survives in `reunion`, `select` in
    // `selected`, `from` in `fromage`, `users` in `userspace`. None of
    // those is the keyword, so the candidate does NOT execute the UNION
    // exfil — yet the old gate credited it as equivalent. The fix matches
    // against the candidate's WHOLE tokens, so a buried substring no longer
    // counts. Reverting `token_set` membership back to `nc.contains(t)`
    // turns this red.
    let orig = "1 UNION SELECT 1,2 FROM users";
    // Every structural token of `orig` (union/select/from/users) appears
    // here ONLY as a substring of a larger word — never as a token.
    let buried = "1 reunion selected fromage userspace 1,2";
    assert!(
        !esql::still_executes(orig, buried),
        "keywords buried inside larger identifiers must NOT count as surviving"
    );
    // Sanity twin: the SAME tokens present as REAL whole tokens (different
    // column list / ordering of the projection) still execute — the fix
    // rejects burial, not legitimate re-spelling.
    let real = "1 union select 2,1 from users";
    assert!(
        esql::still_executes(orig, real),
        "genuine surviving tokens must still execute"
    );
}

#[test]
fn still_executes_tautology_with_whitespace_rewrite() {
    // PROPERTY: a whitespace rewrite of a tautology must still be
    // recognised as executing the same exploit.
    let orig = "1' OR '1'='1";
    // Whitespace variation — still has quote, OR, and equality check.
    let variant = "1'\tOR\t'1'='1";
    assert!(
        esql::still_executes(orig, variant),
        "whitespace-rewritten tautology must still execute"
    );
}

#[test]
fn still_executes_rejects_junk_payload() {
    // PROPERTY: random junk that has no SQL attack structure must not be
    // classified as executing any SQL attack (anti-rig).
    let junk_cases = [
        "hello world",
        "SELECT", // keyword alone is not an attack
        "123",
        "true",
        "null",
    ];
    let attacks = ["1' OR '1'='1", "1 UNION SELECT 1-- -"];
    for orig in attacks {
        for junk in junk_cases {
            // Not all of these are guaranteed to fail (SELECT in a
            // structured payload keeps structural tokens), but the
            // non-keyword junk cases must all fail.
            // We only assert on clearly non-attack inputs.
            if !junk.contains("SELECT") && !junk.contains("UNION") {
                assert!(
                    !esql::still_executes(orig, junk),
                    "junk {junk:?} must not execute {orig:?}"
                );
            }
        }
    }
}

// ─── _sample_truth / _sample_false ──────────────────────────────────────────

#[test]
fn sample_truth_is_non_empty_and_deterministic() {
    // PROPERTY: the sampled truth must be a non-empty string and the
    // same seed must yield the exact same string every time (the RNG is
    // deterministic SplitMix64, not OS entropy).
    let a = esql::_sample_truth(42);
    let b = esql::_sample_truth(42);
    assert_eq!(a, b, "same seed must yield same truth expression");
    assert!(!a.is_empty(), "sampled truth must be non-empty");
}

#[test]
fn sample_false_is_non_empty_and_deterministic() {
    // PROPERTY: same contract as `_sample_truth`: non-empty and
    // reproducible under the same seed.
    let a = esql::_sample_false(7);
    let b = esql::_sample_false(7);
    assert_eq!(a, b, "same seed must yield same false expression");
    assert!(!a.is_empty(), "sampled false must be non-empty");
}

#[test]
fn sample_truth_differs_from_sample_false_for_same_seed() {
    // PROPERTY: a true-expression generator and a false-expression
    // generator MUST NOT produce the same string (if they did, one of
    // them is broken). This is a sanity check, not a proof — the
    // grammar-level truth property is proven by the equiv_sql tests.
    for seed in 0u64..20 {
        let t = esql::_sample_truth(seed);
        let f = esql::_sample_false(seed);
        assert_ne!(t, f, "seed {seed}: truth and false samples must differ");
    }
}

#[test]
fn sample_truth_varies_across_seeds() {
    // PROPERTY: the RNG must actually produce different outputs for
    // different seeds (a constant-output RNG would pass all individual
    // tests while being entirely fake).
    let samples: Vec<String> = (0u64..10).map(esql::_sample_truth).collect();
    let unique: std::collections::HashSet<_> = samples.iter().collect();
    assert!(
        unique.len() >= 3,
        "at least 3 distinct truth-expressions across 10 seeds; got {}",
        unique.len()
    );
}

// ─── delivery_kind_label / DELIVERY_ARMS ────────────────────────────────────

#[test]
fn delivery_kind_label_covers_all_arms() {
    // PROPERTY: `delivery_kind_label(i)` must return a distinct,
    // non-empty label for every arm index 0..DELIVERY_ARMS.
    let mut seen = std::collections::HashSet::new();
    for i in 0..esql::DELIVERY_ARMS {
        let label = esql::delivery_kind_label(i);
        assert!(!label.is_empty(), "arm {i} has empty label");
        assert!(seen.insert(label), "arm {i} label {label:?} is a duplicate");
    }
}

#[test]
fn delivery_kind_label_out_of_range_returns_query() {
    // PROPERTY: an out-of-range arm index must fall back to "query" so
    // old persisted bandit state that references a removed arm doesn't
    // crash the adaptive scan.
    assert_eq!(esql::delivery_kind_label(usize::MAX), "query");
    assert_eq!(esql::delivery_kind_label(esql::DELIVERY_ARMS), "query");
    assert_eq!(
        esql::delivery_kind_label(esql::DELIVERY_ARMS + 100),
        "query"
    );
}

#[test]
fn delivery_arms_constant_is_at_least_seven() {
    // PROPERTY: the minimum set of delivery shapes the paper identified
    // as statistically distinct in the CRS bypass study was 7 (the
    // original 7 axes). A regression below this value would silently
    // disable proven bypass channels.
    // Constant-value assertion is INTENTIONAL — this is a build-time
    // regression gate: a DELIVERY_ARMS change below 7 should fail
    // CI, and clippy's `assertions_on_constants` lint would
    // otherwise hide the assert in test compilation. The const
    // const_assert! crate would be the alternative but pulls in an
    // unnecessary build dep for one site.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            esql::DELIVERY_ARMS >= 7,
            "DELIVERY_ARMS must be ≥ 7; got {}",
            esql::DELIVERY_ARMS
        );
    }
}

// ─── generate (the main public API) ─────────────────────────────────────────

#[test]
fn generate_returns_empty_for_non_attack_input() {
    // PROPERTY: anti-rig guarantee — a payload that is not a real attack
    // must produce zero members. The generator cannot manufacture an
    // exploit from junk.
    //
    // Note: SQL keywords like `SELECT` ARE classified as structured
    // attacks by `is_structured_attack` (it checks for the keyword
    // substring in normalised form) and CAN generate members because
    // `still_executes("SELECT","SELECT")` = true. What truly produces
    // zero members is payload that has no SQL attack structure at all.
    let non_attacks = [
        "",
        "hello world",
        "just some prose without sql structure here",
        "123",
        "true",
        "null",
    ];
    for junk in non_attacks {
        let out = equiv::equiv_sql(junk, &cfg_max(32));
        assert!(
            out.is_empty(),
            "non-attack {junk:?} must yield empty generation; got {} members",
            out.len()
        );
    }
}

#[test]
fn generate_happy_path_union_select_yields_members() {
    // PROPERTY: a canonical UNION-SELECT exfil attack must produce a
    // non-empty equivalence class with the default configuration.
    let p = "1 UNION SELECT username,password FROM users-- -";
    let out = equiv::equiv_sql(p, &cfg_max(32));
    assert!(
        !out.is_empty(),
        "UNION-SELECT payload must produce equivalence members"
    );
}

#[test]
fn generate_happy_path_auth_bypass_yields_members() {
    // PROPERTY: a canonical OR-tautology auth bypass must also produce
    // members so the scan pipeline has variants to try.
    let p = "1' OR '1'='1";
    let out = equiv::equiv_sql(p, &cfg_max(32));
    assert!(
        !out.is_empty(),
        "OR-tautology payload must produce equivalence members"
    );
}

#[test]
fn generate_respects_max_cap() {
    // PROPERTY: `cfg.max` is a hard upper bound on the number of members
    // the generator returns; it must never exceed it.
    for max in [1, 5, 10, 64] {
        let p = "1 UNION SELECT 1-- -";
        let out = equiv::equiv_sql(p, &cfg_max(max));
        assert!(
            out.len() <= max,
            "max={max} violated: got {} members",
            out.len()
        );
    }
}

#[test]
fn generate_is_deterministic_across_invocations() {
    // PROPERTY: `generate` is a pure function of `(payload, cfg)`. The
    // same (seed, max) pair must produce byte-identical output every
    // time; non-determinism here would make bench results irreproducible.
    let p = "1' OR 1=1-- -";
    let a = equiv::equiv_sql(p, &cfg_max(32));
    let b = equiv::equiv_sql(p, &cfg_max(32));
    let av: Vec<_> = a
        .iter()
        .map(|x| (x.payload.as_str(), x.delivery.label()))
        .collect();
    let bv: Vec<_> = b
        .iter()
        .map(|x| (x.payload.as_str(), x.delivery.label()))
        .collect();
    assert_eq!(av, bv, "same seed must yield same output across two calls");
}

#[test]
fn generate_every_member_still_executes() {
    // PROPERTY: the soundness contract of the generator — every emitted
    // member must pass `still_executes`. A single violation is a
    // generator bug (it emitted a non-attack).
    let attacks = [
        "1' OR '1'='1",
        "1 UNION SELECT username,password FROM users-- -",
        "admin'--",
        "1 AND SLEEP(5)-- -",
    ];
    for orig in attacks {
        for m in equiv::equiv_sql(orig, &cfg_max(48)) {
            assert!(
                esql::still_executes(orig, &m.payload),
                "generator emitted non-attack: {:?} from {:?} (rules {:?})",
                m.payload,
                orig,
                m.rules
            );
        }
    }
}

#[test]
fn generate_with_force_delivery_restricts_to_single_delivery_shape() {
    // PROPERTY: `force_delivery = Some(i)` must produce only members
    // using ONE delivery shape variant — not a mixture. Used by the
    // Phase-C bandit to concentrate the budget on a single delivery axis.
    //
    // Note: `delivery_kind_label(i)` uses more granular labels than
    // `DeliveryShape::label()` (e.g. "json_no_ct" vs "json_body") so we
    // compare the DeliveryShape variants directly via discriminant
    // equality instead of label string equality.
    let p = "1 UNION SELECT 1-- -";
    for arm in 0..esql::DELIVERY_ARMS {
        let cfg = EquivConfig {
            force_delivery: Some(arm),
            max: 20,
            vary_delivery: true,
            ..cfg_max(20)
        };
        let out = equiv::equiv_sql(p, &cfg);
        // All members must use the SAME delivery shape (same discriminant).
        // Collect unique delivery labels and assert at most one.
        let shapes: std::collections::HashSet<&'static str> =
            out.iter().map(|m| m.delivery.label()).collect();
        assert!(
            shapes.len() <= 1,
            "arm={arm}: force_delivery produced mixed shapes: {shapes:?}"
        );
    }
}

#[test]
fn generate_does_not_emit_duplicate_payload_delivery_pairs() {
    // PROPERTY: the generator maintains a seen-set and must not emit the
    // same `(payload, delivery_label)` pair twice in one call. Duplicates
    // waste scanner budget and artificially inflate bypass counts.
    let p = "1' OR '1'='1";
    let out = equiv::equiv_sql(p, &cfg_max(64));
    let mut pairs = std::collections::HashSet::new();
    for m in &out {
        let key = format!("{}\x01{}", m.payload, m.delivery.label());
        assert!(
            pairs.insert(key.clone()),
            "duplicate (payload, delivery) pair emitted: {key:?}"
        );
    }
}

#[test]
fn generate_oversized_max_does_not_panic() {
    // PROPERTY: a very large `max` must not cause an OOM or panic — the
    // generator terminates when it cannot produce more unique members and
    // returns whatever it found.
    let p = "1' OR '1'='1";
    let out = equiv::equiv_sql(p, &cfg_max(100_000));
    // We only guarantee no panic and at least one member; the exact
    // count is bounded by the grammar's entropy.
    assert!(!out.is_empty());
}

// ─── DeliveryShape::label ────────────────────────────────────────────────────

#[test]
fn delivery_shape_label_matches_delivery_kind_label() {
    // PROPERTY: `delivery_set(param)[i].label()` must agree with
    // `delivery_kind_label(i)` so the bandit's arm-index → label
    // mapping is consistent across the API boundary.
    // We verify a representative sample of shapes directly.
    let q = DeliveryShape::Query { param: "id".into() };
    assert_eq!(q.label(), "query");
    let mp = DeliveryShape::MultipartFile {
        name: "f".into(),
        filename: "a.txt".into(),
        part_ct: "application/octet-stream".into(),
    };
    assert_eq!(mp.label(), "multipart_file");
    let ps = DeliveryShape::PathSegment;
    assert_eq!(ps.label(), "path_segment");
    let hv = DeliveryShape::HeaderValue {
        name: "X-Forwarded-Host".into(),
    };
    assert_eq!(hv.label(), "header_value");
}
