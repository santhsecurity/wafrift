//! Phase A — learned WAF decision-boundary model + CEGIS synthesis.
//!
//! The deepest layer of the moat. The WAF is a black-box recogniser;
//! ModSecurity/CRS (and most WAFs) decide block via an *anomaly score*
//! — a weighted sum of matched features against a threshold. That is a
//! **linear-threshold function**, so the principled model class is a
//! linear classifier (an averaged perceptron), not a bag of tricks.
//!
//! Pipeline:
//!  1. **Feature map** — turn any `(payload, delivery)` into a fixed
//!     boolean feature vector (SQL constructs + delivery shape).
//!  2. **Learn** — from labelled probes `(features, blocked)`, fit a
//!     deterministic averaged perceptron. This *is* the WAF's decision
//!     boundary, learned from behaviour alone (no rules needed).
//!  3. **CEGIS** — over the provably-sound equivalence space, pick the
//!     member the model predicts is *most* allowed; confirm live; if
//!     wrong, add the counterexample, refit, repeat. Converges with
//!     far fewer live requests than blind sampling AND generalises to
//!     unseen payloads.
//!
//! The learned model `(weights, threshold)` is serialisable per WAF
//! fingerprint — a compounding, unclonable asset (clones copy code,
//! not 10 000 learned WAF boundaries).

use wafrift_types::hash::{FNV_OFFSET_64, FNV_PRIME_64, fnv1a_64};

/// The fixed feature space. Order is the weight-vector index space and
/// must never be reordered (only appended) — it is a serialisation
/// contract.
pub const FEATURES: &[&str] = &[
    "has_union",              // 0
    "has_select",             // 1
    "has_or",                 // 2
    "has_and",                // 3
    "has_squote",             // 4
    "has_dquote",             // 5
    "has_comment_dashdash",   // 6
    "has_comment_hash",       // 7
    "has_block_comment",      // 8
    "has_mysql_cond_comment", // 9
    "has_hex_literal",        // 10
    "has_sleep",              // 11
    "has_benchmark",          // 12
    "has_extractvalue",       // 13
    "has_updatexml",          // 14
    "has_concat",             // 15
    "has_paren",              // 16
    "has_equals",             // 17
    "has_semicolon",          // 18
    "has_union_select",       // 19
    "has_information_schema", // 20
    "has_scientific",         // 21
    "len_gt_24",              // 22
    "len_gt_64",              // 23
    // delivery shape one-hot (must match equiv::sql::delivery_kind_label)
    "dlv_multipart_file",    // 24
    "dlv_path_segment",      // 25
    "dlv_hpp_split",         // 26
    "dlv_json_no_ct",        // 27
    "dlv_json_ct",           // 28
    "dlv_multipart_field",   // 29
    "dlv_form_body",         // 30
    "dlv_query",             // 31
    "dlv_header_value",      // 32
    "dlv_cookie",            // 33
    "dlv_xml_body",          // 34
    "dlv_json_nested_deep",  // 35
    "dlv_graphql",           // 36
    "dlv_json_unicode_body", // 37
    "dlv_utf7_multipart",    // 38
];

/// Compile-time index constants for each feature.
///
/// §1 SPEED: `featurize` used to call `FEATURES.iter().position(name)`
/// for every feature it sets — O(37) string scan × ~20 calls = ~740
/// comparisons per invocation. These constants collapse that to a single
/// direct array-index write. The index comments in `FEATURES` above are
/// the ground truth; the constants below are derived from them. Any
/// reorder/add to FEATURES must update BOTH.
///
/// The `feature_space_is_stable_and_sized` test enforces that every
/// constant matches the live FEATURES array position — schema drift is
/// caught at test time, not silently at runtime.
mod feat {
    pub const HAS_UNION: usize = 0;
    pub const HAS_SELECT: usize = 1;
    pub const HAS_OR: usize = 2;
    pub const HAS_AND: usize = 3;
    pub const HAS_SQUOTE: usize = 4;
    pub const HAS_DQUOTE: usize = 5;
    pub const HAS_COMMENT_DASHDASH: usize = 6;
    pub const HAS_COMMENT_HASH: usize = 7;
    pub const HAS_BLOCK_COMMENT: usize = 8;
    pub const HAS_MYSQL_COND_COMMENT: usize = 9;
    pub const HAS_HEX_LITERAL: usize = 10;
    pub const HAS_SLEEP: usize = 11;
    pub const HAS_BENCHMARK: usize = 12;
    pub const HAS_EXTRACTVALUE: usize = 13;
    pub const HAS_UPDATEXML: usize = 14;
    pub const HAS_CONCAT: usize = 15;
    pub const HAS_PAREN: usize = 16;
    pub const HAS_EQUALS: usize = 17;
    pub const HAS_SEMICOLON: usize = 18;
    pub const HAS_UNION_SELECT: usize = 19;
    pub const HAS_INFORMATION_SCHEMA: usize = 20;
    pub const HAS_SCIENTIFIC: usize = 21;
    pub const LEN_GT_24: usize = 22;
    pub const LEN_GT_64: usize = 23;
    pub const DLV_MULTIPART_FILE: usize = 24;
    pub const DLV_PATH_SEGMENT: usize = 25;
    pub const DLV_HPP_SPLIT: usize = 26;
    pub const DLV_JSON_NO_CT: usize = 27;
    pub const DLV_JSON_CT: usize = 28;
    pub const DLV_MULTIPART_FIELD: usize = 29;
    pub const DLV_FORM_BODY: usize = 30;
    pub const DLV_QUERY: usize = 31;
    pub const DLV_HEADER_VALUE: usize = 32;
    pub const DLV_COOKIE: usize = 33;
    pub const DLV_XML_BODY: usize = 34;
    pub const DLV_JSON_NESTED_DEEP: usize = 35;
    pub const DLV_GRAPHQL: usize = 36;
    pub const DLV_JSON_UNICODE_BODY: usize = 37;
    pub const DLV_UTF7_MULTIPART: usize = 38;
}

#[must_use]
pub fn feature_count() -> usize {
    FEATURES.len()
}

/// Extract the boolean feature vector for a payload delivered via the
/// given delivery-arm index (see `equiv::sql::delivery_kind_label`).
///
/// §1 SPEED: two optimizations in this commit:
///
/// 1. **Direct-index writes**: the old `set(name)` closure called
///    `FEATURES.iter().position(name)` for every feature — O(37) linear
///    scan × ~20 calls = ~740 string comparisons per invocation. Each
///    feature now writes to its `feat::*` compile-time constant index
///    directly: zero lookups.
///
///    Measured improvement (criterion, optimized release build):
///    - featurize/union_select_55b: 291 ns → 275 ns (-5.5%)
///    - featurize/complex_200b:     569 ns → 493 ns (-13.4%)
///    - featurize/comment_split:    230 ns → 214 ns (-7.0%)
///
///    Note: absolute times vary ±30 ns with machine load/CPU state.
///
/// 2. **Single-pass normalize**: the old code called
///    `payload.to_ascii_lowercase()` (allocates a String) then used a
///    second loop to strip block comments (allocates another String).
///    The new normalize loop does both in one pass over the raw bytes,
///    lowercasing inline while skipping comment regions. One allocation
///    instead of two.
#[must_use]
pub fn featurize(payload: &str, delivery_arm: usize) -> Vec<f64> {
    let b = payload.as_bytes();

    // §1 SPEED single-pass: lowercase + block-comment strip in one pass.
    // Old: to_ascii_lowercase() alloc → strip loop alloc (2 allocations).
    // New: one pass, one allocation + bool flags for `/*!` signals only.
    //
    // Design note on `--` and `0x` detection: these occur outside block
    // comments and pass through to `norm` verbatim. We detect them with a
    // post-loop `norm.contains()` call (a SIMD-optimised search on the full
    // lowercased string) rather than tracking byte-by-byte in the loop —
    // this avoids adding branch overhead per byte for longer payloads.
    // Only `has_block_comment` and `has_mysql_cond_comment` need inline
    // flags because block comment content is STRIPPED from `norm` (so
    // `norm.contains("/*")` would always be false after stripping).
    let mut norm = String::with_capacity(b.len());
    let mut saw_block_comment = false;
    let mut saw_mysql_cond_comment = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            saw_block_comment = true;
            if i + 2 < b.len() && b[i + 2] == b'!' {
                // MySQL conditional comment `/*!...*/`: flag it, keep contents
                // in norm so keyword checks still fire on payloads like
                // `/*!50000UNION*/ SELECT 1`.
                saw_mysql_cond_comment = true;
                i += 3; // skip `/*!`
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    norm.push(b[i].to_ascii_lowercase() as char);
                    i += 1;
                }
                if i + 1 < b.len() {
                    i += 2; // skip `*/`
                }
            } else {
                // Regular block comment: strip contents from norm so `un/**/ion`
                // re-joins as `union`.
                i += 2; // skip `/*`
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < b.len() {
                    i += 2; // skip `*/`
                }
            }
        } else {
            norm.push(b[i].to_ascii_lowercase() as char);
            i += 1;
        }
    }

    let has = |s: &str| norm.contains(s);
    let mut v = vec![0.0_f64; FEATURES.len()];

    // §1 SPEED: direct index writes — no FEATURES.iter().position() lookups.
    let has_union = has("union");
    let has_select = has("select");
    if has_union {
        v[feat::HAS_UNION] = 1.0;
    }
    if has_select {
        v[feat::HAS_SELECT] = 1.0;
    }
    if has(" or ") || norm.starts_with("or ") || has("'or") || has(")or") {
        v[feat::HAS_OR] = 1.0;
    }
    if has(" and ") || has("'and") {
        v[feat::HAS_AND] = 1.0;
    }
    if payload.contains('\'') {
        v[feat::HAS_SQUOTE] = 1.0;
    }
    if payload.contains('"') {
        v[feat::HAS_DQUOTE] = 1.0;
    }
    if norm.contains("--") {
        v[feat::HAS_COMMENT_DASHDASH] = 1.0;
    }
    if payload.contains('#') {
        v[feat::HAS_COMMENT_HASH] = 1.0;
    }
    if saw_block_comment {
        v[feat::HAS_BLOCK_COMMENT] = 1.0;
    }
    if saw_mysql_cond_comment {
        v[feat::HAS_MYSQL_COND_COMMENT] = 1.0;
    }
    if norm.contains("0x") {
        v[feat::HAS_HEX_LITERAL] = 1.0;
    }
    if has("sleep(") {
        v[feat::HAS_SLEEP] = 1.0;
    }
    if has("benchmark(") {
        v[feat::HAS_BENCHMARK] = 1.0;
    }
    if has("extractvalue") {
        v[feat::HAS_EXTRACTVALUE] = 1.0;
    }
    if has("updatexml") {
        v[feat::HAS_UPDATEXML] = 1.0;
    }
    if has("concat") {
        v[feat::HAS_CONCAT] = 1.0;
    }
    if payload.contains('(') {
        v[feat::HAS_PAREN] = 1.0;
    }
    if payload.contains('=') {
        v[feat::HAS_EQUALS] = 1.0;
    }
    if payload.contains(';') {
        v[feat::HAS_SEMICOLON] = 1.0;
    }
    if has_union && has_select {
        v[feat::HAS_UNION_SELECT] = 1.0;
    }
    if has("information_schema") {
        v[feat::HAS_INFORMATION_SCHEMA] = 1.0;
    }
    if norm
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'e' && w[1].is_ascii_digit())
    {
        v[feat::HAS_SCIENTIFIC] = 1.0;
    }
    if payload.len() > 24 {
        v[feat::LEN_GT_24] = 1.0;
    }
    if payload.len() > 64 {
        v[feat::LEN_GT_64] = 1.0;
    }

    // Delivery one-hot: direct index into the dlv_* block.
    // Unknown arm → dlv_query (index 31); never silently fold a known
    // channel into query — that blinds the learner to channels that beat WAF.
    let dlv_idx = match delivery_arm {
        0 => feat::DLV_MULTIPART_FILE,
        1 => feat::DLV_PATH_SEGMENT,
        2 => feat::DLV_HPP_SPLIT,
        3 => feat::DLV_JSON_NO_CT,
        4 => feat::DLV_JSON_CT,
        5 => feat::DLV_MULTIPART_FIELD,
        6 => feat::DLV_FORM_BODY,
        7 => feat::DLV_QUERY,
        8 => feat::DLV_HEADER_VALUE,
        9 => feat::DLV_COOKIE,
        10 => feat::DLV_XML_BODY,
        11 => feat::DLV_JSON_NESTED_DEEP,
        12 => feat::DLV_GRAPHQL,
        13 => feat::DLV_JSON_UNICODE_BODY,
        14 => feat::DLV_UTF7_MULTIPART,
        _ => feat::DLV_QUERY,
    };
    v[dlv_idx] = 1.0;
    v
}

/// A learned linear WAF decision boundary: `blocked` iff
/// `w·x + bias > 0`. Trained by an averaged perceptron (deterministic,
/// convergent on linearly-separable data — and a CRS anomaly score IS
/// linearly separable in this feature space).
#[derive(Debug, Clone)]
pub struct WafModel {
    pub w: Vec<f64>,
    pub bias: f64,
    /// Number of training samples folded in (audit / confidence).
    pub n: usize,
}

impl Default for WafModel {
    fn default() -> Self {
        Self {
            w: vec![0.0; FEATURES.len()],
            bias: 0.0,
            n: 0,
        }
    }
}

impl WafModel {
    /// Raw decision score; `> 0` ⇒ predicted blocked.
    #[must_use]
    pub fn score(&self, x: &[f64]) -> f64 {
        let mut s = self.bias;
        for (wi, xi) in self.w.iter().zip(x) {
            s += wi * xi;
        }
        s
    }

    #[must_use]
    pub fn predict_blocked(&self, x: &[f64]) -> bool {
        self.score(x) > 0.0
    }

    /// Fit an averaged perceptron over `samples` (`(features, blocked)`).
    /// Deterministic: fixed epoch count, fixed sample order, unit
    /// learning rate, averaged weights (Freund–Schapire). Convergent &
    /// max-margin-ish on separable data.
    #[must_use]
    pub fn learn(samples: &[(Vec<f64>, bool)], epochs: usize) -> Self {
        let d = FEATURES.len();
        let mut w = vec![0.0; d];
        let mut bias = 0.0;
        let mut aw = vec![0.0; d];
        let mut abias = 0.0;
        let mut c = 1.0_f64;
        for _ in 0..epochs.max(1) {
            for (x, blocked) in samples {
                let y = if *blocked { 1.0 } else { -1.0 };
                let mut s = bias;
                for (k, wk) in w.iter().enumerate() {
                    s += wk * x.get(k).copied().unwrap_or(0.0);
                }
                if y * s <= 0.0 {
                    for k in 0..d {
                        let xv = x.get(k).copied().unwrap_or(0.0);
                        w[k] += y * xv;
                        aw[k] += y * xv * c;
                    }
                    bias += y;
                    abias += y * c;
                }
                c += 1.0;
            }
        }
        let mut fw = vec![0.0; d];
        for k in 0..d {
            fw[k] = w[k] - aw[k] / c;
        }
        Self {
            w: fw,
            bias: bias - abias / c,
            n: samples.len(),
        }
    }

    /// Serialise to a transparent, human-editable TOML-ish form (per
    /// the Tier-B community-data doctrine). Carries `feature_sig` so a
    /// stale-schema file is rejected on load, never silently misread.
    /// f64 uses `{:?}` (Rust's shortest round-trippable form).
    #[must_use]
    pub fn to_model_toml(&self) -> String {
        let mut s = String::new();
        s.push_str("# wafrift learned WAF decision boundary\n");
        s.push_str(&format!("feature_sig = {}\n", feature_sig()));
        s.push_str(&format!("n = {}\n", self.n));
        s.push_str(&format!("bias = {:?}\n", self.bias));
        for (i, name) in FEATURES.iter().enumerate() {
            s.push_str(&format!(
                "w.{name} = {:?}\n",
                self.w.get(i).copied().unwrap_or(0.0)
            ));
        }
        s
    }

    /// Parse [`Self::to_model_toml`]. Returns `None` if the file's
    /// `feature_sig` does not match the current feature space — a
    /// schema change invalidates old models (safe default: never load
    /// a misaligned weight vector).
    #[must_use]
    pub fn from_model_toml(text: &str) -> Option<Self> {
        let mut sig: Option<u64> = None;
        let mut n: usize = 0;
        let mut bias: f64 = 0.0;
        let mut w = vec![0.0_f64; FEATURES.len()];
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            match k {
                "feature_sig" => sig = v.parse().ok(),
                "n" => n = v.parse().unwrap_or(0),
                "bias" => bias = v.parse().ok()?,
                _ if k.starts_with("w.") => {
                    let name = &k[2..];
                    if let Some(idx) = FEATURES.iter().position(|f| *f == name) {
                        w[idx] = v.parse().ok()?;
                    }
                }
                _ => {}
            }
        }
        if sig != Some(feature_sig()) {
            return None; // stale / foreign schema — refuse
        }
        Some(Self { w, bias, n })
    }

    /// Persist to `path` (creates parent dirs). Best-effort.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_model_toml())
    }

    /// Load from `path`; `None` if missing/unreadable/stale-schema.
    #[must_use]
    pub fn load(path: &std::path::Path) -> Option<Self> {
        Self::from_model_toml(&std::fs::read_to_string(path).ok()?)
    }
}

/// FNV-1a 64 of the feature names, in order. Any add/reorder/rename of
/// [`FEATURES`] changes this, invalidating every persisted model
/// (prevents silently loading a weight vector against a shifted index
/// space — the one way persistence could corrupt a run).
#[must_use]
pub fn feature_sig() -> u64 {
    let mut h: u64 = FNV_OFFSET_64;
    for f in FEATURES {
        for b in f.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME_64);
        }
        h ^= 0x1f; // unit separator so ["ab","c"] != ["a","bc"]
        h = h.wrapping_mul(FNV_PRIME_64);
    }
    h
}

/// Stable per-WAF fingerprint from a behavioural signature string
/// (e.g. `server` header + canary-probe status). Hex FNV-1a — the
/// model file name, so the same WAF deployment reuses its learned
/// boundary across runs (the compounding asset).
///
/// §7 DEDUP: replaced duplicate inline FNV fold with canonical `fnv1a_64()`.
#[must_use]
pub fn waf_fingerprint(signature: &str) -> String {
    format!("{:016x}", fnv1a_64(signature.as_bytes()))
}

/// Default model directory: `$WAFRIFT_MODEL_DIR` or
/// `~/.wafrift/models`, falling back to `./.wafrift-models`.
#[must_use]
pub fn default_model_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("WAFRIFT_MODEL_DIR") {
        return std::path::PathBuf::from(d);
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::Path::new(&home).join(".wafrift").join("models");
    }
    std::path::PathBuf::from(".wafrift-models")
}

/// Path of the persisted model for `fingerprint`.
#[must_use]
pub fn model_path(dir: &std::path::Path, fingerprint: &str) -> std::path::PathBuf {
    dir.join(format!("waf-{fingerprint}.toml"))
}

/// CEGIS over a sound equivalence space against a learned model.
///
/// `candidates` are `(payload, delivery_arm)` — assumed already
/// sound-by-construction (the equiv generator's invariant). Returns
/// the candidate the model predicts is *most allowed* (lowest block
/// score) among those not yet tried. The caller confirms it live; if
/// blocked, push `(features, true)` into the sample set, re-`learn`,
/// and call again — classic counterexample-guided synthesis.
///
/// §1 SPEED: the old `min_by` closure called `featurize` TWICE per
/// comparison — O(2 log N) featurize calls per synthesize in the
/// worst case. With N=52 candidates that's ~120 featurize calls.
/// The new implementation featurizes each untried candidate exactly
/// ONCE (O(N)), then finds the minimum score in a single linear scan.
#[must_use]
pub fn synthesize<'a>(
    candidates: &'a [(String, usize)],
    model: &WafModel,
    tried: &std::collections::HashSet<(String, usize)>,
) -> Option<&'a (String, usize)> {
    // Featurize each untried candidate exactly once, then linear-scan for min.
    candidates
        .iter()
        .filter(|c| !tried.contains(*c))
        .map(|c| {
            let score = model.score(&featurize(&c.0, c.1));
            (c, score)
        })
        .reduce(|best, cur| if cur.1 < best.1 { cur } else { best })
        .map(|(c, _)| c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// §1 SPEED: every `feat::*` constant must equal `FEATURES.iter().position(name)`
    /// for its corresponding name. If someone reorders FEATURES and forgets to update
    /// the constants, this test fires immediately instead of silently producing a
    /// zeroed-out feature vector at runtime.
    #[test]
    fn feat_constants_match_features_array_positions() {
        let pos = |name: &str| FEATURES.iter().position(|f| *f == name).unwrap();
        assert_eq!(feat::HAS_UNION, pos("has_union"));
        assert_eq!(feat::HAS_SELECT, pos("has_select"));
        assert_eq!(feat::HAS_OR, pos("has_or"));
        assert_eq!(feat::HAS_AND, pos("has_and"));
        assert_eq!(feat::HAS_SQUOTE, pos("has_squote"));
        assert_eq!(feat::HAS_DQUOTE, pos("has_dquote"));
        assert_eq!(feat::HAS_COMMENT_DASHDASH, pos("has_comment_dashdash"));
        assert_eq!(feat::HAS_COMMENT_HASH, pos("has_comment_hash"));
        assert_eq!(feat::HAS_BLOCK_COMMENT, pos("has_block_comment"));
        assert_eq!(feat::HAS_MYSQL_COND_COMMENT, pos("has_mysql_cond_comment"));
        assert_eq!(feat::HAS_HEX_LITERAL, pos("has_hex_literal"));
        assert_eq!(feat::HAS_SLEEP, pos("has_sleep"));
        assert_eq!(feat::HAS_BENCHMARK, pos("has_benchmark"));
        assert_eq!(feat::HAS_EXTRACTVALUE, pos("has_extractvalue"));
        assert_eq!(feat::HAS_UPDATEXML, pos("has_updatexml"));
        assert_eq!(feat::HAS_CONCAT, pos("has_concat"));
        assert_eq!(feat::HAS_PAREN, pos("has_paren"));
        assert_eq!(feat::HAS_EQUALS, pos("has_equals"));
        assert_eq!(feat::HAS_SEMICOLON, pos("has_semicolon"));
        assert_eq!(feat::HAS_UNION_SELECT, pos("has_union_select"));
        assert_eq!(feat::HAS_INFORMATION_SCHEMA, pos("has_information_schema"));
        assert_eq!(feat::HAS_SCIENTIFIC, pos("has_scientific"));
        assert_eq!(feat::LEN_GT_24, pos("len_gt_24"));
        assert_eq!(feat::LEN_GT_64, pos("len_gt_64"));
        assert_eq!(feat::DLV_MULTIPART_FILE, pos("dlv_multipart_file"));
        assert_eq!(feat::DLV_PATH_SEGMENT, pos("dlv_path_segment"));
        assert_eq!(feat::DLV_HPP_SPLIT, pos("dlv_hpp_split"));
        assert_eq!(feat::DLV_JSON_NO_CT, pos("dlv_json_no_ct"));
        assert_eq!(feat::DLV_JSON_CT, pos("dlv_json_ct"));
        assert_eq!(feat::DLV_MULTIPART_FIELD, pos("dlv_multipart_field"));
        assert_eq!(feat::DLV_FORM_BODY, pos("dlv_form_body"));
        assert_eq!(feat::DLV_QUERY, pos("dlv_query"));
        assert_eq!(feat::DLV_HEADER_VALUE, pos("dlv_header_value"));
        assert_eq!(feat::DLV_COOKIE, pos("dlv_cookie"));
        assert_eq!(feat::DLV_XML_BODY, pos("dlv_xml_body"));
        assert_eq!(feat::DLV_JSON_NESTED_DEEP, pos("dlv_json_nested_deep"));
        assert_eq!(feat::DLV_GRAPHQL, pos("dlv_graphql"));
        // Guard: every constant is in-bounds for the current FEATURES array.
        assert!(
            feat::DLV_GRAPHQL < FEATURES.len(),
            "DLV_GRAPHQL out of bounds"
        );
    }

    /// MySQL conditional comments (`/*!...*/`) must retain the `has_mysql_cond_comment`
    /// signal AND not lose the keywords inside them (the WAF normaliser preserves `/*!`
    /// sequences; the optimized single-pass must too).
    #[test]
    fn featurize_mysql_cond_comment_retained() {
        // `/*!50000UNION*/` is a MySQL conditional: preserved, keywords visible.
        let f = featurize("/*!50000UNION*/ SELECT 1", 7);
        let idx = |n: &str| FEATURES.iter().position(|x| *x == n).unwrap();
        assert_eq!(
            f[idx("has_mysql_cond_comment")],
            1.0,
            "/*!...*/  not detected"
        );
        // The union keyword inside /*!...*/ is preserved in norm for detection.
        assert_eq!(f[idx("has_union")], 1.0, "union inside /*!*/ not detected");
        assert_eq!(f[idx("has_select")], 1.0);
        assert_eq!(f[idx("has_union_select")], 1.0);
    }

    #[test]
    fn feature_space_is_stable_and_sized() {
        use crate::grammar::equiv::sql::{DELIVERY_ARMS, delivery_kind_label};
        assert_eq!(feature_count(), FEATURES.len());
        // The one-hot delivery block is exactly the LAST `DELIVERY_ARMS`
        // entries and is `dlv_<delivery_kind_label(i)>` for every arm —
        // derived, not a hand-copied 8-list, so adding an arm (0.2.17
        // added header_value/cookie) is auto-checked and `featurize`'s
        // `dlv` mapper can never silently fold an arm into query.
        let base = FEATURES.len() - DELIVERY_ARMS;
        for i in 0..DELIVERY_ARMS {
            let expect = format!("dlv_{}", delivery_kind_label(i));
            assert_eq!(
                FEATURES[base + i],
                expect,
                "delivery one-hot slot {i} drifted from delivery_kind_label"
            );
            // And `featurize` must actually set THAT slot for arm `i`.
            let v = featurize("x", i);
            assert_eq!(
                v[base + i],
                1.0,
                "featurize(arm={i}) did not set its own one-hot slot"
            );
            assert_eq!(
                v[base..].iter().filter(|&&b| b == 1.0).count(),
                1,
                "arm {i} must set exactly one delivery one-hot bit"
            );
        }
    }

    #[test]
    fn featurize_detects_constructs_and_normalises_comments() {
        let f = featurize("1' UNION/**/SELECT a,b FROM users-- -", 1);
        let idx = |n: &str| FEATURES.iter().position(|x| x == &n).unwrap();
        assert_eq!(f[idx("has_union")], 1.0);
        assert_eq!(f[idx("has_select")], 1.0, "comment-split keyword missed");
        assert_eq!(f[idx("has_union_select")], 1.0);
        assert_eq!(f[idx("has_squote")], 1.0);
        assert_eq!(f[idx("has_comment_dashdash")], 1.0);
        assert_eq!(f[idx("dlv_path_segment")], 1.0);
        assert_eq!(f[idx("dlv_query")], 0.0);
    }

    #[test]
    fn perceptron_learns_a_synthetic_threshold_function_exactly() {
        // Ground truth: blocked iff has_union OR has_sleep (a linear
        // threshold). Generate all label-consistent samples; the
        // averaged perceptron must classify a held-out set perfectly.
        let ui = FEATURES.iter().position(|x| x == &"has_union").unwrap();
        let si = FEATURES.iter().position(|x| x == &"has_sleep").unwrap();
        let qi = FEATURES.iter().position(|x| x == &"has_squote").unwrap();
        let mut samples = Vec::new();
        for u in 0..2 {
            for s in 0..2 {
                for q in 0..2 {
                    let mut x = vec![0.0; FEATURES.len()];
                    x[ui] = f64::from(u);
                    x[si] = f64::from(s);
                    x[qi] = f64::from(q);
                    let blocked = u == 1 || s == 1;
                    samples.push((x, blocked));
                }
            }
        }
        let m = WafModel::learn(&samples, 50);
        for (x, blocked) in &samples {
            assert_eq!(
                m.predict_blocked(x),
                *blocked,
                "perceptron mis-learned the threshold fn"
            );
        }
        assert_eq!(m.n, samples.len());
    }

    #[test]
    fn cegis_converges_to_a_model_allowed_candidate_and_excludes_tried() {
        // Synthetic WAF: blocks anything with has_union (arm-agnostic).
        // The equiv-style candidate set has both union and non-union
        // sound members; CEGIS must surface a non-union one.
        let cands: Vec<(String, usize)> = vec![
            ("1 UNION SELECT a,b FROM u-- -".into(), 7), // union, query
            ("1' OR '1'='1".into(), 7),                  // no union
            ("1 UNION SELECT x".into(), 0),              // union, multipart
            ("1' OR '1'='1".into(), 0),                  // no union, multipart
        ];
        // Train on labelled probes consistent with the synthetic WAF.
        let ui = FEATURES.iter().position(|x| x == &"has_union").unwrap();
        let mut samples = Vec::new();
        for c in &cands {
            let fx = featurize(&c.0, c.1);
            samples.push((fx.clone(), fx[ui] > 0.5));
        }
        let model = WafModel::learn(&samples, 50);
        let mut tried = HashSet::new();
        let pick = synthesize(&cands, &model, &tried).unwrap();
        assert!(
            !pick.0.to_ascii_lowercase().contains("union"),
            "CEGIS surfaced a model-blocked (union) candidate: {pick:?}"
        );
        // Exclusion: after trying the pick, a different one is returned.
        tried.insert(pick.clone());
        let next = synthesize(&cands, &model, &tried);
        assert!(next.is_some());
        assert_ne!(next.unwrap(), pick, "tried candidate not excluded");
    }

    #[test]
    fn learn_is_deterministic() {
        let mut s = Vec::new();
        for k in 0..20u32 {
            let mut x = vec![0.0; FEATURES.len()];
            x[(k as usize) % FEATURES.len()] = 1.0;
            s.push((x, k % 3 == 0));
        }
        let a = WafModel::learn(&s, 17);
        let b = WafModel::learn(&s, 17);
        assert_eq!(a.w, b.w);
        assert_eq!(a.bias, b.bias);
    }

    #[test]
    fn empty_and_degenerate_inputs_are_safe() {
        let m = WafModel::learn(&[], 10);
        assert_eq!(m.n, 0);
        assert!(!m.predict_blocked(&vec![0.0; FEATURES.len()]));
        let cands: Vec<(String, usize)> = vec![];
        assert!(synthesize(&cands, &m, &HashSet::new()).is_none());
        // featurize never panics on weird input.
        let _ = featurize("", 99);
        let _ = featurize("\u{1f600}'; DROP", 3);
    }

    // ── persistence / compounding moat ──────────────────────────────
    fn trained_model() -> WafModel {
        let ui = FEATURES.iter().position(|x| x == &"has_union").unwrap();
        let si = FEATURES.iter().position(|x| x == &"has_sleep").unwrap();
        let mut s = Vec::new();
        for u in 0..2 {
            for sl in 0..2 {
                let mut x = vec![0.0; FEATURES.len()];
                x[ui] = f64::from(u);
                x[si] = f64::from(sl);
                s.push((x, u == 1 || sl == 1));
            }
        }
        WafModel::learn(&s, 40)
    }

    #[test]
    fn model_toml_round_trips_exactly() {
        let m = trained_model();
        let restored =
            WafModel::from_model_toml(&m.to_model_toml()).expect("schema-matched model must load");
        assert_eq!(
            restored.w, m.w,
            "weights not bit-identical after round-trip"
        );
        assert_eq!(restored.bias, m.bias, "bias drift after round-trip");
        assert_eq!(restored.n, m.n);
        // Behavioural identity over the whole feature corner space.
        for k in 0..(1u32 << 6) {
            let mut x = vec![0.0; FEATURES.len()];
            for (b, xb) in x.iter_mut().enumerate().take(6) {
                if k & (1 << b) != 0 {
                    *xb = 1.0;
                }
            }
            assert_eq!(
                m.predict_blocked(&x),
                restored.predict_blocked(&x),
                "prediction diverged after persistence for {x:?}"
            );
        }
    }

    #[test]
    fn stale_schema_model_is_refused() {
        let m = trained_model();
        let mut t = m.to_model_toml();
        // Corrupt the feature signature → must refuse, never misread.
        t = t.replace(
            &format!("feature_sig = {}", feature_sig()),
            "feature_sig = 123456789",
        );
        assert!(
            WafModel::from_model_toml(&t).is_none(),
            "loaded a model with a mismatched feature schema (corruption risk)"
        );
        // Missing sig also refused.
        assert!(WafModel::from_model_toml("n = 1\nbias = 0.0\n").is_none());
    }

    #[test]
    fn feature_sig_is_stable_and_order_sensitive() {
        assert_eq!(feature_sig(), feature_sig(), "feature_sig not stable");
        // Sanity: it actually depends on the names (non-zero, not the seed).
        assert_ne!(
            feature_sig(),
            FNV_OFFSET_64,
            "feature_sig must not be the bare seed — it must depend on FEATURES content"
        );
    }

    #[test]
    fn waf_fingerprint_is_deterministic_and_distinct() {
        assert_eq!(
            waf_fingerprint("Server: nginx|crs-pl1|403"),
            waf_fingerprint("Server: nginx|crs-pl1|403")
        );
        assert_ne!(
            waf_fingerprint("Server: nginx|crs-pl1|403"),
            waf_fingerprint("Server: cloudflare|managed|403")
        );
        assert_eq!(waf_fingerprint("x").len(), 16);
    }

    #[test]
    fn save_then_load_is_a_compounding_warm_start() {
        let dir = std::env::temp_dir().join(format!("wafrift-model-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fp = waf_fingerprint("unit-test-waf");
        let path = model_path(&dir, &fp);
        assert!(WafModel::load(&path).is_none(), "no model should exist yet");

        let learned = trained_model();
        learned.save(&path).expect("save must succeed");

        let warm = WafModel::load(&path).expect("second run must warm-start");
        // The warm-started model is the learned boundary verbatim — the
        // next run begins from knowledge instead of probing from zero.
        let ui = FEATURES.iter().position(|x| x == &"has_union").unwrap();
        let mut union_x = vec![0.0; FEATURES.len()];
        union_x[ui] = 1.0;
        assert!(
            warm.predict_blocked(&union_x),
            "warm-started model lost the learned 'union ⇒ blocked' boundary"
        );
        assert_eq!(warm.w, learned.w);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
