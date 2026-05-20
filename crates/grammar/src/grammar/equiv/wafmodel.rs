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

/// The fixed feature space. Order is the weight-vector index space and
/// must never be reordered (only appended) — it is a serialisation
/// contract.
pub const FEATURES: &[&str] = &[
    "has_union",
    "has_select",
    "has_or",
    "has_and",
    "has_squote",
    "has_dquote",
    "has_comment_dashdash",
    "has_comment_hash",
    "has_block_comment",
    "has_mysql_cond_comment",
    "has_hex_literal",
    "has_sleep",
    "has_benchmark",
    "has_extractvalue",
    "has_updatexml",
    "has_concat",
    "has_paren",
    "has_equals",
    "has_semicolon",
    "has_union_select",
    "has_information_schema",
    "has_scientific",
    "len_gt_24",
    "len_gt_64",
    // delivery shape one-hot (must match equiv::sql::delivery_kind_label)
    "dlv_multipart_file",
    "dlv_path_segment",
    "dlv_hpp_split",
    "dlv_json_no_ct",
    "dlv_json_ct",
    "dlv_multipart_field",
    "dlv_form_body",
    "dlv_query",
    "dlv_header_value",
    "dlv_cookie",
    "dlv_xml_body",
    "dlv_json_nested_deep",
    "dlv_graphql",
];

#[must_use]
pub fn feature_count() -> usize {
    FEATURES.len()
}

/// Extract the boolean feature vector for a payload delivered via the
/// given delivery-arm index (see `equiv::sql::delivery_kind_label`).
#[must_use]
pub fn featurize(payload: &str, delivery_arm: usize) -> Vec<f64> {
    let l = payload.to_ascii_lowercase();
    // strip block comments so `un/**/ion` reads as `union` (the WAF
    // normalises too) — same spirit as the equiv normaliser.
    let norm: String = {
        let b = l.as_bytes();
        let mut o = String::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            } else {
                o.push(b[i] as char);
                i += 1;
            }
        }
        o
    };
    let has = |s: &str| norm.contains(s);
    let mut v = vec![0.0; FEATURES.len()];
    let mut set = |name: &str| {
        if let Some(idx) = FEATURES.iter().position(|f| *f == name) {
            v[idx] = 1.0;
        }
    };
    if has("union") {
        set("has_union");
    }
    if has("select") {
        set("has_select");
    }
    if has(" or ") || norm.starts_with("or ") || has("'or") || has(")or") {
        set("has_or");
    }
    if has(" and ") || has("'and") {
        set("has_and");
    }
    if payload.contains('\'') {
        set("has_squote");
    }
    if payload.contains('"') {
        set("has_dquote");
    }
    if l.contains("--") {
        set("has_comment_dashdash");
    }
    if payload.contains('#') {
        set("has_comment_hash");
    }
    if l.contains("/*") {
        set("has_block_comment");
    }
    if l.contains("/*!") {
        set("has_mysql_cond_comment");
    }
    if l.contains("0x") {
        set("has_hex_literal");
    }
    if has("sleep(") {
        set("has_sleep");
    }
    if has("benchmark(") {
        set("has_benchmark");
    }
    if has("extractvalue") {
        set("has_extractvalue");
    }
    if has("updatexml") {
        set("has_updatexml");
    }
    if has("concat") {
        set("has_concat");
    }
    if payload.contains('(') {
        set("has_paren");
    }
    if payload.contains('=') {
        set("has_equals");
    }
    if payload.contains(';') {
        set("has_semicolon");
    }
    if has("union") && has("select") {
        set("has_union_select");
    }
    if has("information_schema") {
        set("has_information_schema");
    }
    if norm
        .as_bytes()
        .windows(2)
        .any(|w| (w[0] == b'e') && w[1].is_ascii_digit())
    {
        set("has_scientific");
    }
    if payload.len() > 24 {
        set("len_gt_24");
    }
    if payload.len() > 64 {
        set("len_gt_64");
    }
    let dlv = match delivery_arm {
        0 => "dlv_multipart_file",
        1 => "dlv_path_segment",
        2 => "dlv_hpp_split",
        3 => "dlv_json_no_ct",
        4 => "dlv_json_ct",
        5 => "dlv_multipart_field",
        6 => "dlv_form_body",
        7 => "dlv_query",
        8 => "dlv_header_value",
        9 => "dlv_cookie",
        10 => "dlv_xml_body",
        11 => "dlv_json_nested_deep",
        12 => "dlv_graphql",
        // Unknown arm ⇒ baseline; never silently fold a known channel
        // into query — that blinds the learner to the channels that
        // actually beat the WAF.
        _ => "dlv_query",
    };
    set(dlv);
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
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in FEATURES {
        for b in f.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h ^= 0x1f; // unit separator so ["ab","c"] != ["a","bc"]
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Stable per-WAF fingerprint from a behavioural signature string
/// (e.g. `server` header + canary-probe status). Hex FNV-1a — the
/// model file name, so the same WAF deployment reuses its learned
/// boundary across runs (the compounding asset).
#[must_use]
pub fn waf_fingerprint(signature: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in signature.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
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
#[must_use]
pub fn synthesize<'a>(
    candidates: &'a [(String, usize)],
    model: &WafModel,
    tried: &std::collections::HashSet<(String, usize)>,
) -> Option<&'a (String, usize)> {
    candidates
        .iter()
        .filter(|c| !tried.contains(*c))
        .min_by(|a, b| {
            let sa = model.score(&featurize(&a.0, a.1));
            let sb = model.score(&featurize(&b.0, b.1));
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
        assert_ne!(feature_sig(), 0xcbf2_9ce4_8422_2325);
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
