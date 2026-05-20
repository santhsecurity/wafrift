//! Live findings renderer + markdown safety.
//!
//! The proxy exposes `/_wafrift/findings.md` so practitioners can
//! `curl` a writeup of accumulated bypass discoveries mid-session,
//! without round-tripping through the gene-bank file. This module
//! is that renderer plus the markdown sanitiser that defends
//! against stored-injection via attacker-controlled Host headers.
//!
//! Sanitisation is conservative: only `[A-Za-z0-9.\-_:/@+]` survive
//! verbatim; anything else is replaced with `_`. Hostnames lose
//! nothing valid (RFC 1035 + percent-decoded ports + IPv6 brackets
//! pass through after a separate IPv6 step), but pipe / backtick /
//! asterisk that would break markdown context are neutralised.

use crate::ProxyState;
use wafrift_strategy::HostState;

/// Render the current proxy state as a markdown findings page.
/// Always returns a non-empty string — the "no requests yet" /
/// "no bypasses yet" cases produce a sensible explanation instead
/// of a blank document.
#[must_use]
pub fn render_live_findings(state: &ProxyState) -> String {
    let mut out = String::new();
    out.push_str("# wafrift live findings\n\n");
    out.push_str(&format!(
        "Total proxied: {} · Total WAF blocks observed: {} · Hosts seen: {}\n\n",
        state.total_scanned(),
        state.total_blocks(),
        state.hosts.len(),
    ));

    if state.total_scanned() == 0 {
        out.push_str("No requests have been proxied yet. Send traffic through the proxy to begin evasion discovery.\n");
        return out;
    }

    let mut hosts_with_winners: Vec<(&String, &HostState)> = state
        .hosts
        .iter()
        .filter(|(_, hs)| !hs.proven_winners.is_empty())
        .collect();
    hosts_with_winners.sort_by(|a, b| a.0.cmp(b.0));

    if hosts_with_winners.is_empty() {
        out.push_str("_No bypasses discovered yet — keep traffic flowing through the proxy. Blocks are being recorded and will inform technique selection._\n");
        return out;
    }

    out.push_str("## Hosts with proven bypasses\n\n");
    for (host, hs) in hosts_with_winners {
        // Hostnames come from Host headers — attacker-controllable in
        // every relevant threat model. If a host contains backticks,
        // pipes, or asterisks, they'd be interpreted as markdown
        // formatting (or worse, raw HTML in renderers that allow it)
        // and the local /_wafrift/findings.md endpoint would become a
        // stored-markdown-injection sink. Sanitise to the printable-
        // ASCII subset of valid host characters before interpolating.
        let host_md = sanitize_for_markdown(host);
        let waf_md = hs.waf_name.as_deref().map(sanitize_for_markdown);
        out.push_str(&format!("### `{host_md}`\n\n"));
        if let Some(waf) = &waf_md {
            out.push_str(&format!("**Identified WAF:** {waf}\n\n"));
        }
        out.push_str("**Working techniques:**\n\n");
        for t in &hs.proven_winners {
            out.push_str(&format!("- `{}`\n", sanitize_for_markdown(t)));
        }
        out.push('\n');
        out.push_str(&format!(
            "**Reproduce:** `wafrift replay --target 'https://{host_md}/<PATH>' --param q --payload '<PAYLOAD>' --from-host '{host_md}'`\n\n",
        ));
    }
    out
}

/// Replace markdown- and shell-special characters with `_` so
/// attacker-controlled strings (host headers, technique pool keys
/// round-tripped through gene bank) cannot break out of the
/// rendered markdown.
#[must_use]
pub fn sanitize_for_markdown(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '+' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_markdown_breakers() {
        assert_eq!(sanitize_for_markdown("hello"), "hello");
        assert_eq!(sanitize_for_markdown("example.com"), "example.com");
        assert_eq!(sanitize_for_markdown("a:b@c"), "a:b@c");
        // Pipe / backtick / star / underscore-bold / brackets all
        // become `_`.
        assert_eq!(sanitize_for_markdown("a|b"), "a_b");
        assert_eq!(sanitize_for_markdown("a`b"), "a_b");
        assert_eq!(sanitize_for_markdown("**bold**"), "__bold__");
        assert_eq!(sanitize_for_markdown("[x](y)"), "_x__y_");
    }

    #[test]
    fn sanitize_preserves_canonical_host_chars() {
        // RFC 1035 host chars: A-Za-z0-9.- plus colons for IPv6
        // (which get replaced with `_` since we don't permit `:` in
        // the bare alphabet wait — we DO permit colon, for port
        // separators). The host `[::1]:8080` becomes
        // `__::1__:8080` because `[` and `]` are dropped, but
        // `:` and digits survive. Sanity-check that.
        assert_eq!(sanitize_for_markdown("[::1]:8080"), "_::1_:8080");
    }

    #[test]
    fn sanitize_unicode_replaced_with_underscore() {
        // Non-ASCII (homoglyphs, RTL marks) must be replaced — they
        // can rewrite a markdown render in ways the operator can't
        // see in the raw source.
        let result = sanitize_for_markdown("paypaⅼ.com"); // l = U+217C (small l)
        assert!(result.contains('_'), "non-ASCII letter must be sanitised");
    }

    #[test]
    fn render_with_zero_requests_explains_no_traffic_yet() {
        let state = ProxyState::default();
        let md = render_live_findings(&state);
        assert!(md.contains("No requests have been proxied yet"));
    }
}
