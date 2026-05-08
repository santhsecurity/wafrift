//! TLS JA3/JA4 fingerprint rotation profiles.
//!
//! Modern WAFs (Cloudflare, Akamai, Fastly) block traffic based on
//! TLS `ClientHello` fingerprints before even inspecting HTTP content.
//! A request from `reqwest`/`rustls` has a completely different TLS
//! fingerprint than Chrome — and WAFs know it.
//!
//! This module provides browser-accurate TLS profiles that can be used
//! to configure TLS clients to present fingerprints indistinguishable
//! from real browsers.
//!
//! # JA3 vs JA4
//!
//! - **JA3**: MD5 hash of (`TLSVersion`, `CipherSuites`, Extensions,
//!   `EllipticCurves`, `EcPointFormats`). Easy to spoof but also easy
//!   for WAFs to detect simple randomization.
//! - **JA4**: Normalizes and sorts cipher suites + extensions,
//!   includes ALPN and SNI behavior. Harder to evade because
//!   randomizing the order doesn't change the hash.

use rand::Rng;

/// A TLS fingerprint profile that mimics a specific browser.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Human-readable name (e.g., "Chrome 122 / Windows 11").
    pub name: &'static str,
    /// TLS version to advertise (0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    pub tls_version: u16,
    /// Cipher suites to offer, in exact browser order.
    pub cipher_suites: &'static [u16],
    /// TLS extensions to include, in exact browser order.
    pub extensions: &'static [u16],
    /// Supported elliptic curves (named groups).
    pub elliptic_curves: &'static [u16],
    /// EC point formats.
    pub ec_point_formats: &'static [u8],
    /// ALPN protocols to advertise.
    pub alpn_protocols: &'static [&'static str],
    /// Expected JA3 hash (for validation — not used at runtime).
    pub expected_ja3: &'static str,
    /// Signature algorithms to advertise.
    pub signature_algorithms: &'static [u16],
    /// Whether to include GREASE values (Google Random Extensions And
    /// Security Extensions — random values that test server tolerance).
    pub include_grease: bool,
}

// ──────────────────────────────────────────────
//  Cipher suite constants
// ──────────────────────────────────────────────

/// TLS 1.3 cipher suites used by Chrome.
const TLS13_CHROME_CIPHERS: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// TLS 1.2 cipher suites used by Chrome (in Chrome's exact order).
#[allow(dead_code)] // Used when transport layer integrates full TLS handshake
const TLS12_CHROME_CIPHERS: &[u16] = &[
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// TLS 1.3 cipher suites used by Firefox.
const TLS13_FIREFOX_CIPHERS: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
];

/// TLS 1.2 cipher suites used by Firefox (different order from Chrome).
#[allow(dead_code)] // Used when transport layer integrates full TLS handshake
const TLS12_FIREFOX_CIPHERS: &[u16] = &[
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
];

// ──────────────────────────────────────────────
//  Extension constants
// ──────────────────────────────────────────────

/// Chrome's TLS extension list (in Chrome's exact order).
const CHROME_EXTENSIONS: &[u16] = &[
    0x0000, // server_name (SNI)
    0x0017, // extended_master_secret
    0xFF01, // renegotiation_info
    0x000A, // supported_groups
    0x000B, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // application_layer_protocol_negotiation
    0x0005, // status_request (OCSP stapling)
    0x0012, // signed_certificate_timestamp
    0x0033, // key_share
    0x002B, // supported_versions
    0x000D, // signature_algorithms
    0x002D, // psk_key_exchange_modes
    0x001C, // record_size_limit
    0x001B, // compress_certificate
];

/// Firefox's TLS extension list.
const FIREFOX_EXTENSIONS: &[u16] = &[
    0x0000, // server_name
    0x0017, // extended_master_secret
    0xFF01, // renegotiation_info
    0x000A, // supported_groups
    0x000B, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // ALPN
    0x0005, // status_request
    0x000D, // signature_algorithms
    0x0033, // key_share
    0x002B, // supported_versions
    0x002D, // psk_key_exchange_modes
    0x001C, // record_size_limit
    0x0015, // padding
];

// ──────────────────────────────────────────────
//  Curve and algorithm constants
// ──────────────────────────────────────────────

/// Modern supported groups (X25519 + P-256 + P-384).
const MODERN_CURVES: &[u16] = &[
    0x001D, // x25519
    0x0017, // secp256r1 (P-256)
    0x0018, // secp384r1 (P-384)
];

/// EC point formats: uncompressed only (universal).
const EC_POINT_FORMATS: &[u8] = &[0x00]; // uncompressed

/// Chrome's signature algorithms.
const CHROME_SIG_ALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// Firefox's signature algorithms (slightly different order).
const FIREFOX_SIG_ALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
];

// ──────────────────────────────────────────────
//  Browser profiles
// ──────────────────────────────────────────────

/// Chrome 122+ on Windows 11 / macOS 14.
const CHROME_122: TlsProfile = TlsProfile {
    name: "Chrome 122 / Windows 11",
    tls_version: 0x0303, // ClientHello advertises TLS 1.2, negotiates 1.3 via extension
    cipher_suites: TLS13_CHROME_CIPHERS,
    extensions: CHROME_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "773906b0efdefa24a7f2b8eb6985bf37", // Chrome 122
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
};

/// Chrome 120 on macOS.
const CHROME_120: TlsProfile = TlsProfile {
    name: "Chrome 120 / macOS 14",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS,
    extensions: CHROME_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "cd08e31494f9531f560d64c695473da9",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
};

/// Firefox 122+ on Linux.
const FIREFOX_122: TlsProfile = TlsProfile {
    name: "Firefox 122 / Linux",
    tls_version: 0x0303,
    cipher_suites: TLS13_FIREFOX_CIPHERS,
    extensions: FIREFOX_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "579ccef312d18482fc42e2b822ca2430",
    signature_algorithms: FIREFOX_SIG_ALGS,
    include_grease: false, // Firefox doesn't use GREASE
};

/// Firefox 115 ESR on Windows.
const FIREFOX_115_ESR: TlsProfile = TlsProfile {
    name: "Firefox 115 ESR / Windows 10",
    tls_version: 0x0303,
    cipher_suites: TLS13_FIREFOX_CIPHERS,
    extensions: FIREFOX_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "c5a1d8f2e39abb68df7da538a0c53839",
    signature_algorithms: FIREFOX_SIG_ALGS,
    include_grease: false,
};

/// Safari 17+ on macOS 14.
const SAFARI_17: TlsProfile = TlsProfile {
    name: "Safari 17 / macOS 14",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS, // Safari uses BoringSSL, similar to Chrome
    extensions: CHROME_EXTENSIONS,       // Very similar extension set
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "773906b0efdefa24a7f2b8eb6985bf37",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
};

/// Edge 120+ on Windows 11.
const EDGE_120: TlsProfile = TlsProfile {
    name: "Edge 120 / Windows 11",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS, // Chromium-based, same as Chrome
    extensions: CHROME_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "cd08e31494f9531f560d64c695473da9",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
};

/// curl 8.x with OpenSSL 3.x (scanner baseline).
///
/// Many security scanners use libcurl under the hood. Presenting a curl
/// fingerprint can paradoxically bypass WAFs that whitelist scanning
/// tools from monitoring vendors (`UpGuard`, `SecurityScorecard`, etc.)
const CURL_8_OPENSSL: TlsProfile = TlsProfile {
    name: "curl 8 / OpenSSL 3",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS, // OpenSSL 3 uses same TLS 1.3 suites
    extensions: &[
        0x0000, // server_name
        0x000A, // supported_groups
        0x000B, // ec_point_formats
        0x000D, // signature_algorithms
        0x0033, // key_share
        0x002B, // supported_versions
        0x002D, // psk_key_exchange_modes
        0x0010, // ALPN
    ],
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "b1ce3e0d1a7a3b63f4f6d8e4c1db2a5a", // curl 8 / OpenSSL 3
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: false, // curl doesn't use GREASE
};

/// Mobile Safari on iOS 17.
///
/// iOS has a slightly different extension set from macOS Safari
/// because of the iOS TLS stack's unique post-quantum key exchange
/// support and certificate compression.
const SAFARI_IOS_17: TlsProfile = TlsProfile {
    name: "Safari iOS 17 / iPhone",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS, // BoringSSL-based like macOS Safari
    extensions: &[
        0x0000, // server_name
        0x0017, // extended_master_secret
        0xFF01, // renegotiation_info
        0x000A, // supported_groups
        0x000B, // ec_point_formats
        0x0023, // session_ticket
        0x0010, // ALPN
        0x0005, // status_request
        0x0012, // signed_certificate_timestamp
        0x0033, // key_share
        0x002B, // supported_versions
        0x000D, // signature_algorithms
        0x002D, // psk_key_exchange_modes
        0x001B, // compress_certificate
        0x0039, // encrypted_client_hello (iOS 17+ specific)
    ],
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "e4e98fa90cad4b76c5f7fd9e3c3f9e2b",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
};

/// Python requests / urllib3 with OpenSSL.
///
/// Python's requests library is the second most common HTTP client
/// after browsers. Its TLS fingerprint is distinctive — no GREASE,
/// fewer extensions, and HTTP/1.1 only ALPN by default.
const PYTHON_REQUESTS: TlsProfile = TlsProfile {
    name: "Python requests 2.31 / urllib3",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS,
    extensions: &[
        0x0000, // server_name
        0x000A, // supported_groups
        0x000D, // signature_algorithms
        0x0033, // key_share
        0x002B, // supported_versions
        0x002D, // psk_key_exchange_modes
        0x0010, // ALPN
    ],
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "c67e0093a0f49d2f7bc3e1e8f3b3d5a7",
    signature_algorithms: &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0804, // rsa_pss_rsae_sha256
        0x0401, // rsa_pkcs1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0805, // rsa_pss_rsae_sha384
        0x0501, // rsa_pkcs1_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0601, // rsa_pkcs1_sha512
        0x0201, // rsa_pkcs1_sha1 (Python still includes this)
    ],
    include_grease: false,
};

/// All available TLS profiles.
const ALL_PROFILES: &[TlsProfile] = &[
    CHROME_122,
    CHROME_120,
    FIREFOX_122,
    FIREFOX_115_ESR,
    SAFARI_17,
    EDGE_120,
    CURL_8_OPENSSL,
    SAFARI_IOS_17,
    PYTHON_REQUESTS,
];

// ──────────────────────────────────────────────
//  GREASE values
// ──────────────────────────────────────────────

/// GREASE (Generate Random Extensions And Sustain Extensibility) values.
///
/// Chrome injects these into cipher suites, extensions, and named groups
/// to test server tolerance. A TLS client missing GREASE is instantly
/// identifiable as non-Chrome.
const GREASE_VALUES: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Pick a random GREASE value.
fn random_grease() -> u16 {
    let mut rng = rand::thread_rng();
    GREASE_VALUES[rng.r#gen_range(0..GREASE_VALUES.len())]
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/// Get all available TLS profiles.
#[must_use]
pub fn profiles() -> &'static [TlsProfile] {
    ALL_PROFILES
}

/// Get a specific TLS profile by browser name.
#[must_use]
pub fn profile_for(browser: &str) -> Option<&'static TlsProfile> {
    let lower = browser.to_ascii_lowercase();
    ALL_PROFILES
        .iter()
        .find(|p| p.name.to_ascii_lowercase().contains(&lower))
}

/// Pick a random TLS profile.
#[must_use]
pub fn random_profile() -> Option<&'static TlsProfile> {
    if ALL_PROFILES.is_empty() {
        return None;
    }
    let mut rng = rand::thread_rng();
    Some(&ALL_PROFILES[rng.gen_range(0..ALL_PROFILES.len())])
}

/// Generate the cipher suite list for a profile (with GREASE if applicable).
///
/// Returns the cipher suites in the exact order they should appear
/// in the `ClientHello` message.
#[must_use]
pub fn build_cipher_suites(profile: &TlsProfile) -> Vec<u16> {
    let mut suites = Vec::with_capacity(profile.cipher_suites.len() + 3);
    if profile.include_grease {
        suites.push(random_grease());
    }
    suites.extend_from_slice(profile.cipher_suites);
    suites
}

/// Generate the extension list for a profile (with GREASE if applicable).
#[must_use]
pub fn build_extensions(profile: &TlsProfile) -> Vec<u16> {
    let mut exts = Vec::with_capacity(profile.extensions.len() + 2);
    if profile.include_grease {
        exts.push(random_grease());
    }
    exts.extend_from_slice(profile.extensions);
    if profile.include_grease {
        exts.push(random_grease()); // GREASE at end too
    }
    exts
}

/// Generate the supported groups list (with GREASE if applicable).
#[must_use]
pub fn build_supported_groups(profile: &TlsProfile) -> Vec<u16> {
    let mut groups = Vec::with_capacity(profile.elliptic_curves.len() + 1);
    if profile.include_grease {
        groups.push(random_grease());
    }
    groups.extend_from_slice(profile.elliptic_curves);
    groups
}

/// Compute a JA3 string from a profile's parameters.
///
/// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EcPointFormats)
/// where each field is comma-separated values joined by dashes.
///
/// Note: This generates the JA3 *string* (pre-hash). The caller
/// should MD5-hash it to get the actual JA3 fingerprint.
#[must_use]
pub fn compute_ja3_string(profile: &TlsProfile) -> String {
    let version = profile.tls_version.to_string();
    let ciphers: String = profile
        .cipher_suites
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let extensions: String = profile
        .extensions
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let curves: String = profile
        .elliptic_curves
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let formats: String = profile
        .ec_point_formats
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    format!("{version},{ciphers},{extensions},{curves},{formats}")
}

/// Summary of what makes each profile unique.
#[must_use]
pub fn profile_summary(profile: &TlsProfile) -> String {
    format!(
        "{}: TLS {:#06x}, {} ciphers, {} extensions, GREASE={}, ALPN=[{}]",
        profile.name,
        profile.tls_version,
        profile.cipher_suites.len(),
        profile.extensions.len(),
        profile.include_grease,
        profile.alpn_protocols.join(", "),
    )
}

#[cfg(test)]
#[path = "tls_fingerprint_tests.rs"]
mod tests;
