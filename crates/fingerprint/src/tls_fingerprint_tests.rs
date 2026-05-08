#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::tls_fingerprint::{
        build_cipher_suites, build_extensions, compute_ja3_string, profile_for, profile_summary,
        profiles, random_profile,
    };

    /// GREASE values for test validation (mirrors private const in parent).
    const GREASE_VALUES: &[u16] = &[
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
        0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ];

    #[test]
    fn all_profiles_have_required_fields() {
        for profile in profiles() {
            assert!(!profile.name.is_empty());
            assert!(!profile.cipher_suites.is_empty());
            assert!(!profile.extensions.is_empty());
            assert!(!profile.elliptic_curves.is_empty());
            assert!(!profile.ec_point_formats.is_empty());
            assert!(!profile.alpn_protocols.is_empty());
            assert!(!profile.expected_ja3.is_empty());
            assert!(!profile.signature_algorithms.is_empty());
        }
    }

    #[test]
    fn profiles_count() {
        assert!(
            profiles().len() >= 6,
            "should have at least 6 browser profiles"
        );
    }

    #[test]
    fn profile_for_finds_chrome() {
        let p = profile_for("chrome").unwrap();
        assert!(p.name.contains("Chrome"));
    }

    #[test]
    fn profile_for_finds_firefox() {
        let p = profile_for("firefox").unwrap();
        assert!(p.name.contains("Firefox"));
    }

    #[test]
    fn profile_for_returns_none_for_unknown() {
        assert!(profile_for("netscape").is_none());
    }

    #[test]
    fn random_profile_returns_valid() {
        for _ in 0..50 {
            let p = random_profile().expect("ALL_PROFILES array is empty");
            assert!(!p.name.is_empty());
        }
    }

    #[test]
    fn build_cipher_suites_includes_grease_for_chrome() {
        let p = profile_for("chrome").unwrap();
        assert!(p.include_grease);
        let suites = build_cipher_suites(p);
        // Should have profile ciphers + 1 GREASE
        assert_eq!(suites.len(), p.cipher_suites.len() + 1);
        // First entry should be a GREASE value
        assert!(GREASE_VALUES.contains(&suites[0]));
    }

    #[test]
    fn build_cipher_suites_no_grease_for_firefox() {
        let p = profile_for("firefox").unwrap();
        assert!(!p.include_grease);
        let suites = build_cipher_suites(p);
        assert_eq!(suites.len(), p.cipher_suites.len());
    }

    #[test]
    fn build_extensions_includes_grease() {
        let p = profile_for("chrome").unwrap();
        let exts = build_extensions(p);
        // Should have profile extensions + 2 GREASE (start and end)
        assert_eq!(exts.len(), p.extensions.len() + 2);
    }

    #[test]
    fn ja3_string_format() {
        let p = profile_for("chrome").unwrap();
        let ja3 = compute_ja3_string(p);
        // Should have exactly 4 comma-delimiters at the top level
        // (5 sections separated by commas)
        let sections: Vec<&str> = ja3.split(',').collect();
        // First section is TLS version (one number)
        assert!(sections[0].parse::<u16>().is_ok());
    }

    #[test]
    fn chrome_and_firefox_have_different_cipher_order() {
        let chrome = profile_for("chrome").unwrap();
        let firefox = profile_for("firefox").unwrap();
        // Both have TLS_AES_128_GCM_SHA256 first, but different second
        assert_ne!(chrome.cipher_suites[1], firefox.cipher_suites[1]);
    }

    #[test]
    fn chrome_and_firefox_have_different_sig_algs() {
        let chrome = profile_for("chrome").unwrap();
        let firefox = profile_for("firefox").unwrap();
        // Firefox includes ecdsa_secp521r1_sha512, Chrome doesn't
        assert!(firefox.signature_algorithms.contains(&0x0603));
        assert!(!chrome.signature_algorithms.contains(&0x0603));
    }

    #[test]
    fn grease_values_are_valid() {
        for g in GREASE_VALUES {
            // GREASE values are of the form 0x?A?A where ? is identical
            assert_eq!(g & 0x0F0F, 0x0A0A, "invalid GREASE value: {g:#06x}");
        }
    }

    #[test]
    fn profile_summary_readable() {
        for profile in profiles() {
            let summary = profile_summary(profile);
            assert!(summary.contains(profile.name));
            assert!(summary.contains("ciphers"));
            assert!(summary.contains("ALPN"));
        }
    }

    #[test]
    fn all_profiles_support_h2_and_http11() {
        for profile in profiles() {
            assert!(profile.alpn_protocols.contains(&"h2"));
            assert!(profile.alpn_protocols.contains(&"http/1.1"));
        }
    }

    #[test]
    fn all_profiles_include_sni_extension() {
        for profile in profiles() {
            assert!(
                profile.extensions.contains(&0x0000),
                "profile {} missing SNI extension",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_include_alpn_extension() {
        for profile in profiles() {
            assert!(
                profile.extensions.contains(&0x0010),
                "profile {} missing ALPN extension",
                profile.name
            );
        }
    }
}
