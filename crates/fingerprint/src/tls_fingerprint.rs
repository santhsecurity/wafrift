//! Compatibility facade for shared TLS ClientHello fingerprint profiles.

pub use guise::fingerprint::tls_profiles::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_tls_profile_catalogue() {
        let profile = profile_for("chrome").expect("chrome profile resolves");
        assert!(profile.name.contains("Chrome"));
        let ja3 = compute_ja3_string(profile);
        assert_eq!(ja3.split(',').count(), 5);
        assert!(profiles().iter().any(|candidate| candidate == profile));
    }
}
