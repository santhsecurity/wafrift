//! Compatibility facade for shared browser HTTP fingerprint profiles.

pub use guise::fingerprint::browser_catalog::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_profile_application() {
        let profile = random_profile().expect("profile catalog is non-empty");
        let mut headers = vec![("User-Agent".to_string(), "old".to_string())];
        apply_profile(&mut headers, profile);

        assert_eq!(
            headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .count(),
            1
        );
        assert!(
            headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("accept"))
        );
    }
}
