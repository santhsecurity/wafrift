//! Compatibility facade for shared browser session coherence primitives.

pub use guise::http::session_coherence::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::PROFILES;

    #[test]
    fn facade_reexports_session_pool_and_profile_pairing() {
        let (order, h2) = pair_for_name("chrome131").expect("chrome alias resolves");
        assert_eq!(order.family, "chrome");
        assert_eq!(h2.family, "chrome");

        let pool = SessionPool::new(PROFILES.iter().collect(), 3);
        let profile = pool.profile_for("example.com");
        assert!(PROFILES
            .iter()
            .any(|candidate| candidate.name == profile.name));
    }
}
