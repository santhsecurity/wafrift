//! Wafrift compatibility surface for browser-identical TLS impersonation.
//!
//! The implementation lives in `scanclient` so the Santh scanners share
//! one profile enum, one parser, one bogon guard, and one `rquest`
//! transport. Wafrift keeps this module as the public import path for
//! existing `wafrift_transport::stealth::*` consumers.

pub use scanclient::tls_impersonate::{ImpersonateProfile, ParseProfileError, supported_profiles};
pub use scanclient::tls_impersonate_stealth::{StealthClient, StealthError, StealthResponse};

#[cfg(test)]
mod tests {
    use super::{ImpersonateProfile, ParseProfileError, StealthClient, supported_profiles};

    #[test]
    fn parse_canonical_names() {
        assert_eq!(
            ImpersonateProfile::parse("chrome131").unwrap(),
            ImpersonateProfile::Chrome131
        );
        assert_eq!(
            ImpersonateProfile::parse("firefox133").unwrap(),
            ImpersonateProfile::Firefox133
        );
        assert_eq!(
            ImpersonateProfile::parse("safari18").unwrap(),
            ImpersonateProfile::Safari18
        );
        assert_eq!(
            ImpersonateProfile::parse("edge131").unwrap(),
            ImpersonateProfile::Edge131
        );
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(
            ImpersonateProfile::parse("chrome").unwrap(),
            ImpersonateProfile::Chrome131
        );
        assert_eq!(
            ImpersonateProfile::parse("CHROME-LATEST").unwrap(),
            ImpersonateProfile::Chrome131
        );
        assert_eq!(
            ImpersonateProfile::parse("ff").unwrap(),
            ImpersonateProfile::Firefox133
        );
    }

    #[test]
    fn parse_error_names_bad_profile_and_supported_set() {
        let err = ImpersonateProfile::parse("nonsense").unwrap_err();
        assert_eq!(err, ParseProfileError("nonsense".to_string()));
        let msg = err.to_string();
        assert!(msg.contains("nonsense"));
        assert!(msg.contains("chrome131"));
    }

    #[test]
    fn name_round_trip() {
        for raw in supported_profiles() {
            let parsed = ImpersonateProfile::parse(raw).unwrap_or_else(|_| {
                panic!("supported_profiles() listed {raw:?} but parse rejected it")
            });
            assert_eq!(parsed.name(), raw, "name() must round-trip with parse()");
        }
    }

    #[cfg(not(feature = "tls-impersonate"))]
    #[tokio::test]
    async fn stub_client_errors_with_actionable_message() {
        let err = StealthClient::new(ImpersonateProfile::Chrome131).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tls-impersonate"),
            "stub error must point operator at the feature flag, got: {msg}"
        );
        assert!(
            msg.contains("rebuild"),
            "stub error must include the operator action, got: {msg}"
        );
    }

    #[cfg(feature = "tls-impersonate")]
    #[tokio::test]
    async fn real_client_constructs() {
        for raw in supported_profiles() {
            let profile = ImpersonateProfile::parse(raw).unwrap();
            let client = StealthClient::new(profile).unwrap_or_else(|e| panic!("build {raw}: {e}"));
            assert_eq!(client.profile(), profile);
        }
    }
}
