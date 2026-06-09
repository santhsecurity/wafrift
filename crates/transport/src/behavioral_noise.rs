//! Compatibility facade for shared browser behavioral HTTP noise.

pub use guise::http::behavioral_noise::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_noise_injector() {
        let mut injector = NoiseInjector::new(BehavioralProfile::chrome_us(), 7);
        let mut headers = Vec::new();
        injector.inject(&mut headers);

        assert!(
            headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        );
        assert_eq!(injector.request_count(), 1);
    }
}
