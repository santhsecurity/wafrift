//! Rich response classification — replaces binary is_waf_block with
//! a structured signal the strategy engine can learn from.
//!
//! Instead of "blocked or not," every upstream response produces a
//! [`ResponseSignal`] containing:
//!
//! - **Block classification**: hard block, soft block (200+captcha),
//!   rate limit, challenge, or pass.
//! - **WAF identity**: which WAF produced this block (matched from
//!   TOML response profiles).
//! - **Strategy hints**: which techniques to prioritize and avoid,
//!   pulled from the matched profile.
//! - **Body delta**: change in response body size vs. baseline
//!   (smaller body on block → content was stripped).
//! - **Latency**: response time in ms (WAF inspection adds latency;
//!   a suddenly fast response may mean the WAF short-circuited).

use serde::{Deserialize, Serialize};

/// Rich signal extracted from an upstream response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSignal {
    /// What kind of response this is.
    pub classification: BlockClass,
    /// Which WAF produced this block (if identifiable from the response).
    pub matched_waf: Option<String>,
    /// Techniques to try first based on the matched WAF profile.
    pub prioritize: Vec<String>,
    /// Techniques known to waste requests against this WAF.
    pub avoid: Vec<String>,
    /// HTTP status code.
    pub status: u16,
    /// Response body size in bytes.
    pub body_size: usize,
    /// Inspection model hint from the matched profile (e.g. "single_pass_url_decode").
    pub inspection_model: Option<String>,
}

/// Classification of an upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockClass {
    /// WAF returned an explicit block (403, 406, etc.)
    HardBlock,
    /// 200 OK but body contains block indicators (captcha, access denied)
    SoftBlock,
    /// Rate limited — back off, don't change technique
    RateLimit,
    /// JS challenge (Cloudflare challenge-platform, etc.) — back off
    Challenge,
    /// Not blocked — the payload passed through
    Pass,
}

impl BlockClass {
    /// Whether this response indicates the WAF blocked the request.
    /// Rate limits and challenges are NOT technique failures — they
    /// shouldn't penalize the current technique.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::HardBlock | Self::SoftBlock)
    }

    /// Whether we should back off (reduce request rate) instead of
    /// changing evasion technique.
    #[must_use]
    pub fn should_backoff(&self) -> bool {
        matches!(self, Self::RateLimit | Self::Challenge)
    }
}

/// A single WAF response profile loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseProfile {
    pub name: String,
    #[serde(default)]
    pub block_status_codes: Vec<u16>,
    #[serde(default)]
    pub body_markers: Vec<String>,
    #[serde(default)]
    pub header_markers: Vec<HeaderMarker>,
    #[serde(default)]
    pub inspection_model: Option<String>,
    #[serde(default)]
    pub prioritize: Vec<String>,
    #[serde(default)]
    pub avoid: Vec<String>,
    #[serde(default)]
    pub rate_limit_status: Vec<u16>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Header matching rule for WAF identification.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderMarker {
    pub name: String,
    /// If set, header value must contain this string (case-insensitive).
    #[serde(default)]
    pub contains: Option<String>,
    /// If true, just check that the header exists.
    #[serde(default)]
    pub exists: bool,
}

/// Container for TOML deserialization.
#[derive(Debug, Deserialize)]
struct ProfileFile {
    #[serde(default)]
    response_profile: Vec<ResponseProfile>,
}

/// Loaded response profile database.
#[derive(Debug, Default, Clone)]
pub struct ResponseProfileDb {
    profiles: Vec<ResponseProfile>,
}

impl ResponseProfileDb {
    /// Load all `.toml` files from a directory.
    pub fn load_dir(dir: &std::path::Path) -> Self {
        let mut profiles = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "toml")
                    && let Ok(contents) = std::fs::read_to_string(&path)
                {
                    match toml::from_str::<ProfileFile>(&contents) {
                        Ok(file) => profiles.extend(file.response_profile),
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "failed to parse response profile"
                            );
                        }
                    }
                }
            }
        }
        tracing::info!(count = profiles.len(), "loaded WAF response profiles");
        Self { profiles }
    }

    /// Load from compiled-in rules (fallback when no directory is available).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Classify an upstream response into a rich signal.
    ///
    /// Scans all loaded profiles against the response characteristics
    /// and returns the best-matching profile's recommendations.
    #[must_use]
    pub fn classify(
        &self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
    ) -> ResponseSignal {
        let body_str = {
            let scan_limit = body.len().min(4096);
            String::from_utf8_lossy(&body[..scan_limit]).to_ascii_lowercase()
        };

        // Check for rate limiting first (any profile's rate_limit_status)
        for profile in &self.profiles {
            if profile.rate_limit_status.contains(&status) {
                return ResponseSignal {
                    classification: BlockClass::RateLimit,
                    matched_waf: Some(profile.name.clone()),
                    prioritize: profile.prioritize.clone(),
                    avoid: profile.avoid.clone(),
                    status,
                    body_size: body.len(),
                    inspection_model: profile.inspection_model.clone(),
                };
            }
        }

        // Check for JS challenges (200 + challenge markers)
        if (status == 200 || status == 503)
            && (body_str.contains("challenge-platform")
                || (body_str.contains("captcha") && body_str.contains("cloudflare")))
        {
            let cf_profile = self.profiles.iter().find(|p| p.name == "Cloudflare");
            return ResponseSignal {
                classification: BlockClass::Challenge,
                matched_waf: Some("Cloudflare".to_string()),
                prioritize: cf_profile
                    .map(|p| p.prioritize.clone())
                    .unwrap_or_default(),
                avoid: cf_profile.map(|p| p.avoid.clone()).unwrap_or_default(),
                status,
                body_size: body.len(),
                inspection_model: cf_profile.and_then(|p| p.inspection_model.clone()),
            };
        }

        // Score each profile against the response
        let mut best_match: Option<(usize, &ResponseProfile)> = None;

        for profile in &self.profiles {
            let mut score = 0usize;

            // Status code match
            if profile.block_status_codes.contains(&status) {
                score += 2;
            }

            // Body marker matches
            for marker in &profile.body_markers {
                if body_str.contains(&marker.to_ascii_lowercase()) {
                    score += 3; // body markers are high-confidence
                }
            }

            // Header marker matches
            for hm in &profile.header_markers {
                let header_match = headers.iter().any(|(k, v)| {
                    if !k.eq_ignore_ascii_case(&hm.name) {
                        return false;
                    }
                    if hm.exists {
                        return true;
                    }
                    if let Some(ref contains) = hm.contains {
                        return v.to_ascii_lowercase().contains(&contains.to_ascii_lowercase());
                    }
                    false
                });
                if header_match {
                    score += 2;
                }
            }

            if score > 0
                && (best_match.is_none() || score > best_match.unwrap().0)
            {
                best_match = Some((score, profile));
            }
        }

        // Determine classification
        let classification = if let Some((_, profile)) = best_match {
            if profile.block_status_codes.contains(&status) {
                BlockClass::HardBlock
            } else {
                // Matched body/header markers but status is 200 → soft block
                BlockClass::SoftBlock
            }
        } else {
            // No profile matched — fall back to legacy status-based detection
            if matches!(status, 403 | 406 | 451 | 503) {
                BlockClass::HardBlock
            } else if legacy_body_block_check(&body_str) {
                BlockClass::SoftBlock
            } else {
                BlockClass::Pass
            }
        };

        ResponseSignal {
            classification,
            matched_waf: best_match.map(|(_, p)| p.name.clone()),
            prioritize: best_match
                .map(|(_, p)| p.prioritize.clone())
                .unwrap_or_default(),
            avoid: best_match
                .map(|(_, p)| p.avoid.clone())
                .unwrap_or_default(),
            status,
            body_size: body.len(),
            inspection_model: best_match.and_then(|(_, p)| p.inspection_model.clone()),
        }
    }
}

/// Legacy body-based block detection for responses that don't match
/// any loaded profile. Same indicators as the original `is_waf_block`.
fn legacy_body_block_check(body_lower: &str) -> bool {
    let indicators = [
        "access denied",
        "request blocked",
        "forbidden",
        "security check",
        "attention required",
        "captcha",
        "firewall",
        "blocked by",
        "malicious request",
        "automated request",
    ];
    indicators.iter().any(|indicator| body_lower.contains(indicator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db() -> ResponseProfileDb {
        let toml_str = r#"
        [[response_profile]]
        name = "TestWAF"
        block_status_codes = [403]
        body_markers = ["test-waf-block"]
        header_markers = [{ name = "X-TestWAF", exists = true }]
        inspection_model = "single_pass"
        prioritize = ["DoubleUrlEncode", "CaseMixing"]
        avoid = ["UrlEncode"]
        rate_limit_status = [429]
        notes = "test profile"
        "#;
        let file: ProfileFile = toml::from_str(toml_str).unwrap();
        ResponseProfileDb {
            profiles: file.response_profile,
        }
    }

    #[test]
    fn classify_hard_block() {
        let db = make_db();
        let sig = db.classify(403, &[("X-TestWAF".into(), "1".into())], b"test-waf-block page");
        assert_eq!(sig.classification, BlockClass::HardBlock);
        assert_eq!(sig.matched_waf.as_deref(), Some("TestWAF"));
        assert!(sig.prioritize.contains(&"DoubleUrlEncode".to_string()));
        assert!(sig.avoid.contains(&"UrlEncode".to_string()));
    }

    #[test]
    fn classify_soft_block_200_with_markers() {
        let db = make_db();
        let sig = db.classify(200, &[], b"<html>test-waf-block detected</html>");
        assert_eq!(sig.classification, BlockClass::SoftBlock);
        assert_eq!(sig.matched_waf.as_deref(), Some("TestWAF"));
    }

    #[test]
    fn classify_rate_limit() {
        let db = make_db();
        let sig = db.classify(429, &[], b"Too many requests");
        assert_eq!(sig.classification, BlockClass::RateLimit);
        assert!(sig.classification.should_backoff());
        assert!(!sig.classification.is_blocked());
    }

    #[test]
    fn classify_pass() {
        let db = make_db();
        let sig = db.classify(200, &[], b"Welcome to our site!");
        assert_eq!(sig.classification, BlockClass::Pass);
        assert!(!sig.classification.is_blocked());
        assert!(!sig.classification.should_backoff());
    }

    #[test]
    fn classify_legacy_fallback() {
        // No profiles loaded — should still detect via legacy keywords
        let db = ResponseProfileDb::empty();
        let sig = db.classify(200, &[], b"Access Denied by Web Application Firewall");
        assert_eq!(sig.classification, BlockClass::SoftBlock);
        assert!(sig.matched_waf.is_none());
    }

    #[test]
    fn classify_legacy_403_fallback() {
        let db = ResponseProfileDb::empty();
        let sig = db.classify(403, &[], b"Forbidden");
        assert_eq!(sig.classification, BlockClass::HardBlock);
    }

    #[test]
    fn block_class_is_blocked() {
        assert!(BlockClass::HardBlock.is_blocked());
        assert!(BlockClass::SoftBlock.is_blocked());
        assert!(!BlockClass::RateLimit.is_blocked());
        assert!(!BlockClass::Challenge.is_blocked());
        assert!(!BlockClass::Pass.is_blocked());
    }

    #[test]
    fn block_class_should_backoff() {
        assert!(!BlockClass::HardBlock.should_backoff());
        assert!(!BlockClass::SoftBlock.should_backoff());
        assert!(BlockClass::RateLimit.should_backoff());
        assert!(BlockClass::Challenge.should_backoff());
        assert!(!BlockClass::Pass.should_backoff());
    }

    #[test]
    fn header_marker_matching() {
        let db = make_db();
        // Header present → should match
        let sig = db.classify(403, &[("X-TestWAF".into(), "yes".into())], b"");
        assert_eq!(sig.matched_waf.as_deref(), Some("TestWAF"));

        // Header absent, body marker present → should still match
        let sig2 = db.classify(200, &[], b"test-waf-block error page");
        assert_eq!(sig2.matched_waf.as_deref(), Some("TestWAF"));
    }

    #[test]
    fn inspection_model_passed_through() {
        let db = make_db();
        let sig = db.classify(403, &[], b"test-waf-block");
        assert_eq!(sig.inspection_model.as_deref(), Some("single_pass"));
    }
}
