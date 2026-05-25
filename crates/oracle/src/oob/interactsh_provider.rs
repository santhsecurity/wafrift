//! `OobProviderTrait` implementation backed by [`interactsh::InteractshClient`].
//!
//! Bridges interactsh's correlated-callback API into wafrift's OOB
//! contract so the existing [`super::oracle::OobOracle`] polling loop
//! can drive a real interactsh server (oast.fun / oast.pro /
//! self-hosted) instead of being constrained to the `MockOobProvider`
//! used in tests.
//!
//! ## Correlation
//!
//! interactsh returns *every* callback that matches the client's
//! correlation ID. To map an incoming event back to the wafrift canary
//! that triggered it we stamp each generated URL with a unique
//! `canary_id` attribute inside the [`interactsh::InteractionContext`],
//! then filter the poll output on that attribute. This means polling
//! is O(events × canaries-in-the-tracking-window) — fine for typical
//! scan workloads (< 1000 outstanding canaries) and explicit / honest
//! for larger ones.
//!
//! ## Feature gate
//!
//! Compiled only with `--features interactsh-provider`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use interactsh::{InteractionContext, InteractshClient};
use tokio::sync::RwLock;
use uuid::Uuid;
use wafrift_types::oob::{OobCanary, OobInteraction};

use crate::oob::provider::{OobError, OobProviderTrait};

const CANARY_ATTRIBUTE: &str = "wafrift_canary_id";

/// OOB provider that wraps an [`InteractshClient`].
///
/// Construct once at scan start with [`Self::new`], then hand it to
/// [`super::oracle::OobOracle::new`] (boxed) — the oracle's polling
/// loop will register canaries and poll them through this provider
/// transparently.
#[derive(Debug)]
pub struct InteractshOobProvider {
    client: Arc<InteractshClient>,
    canary_nonces: RwLock<HashMap<Uuid, String>>,
}

impl InteractshOobProvider {
    /// Build a provider around an already-registered interactsh client.
    ///
    /// The client must have completed its initial `register()` round-trip
    /// (which [`InteractshClient::new`] does automatically) before this
    /// constructor is called.
    #[must_use]
    pub fn new(client: Arc<InteractshClient>) -> Self {
        Self {
            client,
            canary_nonces: RwLock::new(HashMap::new()),
        }
    }

    /// Expose the underlying client so callers can keep using
    /// interactsh-specific helpers (e.g.
    /// [`interactsh::payload_helpers::blind_xss_payloads`]) without
    /// having to thread two handles through their scan loop.
    #[must_use]
    pub fn client(&self) -> &Arc<InteractshClient> {
        &self.client
    }
}

#[async_trait]
impl OobProviderTrait for InteractshOobProvider {
    async fn register(&self) -> Result<OobCanary, OobError> {
        let canary_id = Uuid::new_v4();
        let context = InteractionContext::new("wafrift-oob")
            .with_attribute(CANARY_ATTRIBUTE, canary_id.to_string());

        let generated = self
            .client
            .generate_url(context)
            .map_err(|e| OobError::RegistrationFailed {
                reason: format!("interactsh generate_url failed: {e}"),
            })?;

        let host = host_of(&generated.url).unwrap_or_else(|| generated.url.clone());
        let expected_http_path = format!("/wafrift-oob/{canary_id}");

        {
            let mut map = self.canary_nonces.write().await;
            map.insert(canary_id, generated.nonce.clone());
        }

        Ok(OobCanary {
            id: canary_id,
            expected_dns: host,
            expected_http_path,
            created_at: Some(Instant::now()),
        })
    }

    async fn poll(&self, canary: &OobCanary) -> Result<Vec<OobInteraction>, OobError> {
        let interactions =
            self.client
                .poll()
                .await
                .map_err(|e| OobError::PollFailed {
                    reason: format!("interactsh poll failed: {e}"),
                })?;

        let canary_id_string = canary.id.to_string();

        let mut out = Vec::new();
        for correlated in interactions {
            // Only surface events whose context carries the matching
            // canary id. Events for other canaries on the same client
            // session are still buffered — interactsh's correlation
            // engine has already done the heavy lifting, this is just
            // a per-canary fan-out.
            let stamp_matches = correlated
                .context
                .attributes
                .get(CANARY_ATTRIBUTE)
                .map(|value| value == &canary_id_string)
                .unwrap_or(false);

            if !stamp_matches {
                continue;
            }

            let event = correlated.event;
            let protocol = event.protocol.to_lowercase();
            let oob = match protocol.as_str() {
                "dns" => OobInteraction::DnsQuery {
                    query: event.full_id.clone(),
                    // interactsh's wire format doesn't carry a parsed
                    // source IP on the DNS event itself; leave it empty
                    // rather than fabricating something. Consumers that
                    // only need *that the callback fired* still see the
                    // event in the returned vec.
                    source_ip: String::new(),
                },
                "http" | "https" => OobInteraction::HttpRequest {
                    path: event.full_id.clone(),
                    headers: Vec::new(),
                    body: event.raw_request.clone(),
                },
                // Pre-fix `_ =&gt; continue` silently dropped these three.
                // Oracle UTL_SMTP-based blind SQLi, LDAP-injection, and
                // ftp:// SSRF callbacks all use protocols beyond
                // DNS/HTTP — every one of them reported
                // `OobConfirmation::Timeout` while the payload was
                // actually working at the target.
                //
                // `InteractionEvent` does not carry a parsed source IP
                // on its struct (only protocol + full_id + raw_request),
                // so source_ip is left empty — same as the DnsQuery arm
                // above. Consumers that only need *that the callback
                // fired* still see the event in the returned vec.
                "smtp" => OobInteraction::SmtpMessage {
                    raw: event.raw_request.clone().unwrap_or_default(),
                    source_ip: String::new(),
                },
                "ldap" => OobInteraction::LdapQuery {
                    // `full_id` is the queried hostname on LDAP events;
                    // the request body, when present, carries the dn.
                    dn: event.raw_request.clone().unwrap_or_else(|| event.full_id.clone()),
                    source_ip: String::new(),
                },
                "ftp" => OobInteraction::FtpCommand {
                    command: event.raw_request.clone().unwrap_or_default(),
                    source_ip: String::new(),
                },
                _ => continue,
            };
            out.push(oob);
        }
        Ok(out)
    }
}

/// Extract the host portion of `url`, accepting either a fully-formed
/// absolute URL (`http://abc.oast.fun/x`) or interactsh's bare
/// host form (`abcXYZ.oast.fun`).
fn host_of(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        return parsed.host_str().map(str::to_string);
    }
    if let Ok(parsed) = url::Url::parse(&format!("http://{url}")) {
        return parsed.host_str().map(str::to_string);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_handles_absolute_url() {
        assert_eq!(
            host_of("http://abc.oast.fun/wafrift"),
            Some("abc.oast.fun".to_string())
        );
    }

    #[test]
    fn host_of_handles_bare_host_form() {
        assert_eq!(
            host_of("abcXYZ123.oast.fun"),
            Some("abcxyz123.oast.fun".to_string())
        );
    }

    #[test]
    fn host_of_handles_https() {
        assert_eq!(
            host_of("https://xyz.oast.pro/abc"),
            Some("xyz.oast.pro".to_string())
        );
    }

    #[test]
    fn canary_attribute_key_is_stable() {
        // This is a load-bearing string: changing it silently breaks
        // every previously-registered canary on a live scan. Locking
        // it down as a test asserts the value the way docs would.
        assert_eq!(CANARY_ATTRIBUTE, "wafrift_canary_id");
    }
}
