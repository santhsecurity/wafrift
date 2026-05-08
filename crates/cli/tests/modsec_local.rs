//! Optional smoke tests against a **local** ModSecurity/CRS stack.
//!
//! ```bash
//! cd testbed/modsecurity-crs && docker compose up -d
//! export WAFRIFT_MODSEC_URL=http://127.0.0.1:18080
//! cargo test -p wafrift-cli --test modsec_local -- --ignored
//! ```

use reqwest::Client;

#[tokio::test]
#[ignore = "local Docker WAF — see testbed/modsecurity-crs/README.md"]
async fn modsec_url_reachable() {
    let base = std::env::var("WAFRIFT_MODSEC_URL")
        .expect("WAFRIFT_MODSEC_URL must be set when running ignored tests");
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let r = client
        .get(base.trim_end_matches('/').to_string())
        .send()
        .await
        .expect("HTTP connect");
    let code = r.status().as_u16();
    assert!(
        (200..500).contains(&code),
        "unexpected status from bare GET: {code}"
    );
}
