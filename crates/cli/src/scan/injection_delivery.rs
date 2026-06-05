//! How payloads reach the target — GET query vs POST form body.
//!
//! Auto-escalation often pivots to HTML form surfaces; firing variants only
//! via `?param=` would miss the WAF on the real sink.

use wafrift_oracle::response_oracle::{ResponseContext, ResponseOracle};
use wafrift_transport::is_waf_block;
use wafrift_types::Verdict;

use super::scan_url_with_param;

/// Wire shape for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InjectionDelivery {
    GetQuery,
    PostForm,
}

impl InjectionDelivery {
    #[must_use]
    pub(crate) fn from_surface_method(method: &str) -> Self {
        if method.eq_ignore_ascii_case("POST") {
            Self::PostForm
        } else {
            Self::GetQuery
        }
    }

    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::GetQuery => "get_query",
            Self::PostForm => "post_form",
        }
    }
}

struct FireResponse {
    status: u16,
    body: Vec<u8>,
    retry_after: Option<std::time::Duration>,
}

async fn read_response(resp: reqwest::Response) -> Result<FireResponse, ()> {
    let status = resp.status().as_u16();
    let retry_after = if status == 429 || status == 503 {
        let now = std::time::SystemTime::now();
        resp.headers()
            .get_all("retry-after")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|s| crate::retry_after::parse(s, now))
            .max()
    } else {
        None
    };
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .map_err(|_| ())?;
    Ok(FireResponse {
        status,
        body,
        retry_after,
    })
}

/// Fire raw payload (attack-shaped) for baseline / engagement fingerprinting.
pub(crate) async fn fire_raw_payload(
    http: &reqwest::Client,
    delivery: InjectionDelivery,
    url: &str,
    param: &str,
    payload: &str,
) -> Option<(u16, Vec<u8>, bool)> {
    let fr = match delivery {
        InjectionDelivery::GetQuery => {
            let u = scan_url_with_param(url, param, &urlencoding::encode(payload));
            http.get(&u).send().await.ok()?
        }
        InjectionDelivery::PostForm => {
            http.post(url).form(&[(param, payload)]).send().await.ok()?
        }
    };
    let fr = read_response(fr).await.ok()?;
    let blocked = is_waf_block(fr.status, &fr.body);
    Some((fr.status, fr.body, blocked))
}

/// Fire benign probe value for engagement fingerprinting.
pub(crate) async fn fire_benign_probe(
    http: &reqwest::Client,
    delivery: InjectionDelivery,
    url: &str,
    param: &str,
    benign_value: &str,
) -> Option<super::waf_engagement::ResponseFingerprint> {
    let (status, body, _) = fire_raw_payload(http, delivery, url, param, benign_value).await?;
    Some(super::waf_engagement::ResponseFingerprint::from_parts(
        status, &body,
    ))
}

/// Fire one variant and classify with the scan oracle.
pub(crate) async fn fire_variant_classified(
    http: &reqwest::Client,
    delivery: InjectionDelivery,
    url: &str,
    param: &str,
    payload: &str,
    oracle: &ResponseOracle,
) -> (Option<Verdict>, Option<std::time::Duration>) {
    let fr = match delivery {
        InjectionDelivery::GetQuery => {
            let u = scan_url_with_param(url, param, &urlencoding::encode(payload));
            match http.get(&u).send().await {
                Ok(r) => read_response(r).await.ok(),
                Err(_) => None,
            }
        }
        InjectionDelivery::PostForm => {
            match http.post(url).form(&[(param, payload)]).send().await {
                Ok(r) => read_response(r).await.ok(),
                Err(_) => None,
            }
        }
    };
    let Some(fr) = fr else {
        return (None, None);
    };
    let ctx = ResponseContext {
        status: fr.status,
        body: fr.body,
        ..Default::default()
    };
    (Some(oracle.classify(&ctx)), fr.retry_after)
}

#[must_use]
pub(crate) fn repro_curl(
    delivery: InjectionDelivery,
    url: &str,
    param: &str,
    payload: &str,
    techniques: &[String],
    confidence: f64,
    label: &str,
    variant_idx: usize,
) -> String {
    match delivery {
        InjectionDelivery::GetQuery => {
            let full_url = scan_url_with_param(url, param, &urlencoding::encode(payload));
            crate::poc_emit::render_raw_curl(
                &full_url,
                "GET",
                &[],
                None,
                techniques,
                confidence,
                label,
                None,
                Some(&format!("variant.{variant_idx}")),
            )
            .unwrap_or_else(|_| crate::helpers::url_query_repro_curl(url, param, payload))
        }
        InjectionDelivery::PostForm => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            crate::poc_emit::render_raw_curl(
                url,
                "POST",
                &[(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )],
                Some(body.as_bytes()),
                techniques,
                confidence,
                label,
                None,
                Some(&format!("variant.{variant_idx}")),
            )
            .unwrap_or_else(|_| {
                format!(
                    "curl -sS -X POST {} -H 'Content-Type: application/x-www-form-urlencoded' --data-raw {}",
                    shell_quote(url),
                    shell_quote(&body)
                )
            })
        }
    }
}

fn shell_quote(s: &str) -> String {
    crate::helpers::shell_single_quote(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_surface_method_maps_post() {
        assert_eq!(
            InjectionDelivery::from_surface_method("POST"),
            InjectionDelivery::PostForm
        );
        assert_eq!(
            InjectionDelivery::from_surface_method("GET"),
            InjectionDelivery::GetQuery
        );
    }
}
