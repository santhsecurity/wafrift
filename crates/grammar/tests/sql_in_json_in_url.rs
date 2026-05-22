//! Nested delivery: SQL inside JSON inside URL-encoded query values.
//!
//! Exercises [`DeliveryShape`] when the logical attack traverses multiple
//! encoding layers — a WAF that only normalises the outer URL layer must
//! still leave the inner SQL recognizable to the oracle.

use wafrift_grammar::grammar::equiv::DeliveryShape;
use wafrift_oracle::SqlOracle;
use wafrift_oracle::traits::PayloadOracle;

#[cfg(test)]
mod helpers {
    use serde_json::Value;

    /// Build `?<wrap>=<urlencoded json {"param": sql}>`.
    pub fn nested_sql_query_url(target: &str, wrap_param: &str, field: &str, sql: &str) -> String {
        let inner = serde_json::json!({ field: sql }).to_string();
        let sep = if target.contains('?') { '&' } else { '?' };
        format!(
            "{target}{sep}{}={}",
            urlencoding::encode(wrap_param),
            urlencoding::encode(&inner)
        )
    }

    /// One-hop WAF decode: percent-decode then parse JSON and extract the field.
    pub fn waf_decode_sql_from_query_value(encoded: &str, field: &str) -> Option<String> {
        let decoded = urlencoding::decode(encoded).ok()?.into_owned();
        let v: Value = serde_json::from_str(&decoded).ok()?;
        v.get(field).and_then(|x| x.as_str()).map(str::to_string)
    }
}

use helpers::{nested_sql_query_url, waf_decode_sql_from_query_value};

#[test]
fn nested_sql_survives_url_then_json_decode() {
    let sql = "' OR '1'='1' --";
    let url = nested_sql_query_url("https://app.example/api", "data", "q", sql);
    let encoded_value = url.split('=').next_back().expect("query value");
    let recovered = waf_decode_sql_from_query_value(encoded_value, "q").expect("decode chain");
    let oracle = SqlOracle::generic();
    assert!(
        oracle.is_semantically_valid(sql, &recovered),
        "oracle must still see SQLi after nested decode; got {recovered:?}"
    );
}

#[test]
fn delivery_shape_json_body_preserves_sql_in_valid_json() {
    let sql = "1' OR '1'='1";
    let target = "https://app.example/api";
    let req = DeliveryShape::JsonBody {
        param: "filter".into(),
        content_type: Some("application/json".into()),
    }
    .to_request(target, sql);
    let body = String::from_utf8_lossy(req.body.as_deref().unwrap_or(&[]));
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let inner = v["filter"].as_str().expect("sql field");
    let oracle = SqlOracle::generic();
    assert!(oracle.is_semantically_valid(sql, inner));
}

#[test]
fn query_shape_with_json_blob_value_is_percent_encoded() {
    let sql = "admin'--";
    let json_blob = serde_json::json!({ "id": sql }).to_string();
    let req = DeliveryShape::Query {
        param: "payload".into(),
    }
    .to_request("https://app.example/search", &json_blob);
    assert!(
        !req.url.contains(' ') && !req.url.contains('\n'),
        "raw whitespace must not leak into URL: {}",
        req.url
    );
    assert!(req.url.contains("%22"), "JSON quotes must be encoded");
    // Simulate backend last-mile decode of the query value only.
    let value = req.url.rsplit('=').next().expect("value");
    let once = urlencoding::decode(value).unwrap();
    let v: serde_json::Value = serde_json::from_str(&once).unwrap();
    let recovered = v["id"].as_str().unwrap();
    assert_eq!(recovered, sql);
}
