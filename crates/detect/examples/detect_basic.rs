use wafrift_detect::detect;

type Sample = (&'static str, u16, Vec<(String, String)>);

fn main() {
    let samples: [Sample; 3] = [
        (
            "Cloudflare-like",
            403,
            vec![
                ("cf-ray".to_string(), "7f3c1234-IAD".to_string()),
                ("server".to_string(), "cloudflare".to_string()),
            ],
        ),
        (
            "Akamai-like",
            403,
            vec![
                ("x-akamai-transformed".to_string(), "9 12345".to_string()),
                ("server".to_string(), "akamaighost".to_string()),
            ],
        ),
        (
            "AWS WAF-like",
            403,
            vec![("x-amzn-waf-action".to_string(), "BLOCK".to_string())],
        ),
    ];

    for (label, status, headers) in samples {
        let detected = match detect(status, &headers, b"").first() {
            Some(waf) => format!("{} ({:.0}%)", waf.name, waf.confidence * 100.0),
            None => "Unknown".to_string(),
        };

        println!("{label:14} -> {detected}");
    }
}
