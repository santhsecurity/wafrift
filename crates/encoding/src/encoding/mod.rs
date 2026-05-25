//! Payload encoding strategies — transform payloads to bypass WAF keyword detection.
//!
//! Each strategy changes HOW the payload looks without changing WHAT it does.
//! The server decodes the payload back to its original form, but the WAF
//! fails to match it against its rules.
//!
//! # Module structure
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`strategy`] | `Strategy` enum and `encode()` dispatcher |
//! | [`url`] | URL, double-URL, and triple-URL encoding |
//! | [`unicode`] | Unicode `\uXXXX`, `%uXXXX`, JSON, and HTML entity encoding |
//! | [`keyword`] | Case alternation, whitespace/comment insertion, SQL obfuscation |
//! | [`structural`] | Null byte, overlong UTF-8, chunked split, HPP, compression |
//! | [`layered`] | Multi-strategy chaining and aggressiveness scoring |

/// Invisible-character & tag-character encoders (Plan 9 tag chars,
/// variation selectors, stylistic ligatures, enclosed alphanumerics,
/// soft hyphens, word joiners). Looks identical, normalizes identical,
/// byte stream is unrecognizable.
pub mod invisible;
/// Keyword manipulation strategies (case, whitespace, comments).
pub mod keyword;
/// Path-normalization differential encoders (dot-segment variants,
/// percent-encoded slash/dot, double-encoded, Tomcat semicolon,
/// IIS backslash, fullwidth slash, overlong UTF-8 dot). Each variant
/// is RFC 3986 §5.2.4-equivalent to the same target — but most WAFs
/// don't run that exact algorithm.
pub mod path_norm;
/// HTTP request-line differential tricks: exotic methods (WebDAV,
/// CalDAV, cache-private), method case/whitespace tricks, version
/// strings (HTTP/0.9, HTTP/1.99, HTTP/2.0-on-h1-wire), absolute-form
/// URI (RFC 7230 §5.3.2), asterisk-form, authority-form.
pub mod request_line;
/// Deserialization-vulnerability payload generators across Java, .NET,
/// Python, Ruby, PHP, YAML, Hessian. WAFs that scan for keywords miss
/// these because they don't carry keywords — the vulnerability is in
/// the receiving deserializer.
pub mod deserialization;
/// JWT-mutation attack library: alg:none family (4 case variants),
/// algorithm confusion (HS256-with-RSA-key, RS256-flip), embedded
/// JWK, jku/x5u SSRF, kid path-traversal + SQLi + log4shell, empty
/// signature, crit-header bypass, b64 padding tricks, duplicate alg.
pub mod jwt;
/// OAuth 2.0 / OIDC attack library: redirect_uri bypass (11 URL-confusion
/// variants — userinfo, subdomain prefix, path prefix, fragment, percent-encoded
/// dot, backslash parser disagreement, case-fold, port confusion, IP literal,
/// localhost alias, open-redirect chain), state CSRF / binding bugs, PKCE
/// downgrade / reuse / method confusion, scope injection / separator / upgrade,
/// token misuse and replay, response_type+response_mode hybrid-flow confusion,
/// and JWT bearer token mutation relay via the `jwt` module.
pub mod oauth;
/// Single-packet race-condition primitives (Kettle BH23 "Smashing the
/// State Machine"): HTTP/1.1 pipelined coalesce + HTTP/2 last-byte-sync
/// frame builders. Builds wire bytes only; the transport layer
/// handles the TCP_NODELAY-off + writev coalesce.
pub mod race;
/// DOM-clobbering payload library: HTML-only XSS primitives that
/// override JavaScript globals via `<a id=…>`, `<form name=…>`,
/// `<img name=…>`, `<base href=…>`, `<iframe name=…>`, HTMLCollection
/// twins, nested `<form><input>` chains. Defeats CSPs that allow
/// HTML but block `<script>`.
pub mod dom_clobber;
/// Server-side & client-side prototype-pollution payload library:
/// JSON `__proto__`, `constructor.prototype`, lodash-merge / qs-parse
/// bracket-notation, deep-nested-merge variants, MongoDB `$where`
/// gadget. Covers Express, lodash, jQuery, Mongoose, Hoek vulnerable
/// libraries.
pub mod proto_pollution;
/// Server-Side Template Injection (SSTI) sandbox-escape library
/// across 12 template engines: Jinja2 (3 escape vectors), Twig,
/// Smarty (PHP block + write-file), Freemarker (Execute + Spring),
/// Velocity, ERB (direct + Kernel.const_get bypass), Handlebars,
/// Nunjucks, Pebble, Liquid (SSRF), Mako, Razor, AngularJS legacy.
/// Plus a 6-probe engine-fingerprint set.
pub mod ssti_escape;
/// SAML XML Signature Wrapping (XSW1-XSW8) attack library per
/// Somorovsky USENIX Security 2012. Re-shape a signed SAML response
/// so the verifier validates the original assertion but the consumer
/// reads attacker-controlled data. Every commercial SSO has shipped
/// at least one XSW vulnerability — XSW7/XSW8 are still common.
pub mod saml_xsw;
/// Cookie-layer attack library: cookie tossing (parent-domain plant),
/// path tossing, jar overflow, quote encapsulation, double-encoded
/// values, `__Host-`/`__Secure-` prefix violations, CRLF injection
/// in Set-Cookie values, SameSite=None over plaintext, unpartitioned
/// merge, name-whitespace confusion, duplicate-cookie precedence,
/// oversized-cookie proxy truncation.
pub mod cookie_attacks;
/// CSV / spreadsheet formula injection (CWE-1236): DDE, HYPERLINK
/// phishing, WEBSERVICE exfil (Excel 2013+), IMPORTDATA / IMPORTXML
/// (Google Sheets), +/-/@/TAB/CR/LF formula prefixes, CSV row
/// injection, quoted-formula evasion, R1C1 reference, XLM EXEC()
/// macro. Bypasses sanitizers that scan for XSS/SQLi but not formula
/// triggers.
pub mod csv_formula;
/// HTTP method-override confusion: framework re-interprets the
/// request method from `X-HTTP-Method-Override` header (3 name
/// variants), `_method` form field / query / multipart, chunked
/// trailer, or header+form disagreement. Wire method shown to WAF
/// is POST; framework executes DELETE/PUT/PATCH/etc.
pub mod method_override;
/// HTTP cache poisoning payloads: X-Forwarded-Host/Scheme/Port,
/// X-Original-URL, X-Host (Akamai), Forwarded (RFC 7239),
/// X-Backend-Host, loopback-trust headers, web cache deception
/// paths (5 extensions × null-byte / semicolon / traversal forms),
/// cache key normalization variants, Vary header confusion, status
/// code poisoning, HTTP/2 :authority split.
pub mod cache_poison;
/// Mass-assignment + HTTP Parameter Pollution (HPP) payload library:
/// flat (`is_admin=true`), Rails-nested (`user[admin]=true`), Spring
/// dotted (`user.admin=true`), JSON-nested, arbitrary-depth nested,
/// HPP first/last/comma-list disagreement, URL-encoded alias
/// duplicates, CSRF-bundled mass-assign, CRLF-in-form-value
/// sub-field smuggling.
pub mod mass_assignment;
/// MongoDB NoSQL operator-injection payload library: `$ne`/`$gt`/
/// `$lt`/`$regex` auth bypass, `$where` + `$function` + `$accumulator`
/// JS evaluation, `$elemMatch` array-auth bypass, `$or` injection,
/// projection injection, aggregation pipeline `$lookup` + `$out` +
/// `$merge` write-injection, JS-string injection for stringified
/// query contexts.
pub mod mongo_nosqli;
/// LDAP injection comprehensive library: search-filter wildcard
/// match, OR-injection logic flip, AND-truncation, NUL-byte
/// truncation, comment-style truncation, auth-bypass username,
/// blind first-char + prefix probes, timing amplification, DN
/// injection (search-base manipulation), Active Directory specific
/// objectClass injection, wildcard-blocklist bypasses (NUL, double,
/// multi-predicate, URL-encoded).
pub mod ldap_inject;
/// XPath injection comprehensive library: classic OR-1-equals-1
/// auth bypass, wildcard position selectors, blind char-by-char
/// extraction, node-name reconstruction, XPath 2.0 `doc()` SSRF +
/// file-read, `unparsed-text()`, `system-property()` fingerprint,
/// XPath 2.0 comment-syntax bypass, divide-by-zero error reveal,
/// `count()` probes, `position()` filters, CDATA-XSS for XML-
/// returning consumers.
pub mod xpath_inject;
/// OS command-injection comprehensive evasion library across bash /
/// cmd.exe / PowerShell: brace expansion, ${IFS} whitespace bypass,
/// tab IFS, backslash quoting, single-quote split, ANSI-C `$'...'`
/// hex byte embed, variable indirection, backtick + `$()` subst,
/// here-string, `/dev/tcp/` reverse shell, Windows `^` escape,
/// `%PATH:~N,M%` substring extract, PowerShell `iex` download,
/// `-EncodedCommand` UTF-16LE base64, `[char]` casting, perl/python
/// reverse-shell one-liners.
pub mod cmd_inject;
/// XML External Entity (XXE) comprehensive attack library: classic
/// file-read, Windows file paths, HTTP SSRF, AWS IMDS, internal-
/// service SSRF, parameter-entity (`%xxe`) blind XXE, remote-DTD
/// blind XXE, Billion Laughs (9-level recursive expansion),
/// quadratic blowup, SVG-wrapped XXE for image consumers, SOAP
/// envelope XXE, JSON-as-XML XXE, Phithon local-DTD-reuse trick.
pub mod xxe_attacks;
/// SSRF scheme-confusion payload library: `gopher://` arbitrary-
/// protocol injection (Redis SLAVEOF, memcached, SMTP relay),
/// `dict://` memcached/Redis probes, `file://` reads, `ldap://`
/// JNDI Log4Shell-class, `jar://` Java remote archive, `netdoc://`
/// Java-only, `tftp://` UDP, `smtp://` direct relay. Plus IP-shape
/// bypasses (decimal/hex/octal/mixed-base) and IPv6 v4-mapped +
/// 6to4 cloak.
pub mod ssrf_schemes;
/// Multi-strategy layering and aggressiveness scoring.
pub mod layered;
/// Strategy enum and encode() dispatcher.
pub mod strategy;
/// Structural encoding strategies (null byte, overlong UTF-8, chunked, HPP).
pub mod structural;
/// Unicode and HTML entity encoding strategies.
pub mod unicode;
/// URL-based encoding strategies (single, double, triple).
pub mod url;

#[cfg(test)]
mod tests;

// Re-export everything for backwards compatibility (LAW 2).
pub use layered::{aggressiveness, encode_layered, layered_combinations};
pub use strategy::{Strategy, all_strategies, encode};
