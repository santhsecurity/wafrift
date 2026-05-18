//! Windows cmd.exe command injection grammar-aware mutation.
//!
//! Handles `cmd.exe`-specific syntax: caret escaping, `cmd /c`, `for /f`,
//! `set /p`, quote escaping, and `%variable%` expansion.

/// A single Windows CMD mutation with metadata.
#[derive(Debug, Clone)]
pub struct CmdWindowsMutation {
    /// The mutated payload.
    pub payload: String,
    /// Human-readable description of what changed.
    pub description: String,
    /// Which mutation rules were applied.
    pub rules_applied: Vec<&'static str>,
}

/// Detect Windows cmd.exe-specific signals.
#[must_use]
pub fn detect_type(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    lower.contains("cmd ")
        || lower.contains("cmd.exe")
        || lower.contains('^')
        || lower.contains("for /f")
        || lower.contains("set /p")
        || lower.contains("%comspec%")
        || (lower.contains("type ") && !lower.contains("typeof"))
        || lower.contains("dir ")
        || lower.contains("findstr ")
        || lower.contains("powershell")
        || lower.contains("certutil")
}

/// Obfuscate a command using caret insertion (`c^a^t`).
fn caret_obfuscate(cmd: &str) -> String {
    cmd.chars()
        .map(|c| format!("{c}^"))
        .collect::<String>()
        .trim_end_matches('^')
        .to_string()
}

/// Generate Windows cmd.exe grammar-aware mutations.
#[must_use]
pub fn mutate(payload: &str, max_mutations: usize) -> Vec<CmdWindowsMutation> {
    if payload.is_empty() || max_mutations == 0 || !detect_type(payload) {
        return Vec::new();
    }
    let mut results = Vec::new();
    let lower = payload.to_ascii_lowercase();

    // Strategy 1: Caret escaping of common commands
    let cmds = ["type", "dir", "findstr", "certutil", "powershell", "cmd"];
    for cmd in &cmds {
        if lower.contains(cmd) {
            let obf = caret_obfuscate(cmd);
            let mutated = payload
                .replace(cmd, &obf)
                .replace(&cmd.to_ascii_uppercase(), &obf);
            if mutated != payload {
                results.push(CmdWindowsMutation {
                    payload: mutated,
                    description: format!("caret escape: {cmd} → {obf}"),
                    rules_applied: vec!["caret_escape"],
                });
            }
        }
    }

    // Strategy 2: cmd /c wrapper
    results.push(CmdWindowsMutation {
        payload: format!("cmd /c \"{payload}\""),
        description: "cmd /c wrapper".into(),
        rules_applied: vec!["cmd_wrapper"],
    });
    results.push(CmdWindowsMutation {
        payload: format!("cmd.exe /c {payload}"),
        description: "cmd.exe /c wrapper".into(),
        rules_applied: vec!["cmd_wrapper"],
    });

    // Strategy 3: COMSPEC indirection
    results.push(CmdWindowsMutation {
        payload: format!("%comspec% /c {payload}"),
        description: "%COMSPEC% indirection".into(),
        rules_applied: vec!["comspec"],
    });

    // Strategy 4: for /f loop indirection
    results.push(CmdWindowsMutation {
        payload: format!("for /f \"tokens=*\" %a in ('{payload}') do %a"),
        description: "for /f loop indirection".into(),
        rules_applied: vec!["for_loop"],
    });

    // Strategy 5: set /p variable trick
    results.push(CmdWindowsMutation {
        payload: format!("set /p ={payload}<nul"),
        description: "set /p redirection trick".into(),
        rules_applied: vec!["set_p"],
    });

    // Strategy 6: Quote escaping
    results.push(CmdWindowsMutation {
        payload: format!("{payload}\"\"\" "),
        description: "quote escape padding".into(),
        rules_applied: vec!["quote_escape"],
    });

    // Strategy 7: Variable expansion bypass.
    // `echo %TMP%` discards the operator's command entirely — a canned
    // non-attack. For a structured attack that is the cmdi rig (a probe
    // shipped instead of the exploit); only emit it for a bare,
    // non-structured input where an env-echo probe is itself the test.
    if !crate::grammar::cmd::is_structured_cmd(payload) {
        let var_expansions = [
            ("%pATh%", "%PATH% expansion case-mixed"),
            ("%tMp%", "%TMP% expansion"),
            ("%wiNDir%", "%WINDIR% expansion"),
        ];
        for (var, desc) in &var_expansions {
            results.push(CmdWindowsMutation {
                payload: format!("echo {var}"),
                description: (*desc).into(),
                rules_applied: vec!["var_expansion"],
            });
        }
    }

    // Strategy 8: PowerShell obfuscation via cmd
    results.push(CmdWindowsMutation {
        payload: format!("powershell -nop -c \"{payload}\""),
        description: "powershell -nop -c wrapper".into(),
        rules_applied: vec!["ps_wrapper"],
    });

    results.truncate(max_mutations);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cmd_signals() {
        assert!(detect_type("cmd /c dir"));
        assert!(detect_type("t^y^p^e file.txt"));
        assert!(detect_type("for /f \"tokens=*\" %a in ('dir') do %a"));
    }

    #[test]
    fn caret_obfuscation_works() {
        assert_eq!(caret_obfuscate("type"), "t^y^p^e");
        assert_eq!(caret_obfuscate("dir"), "d^i^r");
    }

    #[test]
    fn generates_cmd_wrapper() {
        let mutations = mutate("dir C:\\", 10);
        assert!(mutations.iter().any(|m| m.payload.contains("cmd /c")));
    }

    #[test]
    fn generates_for_loop() {
        let mutations = mutate("dir C:\\", 10);
        assert!(mutations.iter().any(|m| m.payload.contains("for /f")));
    }

    #[test]
    fn rejects_non_windows_cmd() {
        assert!(!detect_type("; cat /etc/passwd"));
        assert!(mutate("hello world", 10).is_empty());
    }

    #[test]
    fn generates_comspec_variant() {
        let mutations = mutate("dir C:\\", 10);
        assert!(mutations.iter().any(|m| m.payload.contains("%comspec%")));
    }

    #[test]
    fn generates_powershell_wrapper() {
        let mutations = mutate("powershell Get-Process", 15);
        assert!(
            mutations
                .iter()
                .any(|m| m.payload.contains("powershell -nop"))
        );
    }

    #[test]
    fn max_mutations_respected() {
        let mutations = mutate("dir C:\\", 3);
        assert!(mutations.len() <= 3);
    }

    #[test]
    fn set_p_trick_generated() {
        let mutations = mutate("dir C:\\", 10);
        assert!(mutations.iter().any(|m| m.payload.contains("set /p")));
    }

    #[test]
    fn empty_payload_returns_empty() {
        assert!(mutate("", 10).is_empty());
    }
}
