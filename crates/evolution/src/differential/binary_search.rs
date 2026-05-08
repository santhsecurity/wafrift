use super::probe::{
    Probe, ProbeTarget, baseline_probe, command_path_probes, command_separator_probes,
    sql_keyword_probes, sql_tautology_probes, xss_event_probes, xss_function_probes,
    xss_tag_probes,
};

/// High-level probe family used to narrow the search space quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFamily {
    Sql,
    Xss,
    Command,
}

/// Generate a minimal first-pass probe set for quick analysis.
#[must_use]
pub fn generate_quick_probes() -> Vec<Probe> {
    let mut probes = Vec::new();
    probes.push(baseline_probe("test_benign", "baseline"));
    probes.extend(generate_family_probes(ProbeFamily::Sql));
    probes.extend(generate_family_probes(ProbeFamily::Xss));
    probes.extend(generate_family_probes(ProbeFamily::Command));
    probes
}

/// Generate a focused probe batch for one family during staged analysis.
#[must_use]
pub fn generate_family_probes(family: ProbeFamily) -> Vec<Probe> {
    match family {
        ProbeFamily::Sql => vec![
            Probe {
                payload: "' OR 1=1--".into(),
                tests: ProbeTarget::SqlTautology("1=1".into()),
                description: "classic SQLi".into(),
                expected_blocked: true,
            },
            Probe {
                payload: "test SELECT test".into(),
                tests: ProbeTarget::SqlKeyword("SELECT".into()),
                description: "SQL keyword".into(),
                expected_blocked: true,
            },
            Probe {
                payload: "test UNION test".into(),
                tests: ProbeTarget::SqlKeyword("UNION".into()),
                description: "SQL UNION".into(),
                expected_blocked: true,
            },
            Probe {
                payload: "'".into(),
                tests: ProbeTarget::SqlQuote,
                description: "single quote".into(),
                expected_blocked: true,
            },
        ],
        ProbeFamily::Xss => {
            let mut tags = xss_tag_probes();
            let mut events = xss_event_probes();
            let mut funcs = xss_function_probes();
            vec![
                tags.remove(0),
                tags.remove(0),
                tags.remove(0),
                events.remove(0),
                funcs.remove(0),
                funcs.remove(5.min(funcs.len().saturating_sub(1))),
            ]
        }
        ProbeFamily::Command => {
            let mut seps = command_separator_probes();
            let mut paths = command_path_probes();
            vec![seps.remove(0), seps.remove(0), paths.remove(0)]
        }
    }
}

/// Generate focused follow-up probes for families that blocked in the quick pass.
#[must_use]
pub fn generate_follow_up_probes(families: &[ProbeFamily]) -> Vec<Probe> {
    let mut probes = Vec::new();
    for family in families {
        probes.extend(match family {
            ProbeFamily::Sql => {
                let mut sql = sql_keyword_probes();
                sql.extend(sql_tautology_probes());
                sql
            }
            ProbeFamily::Xss => {
                let mut xss = xss_tag_probes();
                xss.extend(xss_event_probes());
                xss.extend(xss_function_probes());
                xss
            }
            ProbeFamily::Command => {
                let mut command = command_separator_probes();
                command.extend(command_path_probes());
                command
            }
        });
    }
    probes
}

/// Result of a binary search narrowing operation.
#[derive(Debug, Clone)]
pub struct NarrowingResult {
    pub trigger: String,
    pub start: usize,
    pub end: usize,
    pub probes_sent: usize,
    pub description: String,
}

/// Binary search to find the minimum substring that triggers a WAF block.
pub fn narrow_to_trigger(payload: &str, is_blocked: &dyn Fn(&str) -> bool) -> NarrowingResult {
    let chars: Vec<char> = payload.chars().collect();
    let len = chars.len();
    let mut probes_sent = 0usize;
    if len == 0 {
        return NarrowingResult {
            trigger: String::new(),
            start: 0,
            end: 0,
            probes_sent,
            description: "Empty payload cannot be narrowed".to_string(),
        };
    }

    probes_sent += 1;
    if !is_blocked(payload) {
        return NarrowingResult {
            trigger: payload.to_string(),
            start: 0,
            end: len,
            probes_sent,
            description: "Payload did not trigger a block during narrowing".to_string(),
        };
    }

    let mut start = 0usize;
    let mut end = len;

    loop {
        let removable_prefix =
            max_removable_prefix(&chars, start, end, is_blocked, &mut probes_sent);
        if removable_prefix > 0 {
            start += removable_prefix;
        }

        let removable_suffix =
            max_removable_suffix(&chars, start, end, is_blocked, &mut probes_sent);
        if removable_suffix > 0 {
            end -= removable_suffix;
        }

        if removable_prefix == 0 && removable_suffix == 0 {
            break;
        }
    }

    let trigger: String = chars[start..end].iter().collect();
    probes_sent += 1;
    let still_blocked = is_blocked(&trigger);

    NarrowingResult {
        trigger: trigger.clone(),
        start,
        end,
        probes_sent,
        description: if still_blocked {
            format!(
                "WAF trigger narrowed to '{}' ({} chars, positions {}-{} of {} char payload)",
                if trigger.len() > 50 {
                    &trigger[..50]
                } else {
                    &trigger
                },
                end - start,
                start,
                end,
                len
            )
        } else {
            "Could not narrow trigger (payload may use context-dependent matching)".to_string()
        },
    }
}

fn max_removable_prefix(
    chars: &[char],
    start: usize,
    end: usize,
    is_blocked: &dyn Fn(&str) -> bool,
    probes_sent: &mut usize,
) -> usize {
    if end.saturating_sub(start) <= 1 {
        return 0;
    }
    let mut lo = 0usize;
    let mut hi = end - start - 1;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let candidate: String = chars[start + mid..end].iter().collect();
        *probes_sent += 1;
        if is_blocked(&candidate) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn max_removable_suffix(
    chars: &[char],
    start: usize,
    end: usize,
    is_blocked: &dyn Fn(&str) -> bool,
    probes_sent: &mut usize,
) -> usize {
    if end.saturating_sub(start) <= 1 {
        return 0;
    }
    let mut lo = 0usize;
    let mut hi = end - start - 1;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let candidate: String = chars[start..end - mid].iter().collect();
        *probes_sent += 1;
        if is_blocked(&candidate) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Find multiple independent triggers in a single payload.
pub fn find_all_triggers(payload: &str, is_blocked: &dyn Fn(&str) -> bool) -> Vec<NarrowingResult> {
    let mut triggers = Vec::new();
    let mut remaining = payload.to_string();

    for _ in 0..5 {
        if !is_blocked(&remaining) {
            break;
        }
        let result = narrow_to_trigger(&remaining, is_blocked);
        if result.trigger.is_empty() || result.end <= result.start {
            break;
        }
        let masked: String = remaining
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i >= result.start && i < result.end {
                    'X'
                } else {
                    c
                }
            })
            .collect();
        triggers.push(result);
        remaining = masked;
    }

    triggers
}

#[cfg(test)]
mod tests {
    use super::{
        ProbeFamily, find_all_triggers, generate_family_probes, generate_follow_up_probes,
        generate_quick_probes, narrow_to_trigger,
    };

    #[test]
    fn quick_probes_smaller_set() {
        let quick = generate_quick_probes();
        assert!(quick.len() >= 10);
    }

    #[test]
    fn family_probes_are_focused() {
        assert_eq!(generate_family_probes(ProbeFamily::Sql).len(), 4);
        assert_eq!(generate_family_probes(ProbeFamily::Command).len(), 3);
    }

    #[test]
    fn follow_up_probes_expand_requested_families() {
        let sql_only = generate_follow_up_probes(&[ProbeFamily::Sql]);
        let both = generate_follow_up_probes(&[ProbeFamily::Sql, ProbeFamily::Xss]);
        assert!(both.len() > sql_only.len());
    }

    #[test]
    fn narrow_to_trigger_finds_minimal_substring() {
        let payload = "prefixUNIONsuffix";
        let result = narrow_to_trigger(payload, &|candidate| candidate.contains("UNION"));
        assert_eq!(result.trigger, "UNION");
        assert_eq!(result.start, 6);
        assert_eq!(result.end, 11);
    }

    #[test]
    fn find_all_triggers_masks_and_finds_multiple_regions() {
        let payload = "aaaUNIONbbbSELECTccc";
        let results = find_all_triggers(payload, &|candidate| {
            candidate.contains("UNION") || candidate.contains("SELECT")
        });
        let triggers: Vec<_> = results
            .iter()
            .map(|result| result.trigger.as_str())
            .collect();
        assert!(triggers.contains(&"UNION"));
        assert!(triggers.contains(&"SELECT"));
    }
}
