//! Integration: `dispatch` routes each [`ChallengeKind`] to the correct [`SolveAction`],
//! with negative twins (wrong branch) guarded per kind.

use std::time::Duration;
use wafrift_transport::challenge::{
    ChallengeKind, ChallengeStore, SolveAction, dispatch,
};

fn escalate_reason(kind: ChallengeKind) -> String {
    format!("{} requires interactive solve", kind.label())
}

#[test]
fn dispatch_matrix_without_cookie_cookie_solvable_kinds_wait() {
    let store = ChallengeStore::new();
    for kind in [ChallengeKind::CloudflareManaged, ChallengeKind::AkamaiBmp] {
        let action = dispatch("wait-target.test", kind, &store);
        match action {
            SolveAction::Wait { delay } => {
                let ms = delay.as_millis() as u64;
                assert!(
                    (1000..=3000).contains(&ms),
                    "Fix: jittered Wait must stay within base 2s ±25% (~1–3s); got {ms}ms"
                );
            }
            other => panic!(
                "Fix: {:?} without cookie must Wait for external solver — got {other:?}",
                kind
            ),
        }
    }
}

#[test]
fn dispatch_matrix_without_cookie_interactive_kinds_escalate() {
    let store = ChallengeStore::new();
    for kind in [
        ChallengeKind::Turnstile,
        ChallengeKind::Hcaptcha,
        ChallengeKind::Recaptcha,
        // AwsWaf moved to cookie-solvable in the 2026-05-10 audit
        // because extract_clearance_cookie already stored aws-waf-token
        // entries — the previous escalate-only path silently discarded
        // captured tokens.
        ChallengeKind::Unknown,
    ] {
        let action = dispatch("escalate-target.test", kind, &store);
        match &action {
            SolveAction::EscalateToOperator { kind: k, reason } => {
                assert_eq!(*k, kind);
                assert_eq!(reason, &escalate_reason(kind));
            }
            other => panic!(
                "Fix: {:?} without cookie must EscalateToOperator — got {other:?}",
                kind
            ),
        }
    }
}

#[test]
fn negative_twin_cookie_solvable_without_cookie_must_not_escalate() {
    let store = ChallengeStore::new();
    let action = dispatch("neg-cf.test", ChallengeKind::CloudflareManaged, &store);
    assert!(
        !matches!(action, SolveAction::EscalateToOperator { .. }),
        "Fix: CloudflareManaged without cookie escalates only when misclassified — got {action:?}"
    );
    assert!(
        matches!(action, SolveAction::Wait { .. }),
        "Fix: expected Wait, got {action:?}"
    );
}

#[test]
fn negative_twin_interactive_without_cookie_must_not_wait() {
    let store = ChallengeStore::new();
    let action = dispatch("neg-hc.test", ChallengeKind::Hcaptcha, &store);
    assert!(
        !matches!(action, SolveAction::Wait { .. }),
        "Fix: Hcaptcha must never Wait — needs human; got {action:?}"
    );
}

#[test]
fn dispatch_replays_for_every_kind_when_store_has_active_cookie() {
    let store = ChallengeStore::new();
    let matrix: &[(ChallengeKind, &str)] = &[
        (ChallengeKind::CloudflareManaged, "cf_clearance=cf"),
        (ChallengeKind::AkamaiBmp, "_abck=ak"),
        (ChallengeKind::Turnstile, "cf_clearance=ts"),
        (ChallengeKind::Hcaptcha, "cf_clearance=hc"),
        (ChallengeKind::Recaptcha, "cf_clearance=rc"),
        (ChallengeKind::AwsWaf, "aws-waf-token=aws"),
        (ChallengeKind::Unknown, "cf_clearance=un"),
    ];

    for (kind, cookie) in matrix {
        let host = format!("replay-{host}.test", host = kind.label().replace('.', "_"));
        store.record(&host, *cookie, *kind, None);
        let action = dispatch(&host, *kind, &store);
        match action {
            SolveAction::ReplayWithCookie { cookie_header } => {
                assert_eq!(
                    cookie_header, *cookie,
                    "Fix: replay must echo stored Cookie: line exactly"
                );
            }
            other => panic!(
                "Fix: stored cookie for {:?} must force ReplayWithCookie — got {other:?}",
                kind
            ),
        }
    }
}

#[test]
fn negative_twin_escalate_kind_with_cookie_must_not_escalate() {
    let store = ChallengeStore::new();
    store.record(
        "turnstile-seeded.test",
        "cf_clearance=manual_turnstile",
        ChallengeKind::Turnstile,
        None,
    );
    let action = dispatch(
        "turnstile-seeded.test",
        ChallengeKind::Turnstile,
        &store,
    );
    assert!(
        matches!(action, SolveAction::ReplayWithCookie { .. }),
        "Fix: after manual solve Turnstile must replay cookie, not re-escalate — got {action:?}"
    );
    assert!(
        !matches!(action, SolveAction::EscalateToOperator { .. }),
        "Fix: must not Escalate when clearance cookie present"
    );
}

#[test]
fn negative_twin_wait_kind_with_cookie_must_not_wait() {
    let store = ChallengeStore::new();
    store.record(
        "cf-managed-seeded.test",
        "cf_clearance=ready",
        ChallengeKind::CloudflareManaged,
        None,
    );
    let action = dispatch(
        "cf-managed-seeded.test",
        ChallengeKind::CloudflareManaged,
        &store,
    );
    assert!(
        matches!(action, SolveAction::ReplayWithCookie { .. }),
        "Fix: cookie present must skip Wait — got {action:?}"
    );
}

#[test]
fn dispatch_wait_jitter_spreads_across_back_to_back_calls() {
    let store = ChallengeStore::new();
    let mut distinct_ms = std::collections::HashSet::new();
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(2));
        match dispatch("jitter.test", ChallengeKind::AkamaiBmp, &store) {
            SolveAction::Wait { delay } => {
                distinct_ms.insert(delay.as_millis());
            }
            other => panic!("expected Wait for AkamaiBmp without cookie — got {other:?}"),
        }
    }
    assert!(
        distinct_ms.len() > 1,
        "Fix: jitter must desynchronize retries — got only {} distinct delays",
        distinct_ms.len()
    );
}
