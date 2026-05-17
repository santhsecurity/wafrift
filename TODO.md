# WafRift — Dogfooding Findings

> Captured during real usage. Every item here is a friction point a bug bounty hunter will hit in the field.

## 2026-05-17

- [ ] **UX**: `evade` with `--only encoding/base64/standard` on SQL payload returns "No variants generated"
  - Severity: MEDIUM (user cannot tell if technique is broken or payload is incompatible)
  - Context: Testing evasion engine on a simple SQL payload to verify the build
  - Impact: Unclear whether the technique is unsupported, the payload is incompatible, or there's a bug
  - Repro: `wafrift evade --payload "SELECT * FROM users WHERE id=1" --only encoding/base64/standard`
  - Actual: `No variants generated for the supplied payload.` (exit code 1)
  - Expected: Either (a) a base64-encoded variant, or (b) a clear explanation like
    `"encoding/base64/standard" is not applicable to non-HTTP payloads. This technique operates on request bodies/headers.`
  - Suggestion: Add `--explain` flag to `evade` that shows WHY each technique was or wasn't applied, with technique-specific applicability rules

- [ ] **FEATURE**: `evade` should support stdin / pipe input
  - Context: Wanted to pipe a payload from another tool
  - Impact: Forces writing temp files or using shell quoting gymnastics
  - Suggestion: `echo 'payload' | wafrift evade --stdin --only encoding/base64/standard`

- [ ] **FEATURE**: Add `--target-context` to `evade` (header, body, query-param, cookie)
  - Context: Encoding techniques behave differently depending on where the payload lands
  - Impact: Base64 in a header is different from base64 in a JSON body
  - Suggestion: `wafrift evade --payload "..." --target-context header --only encoding/base64/standard`
