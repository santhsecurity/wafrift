# wafrift-wafmodel

> Decompile a WAF into an executable model. Mine bypasses offline. Prove hole-closure.

A WAF is a black box that answers one question: *does this request reach
the app?* `wafrift-wafmodel` turns that oracle into a **symbolic finite
automaton** via active automaton learning, spending the minimum number of
live queries. Once you have the model:

- **Mine** bypasses offline — intersect the learned pass-language with an
  attack grammar at memory speed, no further live traffic.
- **Solve** the full pipeline — compose the WAF view with the
  normalization transducers (URL/HTML/JSON/multipart) and solve for
  inputs that survive every stage. Normalization-mismatch bypasses
  (double-decode and friends) fall out of the solver; they are not
  hand-coded.
- **Dominate both sides** — the same model drives constrained
  adversarial evasion against ML-WAFs, and provable
  hole-closure (`model ∩ attack-grammar = ∅`) for defenders.

## Modes

```rust
// As a library
use wafrift_wafmodel::{canonicalize, Channel};
let view = canonicalize(&request);
let args = view.channel(Channel::ArgValue);
```

```bash
# As a tool (via the wafrift CLI)
wafrift audit  https://target/      # decompile → report holes
wafrift harden --ruleset crs        # emit verified closing rules
```

Zero-config: pure Rust, no GPU, no external Coraza, no network for the
core. Acceleration (vyre/GPU, live HTTP oracles) is strictly additive.

Part of the [wafrift](https://github.com/santhsecurity/wafrift) workspace.
