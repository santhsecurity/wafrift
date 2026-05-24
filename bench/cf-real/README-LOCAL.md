# Local mock for `bench/cf-real`

The Cloudflare Worker at `worker/src/index.ts` requires `wrangler
deploy` against an authenticated account. For CI / offline
development, a Rust port of the same endpoint shape is bundled
under the cli crate at `crates/cli/tests/cf_real_mock.rs` so the
operator can:

* Verify wafrift's wire shapes match what the deployed Worker
  expects, WITHOUT spending a Cloudflare request quota.
* Run `cargo test -p wafrift-cli --test cf_real_mock_smoke`
  against the in-process mock to catch endpoint drift between
  the TS Worker and the Rust harness.

When you make a change to `worker/src/index.ts`, mirror it into
`crates/cli/tests/cf_real_mock.rs` and run the smoke test. The
two sides diverging is a regression — every endpoint the deployed
Worker exposes MUST also exist in the mock (404 from one and 200
from the other = drift).

## Running

```
cargo test --release -p wafrift-cli --test cf_real_mock_smoke
```

The mock binds `127.0.0.1:0` (kernel-assigned port), so multiple
runs don't collide.
