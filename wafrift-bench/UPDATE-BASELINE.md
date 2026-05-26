# Updating the canonical PL4 baseline

The CI gate in `.github/workflows/bench-gate.yml` measures every PR's PL4 bypass
rate against `wafrift-bench/canonical-baseline.json`. The gate fails if the rate
drops by more than 2 percentage points below `oracle_valid_rate`. When a
deliberate improvement lands — new strategy, corpus expansion, engine upgrade —
run the canonical bench locally (`./target/release/wafrift bench-waf --base-url
http://localhost:18084 --corpus wafrift-bench/corpus --evade --strategies
heavy,equiv-cegis --variants 5 --format json --output /tmp/bench.json
--summary-only`), extract the new `oracle_valid_rate` from `/tmp/bench.json`,
update `oracle_valid_rate` in this file to the verified number, update `date` to
today, and commit both changes in the same PR that contains the improvement. Never
lower the baseline to paper over a regression; the baseline should only ever move
upward (or stay the same after a neutral refactor that reconfirms the number).
