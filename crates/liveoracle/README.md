# wafrift-liveoracle

The **calibrated live oracle**, extracted from the wafrift CLI so any tool can
reuse it (split out of the CLI monolith).

- `verdict` — map a live response to `Allowed` / `Blocked` / `Transient` using
  the status code AND a Tier-B set of block-page body signatures, then drive a
  bounded transient retry (honouring `Retry-After`) so rate-limiting degrades to
  "inconclusive", never a wrong answer. Kills the two classic reliability bugs:
  a 200-served block page read as a pass, and a 429 read as a block.
- `calibration` — learn THIS target's block signal from benign/malicious control
  probes (reflection-aware), so a bespoke 200 block page no signature lists is
  still caught.

The core is pure and network-free: the probe and the sleep are injected, so the
whole oracle is unit-testable offline.
