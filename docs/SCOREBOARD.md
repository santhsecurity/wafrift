# WafRift bypass scoreboard

_Generated 2026-06-05 from `wafrift-bench/results/` via `wafrift-bench/scripts/render-scoreboard.py`. Numbers are the **verified-bypass** rate per payload class — oracle-gated, transport-reached, no inflation. Cell = % of variants for that class that wafrift found a working bypass for; `—` = class not exercised on that stack._

| class | modsec-pl1 | modsec-pl2 | modsec-pl3 | modsec-pl4 | coraza | bunkerweb | naxsi |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| sql | 40.2 | 39.0 | 39.7 | 27.3 | 8.7 | 39.4 | 30.0 |
| xss | — | — | — | 25.9 | — | — | — |
| cmdi | — | — | — | 27.3 | — | — | — |
| ssti | — | — | — | 27.6 | — | — | — |
| path | — | — | — | 28.4 | — | — | — |
| ldap | — | — | — | 28.8 | — | — | — |
| xxe | — | — | — | 25.8 | — | — | — |
| ssrf | — | — | — | 26.5 | — | — | — |
| nosql | — | — | — | 29.3 | — | — | — |
| log4shell | — | — | — | 30.4 | — | — | — |

## Per-stack roll-up

| stack | classes exercised | total variants | total bypassed | overall rate |
|---|---:|---:|---:|---:|
| modsec-pl1 | 1 | 1,730 | 696 | 40.2% |
| modsec-pl2 | 1 | 1,730 | 675 | 39.0% |
| modsec-pl3 | 1 | 1,730 | 686 | 39.7% |
| modsec-pl4 | 10 | 59,941 | 16,319 | 27.2% |
| coraza | 1 | 1,730 | 150 | 8.7% |
| bunkerweb | 1 | 1,730 | 682 | 39.4% |
| naxsi | 1 | 1,730 | 519 | 30.0% |

## Source

Latest result file picked per stack:

- `v022-quotefree-modsec-pl1.json` -> **modsec-pl1**
- `v022-quotefree-modsec-pl2.json` -> **modsec-pl2**
- `v022-quotefree-modsec-pl3.json` -> **modsec-pl3**
- `modsec-pl4-multi.json` -> **modsec-pl4**
- `v022-quotefree-coraza.json` -> **coraza**
- `v022-quotefree-bunkerweb.json` -> **bunkerweb**
- `v022-quotefree-naxsi.json` -> **naxsi**

## Reproduce

```bash
# Bring up one stack
wafrift-bench/scripts/up.sh modsec-pl4

# Run the full bench with verified-bypass gating
cargo run --release -p wafrift-cli -- bench-waf \
    --base-url http://127.0.0.1:18084 \
    --corpus wafrift-bench/corpus \
    --evade --variants 20 \
    --strategies heavy,mcts,smuggling,content-type,redos,hill-climb,sim-anneal,tabu,novelty,map-elites,differential \
    --oracle-gate \
    --format json \
    --output wafrift-bench/results/modsec-pl4-$(date -u +%Y%m%d).json

# Re-render the scoreboard
wafrift-bench/scripts/render-scoreboard.py wafrift-bench/results/ \
    > docs/SCOREBOARD.md
```
