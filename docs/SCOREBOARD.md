# WafRift bypass scoreboard

_Generated 2026-07-21 from `wafrift-bench/results/` via `wafrift-bench/scripts/render-scoreboard.py`. Numbers are the **verified-bypass** rate per payload class — oracle-gated, transport-reached, no inflation. Cell = % of variants for that class that wafrift found a working bypass for; `—` = class not exercised on that stack._

| class | modsec-pl1 | modsec-pl2 | modsec-pl3 | modsec-pl4 | coraza | bunkerweb | naxsi |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| sql | 33.7 | 30.3 | 30.1 | 27.3 | 8.7 | 39.4 | 30.0 |
| xss | 28.6 | 26.2 | 26.2 | 25.9 | — | — | — |
| cmdi | 44.8 | 29.0 | 28.9 | 27.3 | — | — | — |
| ssti | 42.8 | 32.1 | 30.8 | 27.6 | — | — | — |
| path | 37.8 | 29.7 | 29.1 | 28.4 | — | — | — |
| ldap | 55.7 | 38.5 | 29.5 | 28.8 | — | — | — |
| xxe | 27.3 | 25.9 | 25.9 | 25.8 | — | — | — |
| ssrf | 43.0 | 27.1 | 27.4 | 26.5 | — | — | — |
| nosql | 45.0 | 33.1 | 30.7 | 29.3 | — | — | — |
| log4shell | 41.7 | 33.0 | 32.0 | 30.4 | — | — | — |

## Per-stack roll-up

| stack | classes exercised | total variants | total bypassed | overall rate |
|---|---:|---:|---:|---:|
| modsec-pl1 | 10 | 59,941 | 21,857 | 36.5% |
| modsec-pl2 | 10 | 59,941 | 17,571 | 29.3% |
| modsec-pl3 | 10 | 59,941 | 17,260 | 28.8% |
| modsec-pl4 | 10 | 59,941 | 16,319 | 27.2% |
| coraza | 1 | 1,730 | 150 | 8.7% |
| bunkerweb | 1 | 1,730 | 682 | 39.4% |
| naxsi | 1 | 1,730 | 519 | 30.0% |

## Source

Latest result file picked per stack:

- `modsec-pl1-multi-with-ast.json` -> **modsec-pl1**
- `modsec-pl2-multi.json` -> **modsec-pl2**
- `modsec-pl3-multi.json` -> **modsec-pl3**
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
