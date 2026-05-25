-- shadowd bench database initialisation.
-- Loaded by postgres:15-alpine on first startup via /docker-entrypoint-initdb.d/.
-- The pgsql_layout.sql schema is run first (alphabetically); this file adds the
-- bench profile on top of it.

-- Profile 1: wafrift bench profile.
-- mode=1        → enforcement (block on threat, not detect-only)
-- blacklist_enabled=1, whitelist_enabled=0, integrity_enabled=0, flooding_enabled=0
-- blacklist_threshold=10  → block when accumulated filter score ≥ 10
-- hmac_key      → must match the key in shadowd.ini / connector config
INSERT INTO profiles (
    id,
    server_ip,
    name,
    hmac_key,
    mode,
    whitelist_enabled,
    blacklist_enabled,
    integrity_enabled,
    flooding_enabled,
    blacklist_threshold,
    flooding_timeframe,
    flooding_threshold,
    cache_outdated
) VALUES (
    1,
    '*',
    'wafrift-bench',
    'wafrift-bench-key-2026',
    1,
    0,
    1,
    0,
    0,
    10,
    60,
    100,
    0
) ON CONFLICT DO NOTHING;

-- Reset the profiles sequence so future auto-inserts don't collide.
SELECT setval('profiles_id_seq', (SELECT MAX(id) FROM profiles));

-- Blacklist rules: catch-all wildcard rule for all paths and all callers.
--
-- The shadowd daemon uses blacklist_rules to decide WHICH parameters to score
-- against the blacklist_filters regex library. Without at least one matching
-- rule, the daemon skips blacklist scoring entirely and returns status=1 (OK).
--
-- path='*'   → prepare_wildcard converts to '%', matching any parameter path
-- caller='*' → matches any PHP script (SCRIPT_FILENAME)
-- threshold=5 → block when total filter impact >= 5 (catches most SQLi/XSS combos)
-- status=1   → rule is active
INSERT INTO blacklist_rules (profile_id, path, caller, threshold, status)
VALUES (1, '*', '*', 5, 1)
ON CONFLICT DO NOTHING;

SELECT setval('blacklist_rules_id_seq', (SELECT MAX(id) FROM blacklist_rules));
