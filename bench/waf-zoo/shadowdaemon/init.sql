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
