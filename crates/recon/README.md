# wafrift-recon

Reconnaissance helpers for `wafrift`: subdomain discovery via
Certificate Transparency, DNS-based origin enumeration, and the
`wafrift discover` triad (OpenAPI parsing, GraphQL introspection,
differential parameter mining).

## Modules

| Module                     | What it does                                                                                  |
|----------------------------|-----------------------------------------------------------------------------------------------|
| `discover_subdomains_ct`   | Query crt.sh's CT-log JSON API for `*.<domain>` certificates. 30s timeout; bounded recovery.  |
| `resolve_origins`          | DNS-resolve discovered subdomains, filter out known WAF/CDN ranges, return likely origin IPs. |
| `discovery::openapi`       | Parse OpenAPI 2.0 (Swagger) + 3.x JSON specs into `DiscoveredEndpoint`s.                      |
| `discovery::graphql`       | POST a `__schema` introspection query and emit one endpoint per top-level field.              |
| `discovery::param_miner`   | Differential param mining: collect baseline, fire wordlist probes, flag divergent responses.  |
| `discovery::context`       | Heuristic mapping from `(content_type, parameter_location, schema_type)` to `InjectionContext`. |

## Output

All discovery functions emit `wafrift_types::discovery::DiscoveredEndpoint`,
which carries the URL, method, and a `Vec<InjectionPoint>` (each
with `name`, `ParameterLocation`, `InjectionContext`, `required`).
This is the same type `wafrift scan --from-discovery` consumes — so
the typical workflow is:

```bash
wafrift discover --spec api.json --format json --output endpoints.json
wafrift scan --from-discovery endpoints.json --target https://api.example.com/...
```

## Safety contract

- `discover_subdomains_ct` and `discovery::param_miner` send live
  requests against the target. The CT-log query hits crt.sh (a
  third party) — disable if the engagement contract forbids
  unauthorised third-party data exposure.
- `param_miner` payloads are inert (`?<word>=wafrift_canary_x9k2`)
  and won't trigger WAF rules. The `differential` *probes* used
  elsewhere in wafrift are NOT inert; see
  `crates/evolution/src/differential/probe.rs` for those.
- Body reads are capped at 4 MiB per probe so a target returning
  a multi-GB response can't OOM the miner.

## License

Dual MIT / Apache-2.0, matching the wafrift workspace.
