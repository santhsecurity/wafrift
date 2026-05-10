# wafrift-genome-registry

Wire format + ed25519 signing + trust-list management for the
community-contributed wafrift evasion genome ecosystem.

```rust
use wafrift_genome_registry::{Genome, GenomeBundle, SigningKey, TrustList};

// Sign a bundle of genomes
let key = SigningKey::generate();
let bundle = GenomeBundle::new("my-genomes", vec![Genome::new("akamai-bypass-1", "...")]);
let signed = bundle.sign(&key);

// Distribute as JSON
let wire = signed.to_json().expect("serialize");

// Receiver verifies against trust list
let mut trust = TrustList::new();
trust.allow(key.verifying_key(), "alice");
let received: SignedBundle = serde_json::from_str(&wire).expect("parse");
let verified = received.verify(&trust).expect("trusted publisher");
println!("loaded {} genomes from {}", verified.genomes.len(), verified.bundle_name);
```

## Wire format

A signed bundle is a JSON document:

```json
{
  "bundle": {
    "bundle_name": "akamai-recipes",
    "genomes": [{"name": "...", "payload": "..."}],
    "created_unix": 1715000000
  },
  "signature_hex": "...",
  "public_key_hex": "..."
}
```

The signature is computed over a deterministic JSON serialisation of
the inner bundle (so identical bundles always produce identical
signatures regardless of insertion order).

## Trust list

The trust list lives in `~/.wafrift/trusted-keys.toml`:

```toml
[[publishers]]
name = "alice"
public_key_hex = "abc123..."

[[publishers]]
name = "santh-official"
public_key_hex = "def456..."
```

Bundles signed by an unlisted publisher are rejected by `verify()`.
Use `TrustList::allow()` to add new publishers programmatically or
edit the TOML directly.

## License

MIT OR Apache-2.0. Copyright 2026 CORUM COLLECTIVE LLC.
