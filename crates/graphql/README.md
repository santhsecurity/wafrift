# wafrift-graphql

GraphQL-specific WAF-evasion payload generation for [wafrift](https://crates.io/crates/wafrift).

Given an operator-supplied GraphQL operation, this crate emits equivalent
forms that survive signature-based WAF inspection. It transforms what the
operator brings; it does not decide a target is vulnerable.

## Technique Coverage

| Technique | Purpose |
|-----------|---------|
| Alias batching | Collapse N field reads into one request under a rule's per-field threshold |
| Introspection bypass | Reach `__schema` / `__type` via encoding + field-suggestion leakage when introspection is "disabled" |
| Depth / nesting bombs | Generate deeply nested selection sets for depth-limit probing |
| Operation-name mismatch | Desynchronise `operationName` from the document body |

The core operation catalogue is vendored from the sibling Santh project
`gqlprobe`, with wafrift-specific mutators layered on top so the same payload
flows through wafrift's encoder and oracle pipeline.

## License

MIT OR Apache-2.0
