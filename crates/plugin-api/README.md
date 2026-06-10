# wafrift-plugin-api

Plugin / tamper API for [wafrift](https://crates.io/crates/wafrift).

Load external payload tampers without rebuilding wafrift. A tamper takes a
payload and returns transformed variants; this crate defines the contract and
the two loaders:

- **TOML tampers** — declarative search/replace, encoding, and wrapping rules
  dropped into a rules directory (Tier B configuration).
- **WebAssembly tampers** — sandboxed `.wasm` modules implementing the tamper
  ABI for logic that a declarative rule cannot express.

The API is the boundary; the tampers are operator-supplied. wafrift runs them
over operator payloads and reports the transformed forms.

## License

MIT OR Apache-2.0
