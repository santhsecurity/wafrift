# wafrift-grpc-evasion

gRPC / protobuf opaque-payload WAF-evasion for [wafrift](https://crates.io/crates/wafrift).

Many WAFs treat a gRPC request body as opaque binary and skip their signature
rules over it. This crate embeds an operator-supplied payload (SQLi / XSS /
command-injection string) into a valid protobuf wire-format message so the
attack the operator brought is carried inside the binary frame.

It is a transform: it re-frames the operator's payload into protobuf wire
format and reports the encoded form. It does not scan, score, or assert that a
target is exploitable.

## Wire format

Payloads are written as protobuf length-delimited fields (wire type 2) with
configurable field numbers, optionally wrapped in the gRPC length-prefixed
message framing (1-byte compression flag + 4-byte big-endian length).

## License

MIT OR Apache-2.0
