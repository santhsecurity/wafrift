# wafrift Plugin / Tamper API

Add a new tamper in 60 seconds — no Rust, no rebuild.

## Overview

External tampers live in `~/.wafrift/tampers/`.  wafrift scans that directory
at startup and loads every `.toml` and `.wasm` file it finds.  Two formats are
supported:

| Format | Mechanism | Best for |
|--------|-----------|----------|
| `.toml` | Ordered regex-substitution rules | ~80% of tampers: encoders, comment injectors, case mutators |
| `.wasm` | WebAssembly module (sandboxed) | Turing-complete transforms: crypto, stateful generation |

---

## TOML format (quickest path)

### Step 1 — create the file

```toml
# ~/.wafrift/tampers/my_tamper.toml

[manifest]
name            = "my_tamper"          # snake_case, ASCII only, unique
version         = "1.0.0"             # semver string
author          = "You <you@example.com>"
payload_classes = ["sqli", "xss"]     # what injection types this targets
contexts        = ["query_string"]    # where the payload appears
description     = "Turns spaces into SQL comments."

# Rules run top-to-bottom.  Each matches on the output of the previous rule.

[[rules]]
pattern     = " "           # regex; double-quotes in TOML, literal backslash → use single-quoted patterns
replacement = "/**/"        # standard replacement; use $1, $2 for capture groups

[[rules]]
pattern     = "SELECT"
replacement = "SEL/**/ECT"
```

### Step 2 — verify

```
wafrift tamper --payload "SELECT * FROM users" --tamper my_tamper
# → SEL/**/ECT/**/*/*/**/ FROM/**/users
```

That's it.

### Special replacement: `$REVERSED`

Use `$REVERSED` to replace the entire match with its character-reversed form:

```toml
[[rules]]
pattern     = "^(.+)$"
replacement = "$REVERSED"
```

### Regex note

TOML double-quoted strings process `\n`, `\t`, `\uXXXX`, etc.  For regex
patterns that include backslashes (e.g., `\d`, `\s`) use **TOML literal
strings** (single-quoted):

```toml
[[rules]]
pattern     = '\d+'    # literal backslash preserved
replacement = "N"
```

---

## WebAssembly format (advanced)

For transforms that require real logic — crypto, stateful generation,
external libraries compiled to Wasm — ship a `.wasm` module.

### Security sandbox

The WASM runtime is **fully sandboxed**:

- No WASI imports — no filesystem, no network, no environment variables
- Fuel limited to **1 000 000 instructions** per `apply()` call (prevents infinite loops)
- Stack capped at **512 KiB**
- No threads (wasm-threads disabled)

Any attempt to import a disallowed symbol causes the module to be **rejected at load time**, not at runtime.

### Required exports

Your module must export exactly these three symbols:

| Export | Type | Purpose |
|--------|------|---------|
| `memory` | Memory | Linear memory (must be exported) |
| `alloc(len: i32) -> i32` | Function | Allocate `len` bytes, return pointer |
| `tamper(ptr: i32, len: i32) -> i64` | Function | Transform the payload |
| `dealloc(ptr: i32, len: i32)` | Function | Free allocation (optional but recommended) |

The `tamper` function receives the input payload as UTF-8 bytes at `(ptr, len)` in linear memory and must return a packed `i64`:

```
result_ptr << 32 | result_len
```

### Required custom section

The module must embed a `wafrift_manifest` custom section containing the
manifest as TOML text:

```toml
name            = "my_wasm_tamper"
version         = "1.0.0"
author          = "You <you@example.com>"
payload_classes = ["sqli"]
contexts        = ["query_string"]
description     = "Wasm-based SQL comment injector."
```

### Compilation example (Rust → wasm32-wasip1)

```rust
// src/lib.rs
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, len: i32) {
    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) }
}

/// Replace spaces with /**/.
#[no_mangle]
pub extern "C" fn tamper(ptr: i32, len: i32) -> i64 {
    let input = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr as *const u8, len as usize))
    };
    let output: String = input.replace(' ', "/**/");
    let bytes = output.into_bytes();
    let out_len = bytes.len() as i32;
    let out_ptr = alloc(out_len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, out_len as usize);
    }
    ((out_ptr as i64) << 32) | (out_len as i64)
}
```

```toml
# Cargo.toml
[package]
name = "my_wasm_tamper"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
```

```sh
# Build
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release

# Embed the manifest custom section (requires wasm-tools)
wasm-tools strip my_wasm_tamper.wasm -o stripped.wasm
printf '[manifest]\nname="my_wasm_tamper"\nversion="1.0.0"\nauthor="You"\npayload_classes=["sqli"]\ncontexts=["query_string"]\ndescription="SQL comment injector."\n' \
  | wasm-tools custom section add --name wafrift_manifest --from-stdin stripped.wasm \
  -o ~/.wafrift/tampers/my_wasm_tamper.wasm
```

---

## Plugin loading rules

1. Files scanned at startup from `~/.wafrift/tampers/` (subdirectories ignored).
2. Load failures are logged at `WARN` level and skipped — they do not prevent other plugins from loading.
3. Name collisions (two plugins with the same `name`) cause the second to be rejected.
4. Manifest validation enforced:
   - `name`: non-empty, ASCII alphanumeric + underscores only
   - `version`: non-empty string
   - `author`: non-empty string
   - `description`: max 512 characters

---

## Example included

`examples/tampers/reverse_string.toml` in the wafrift repository demonstrates
the TOML format.  Copy it to `~/.wafrift/tampers/` to try it immediately.
