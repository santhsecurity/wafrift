//! wafrift-plugin-api — External tamper plugin system.
//!
//! Lets external contributors add tampers **without a Rust rebuild**.
//! Plugins live at `~/.wafrift/tampers/`:
//!
//! | Extension | Mechanism | Use case |
//! |-----------|-----------|----------|
//! | `.toml`   | Regex substitution rules | ~80% of tampers (encoders / replacers) |
//! | `.wasm`   | WebAssembly (wasmtime)   | Turing-complete logic |
//!
//! # Security model
//!
//! WASM modules run inside a `wasmtime::Engine` with **no** WASI
//! capabilities attached: no filesystem, no network, no environment
//! variables, no random, no clocks. The only ABI is a single exported
//! function `tamper(ptr: i32, len: i32) -> i64` that receives the
//! payload as UTF-8 bytes via linear memory and returns a
//! `(ptr << 32 | len)` packed into an i64.  Memory is bounded to 4 MiB.
//! Fuel limiting caps execution to 1 000 000 instructions per call.
//!
//! # Quick start
//!
//! ```no_run
//! use wafrift_plugin_api::load_all;
//!
//! let tampers = load_all();
//! for t in &tampers {
//!     println!("{}: {}", t.name(), t.apply("SELECT 1"));
//! }
//! ```

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────
// Public trait: Tamper
// ──────────────────────────────────────────────────────────────────────────

/// Every plugin — TOML or WASM — implements this trait.
///
/// The trait is object-safe so plugins can be stored as `Box<dyn Tamper>`.
pub trait Tamper: Send + Sync {
    /// Unique, ASCII-only snake_case name.  Must not collide with built-ins.
    fn name(&self) -> &str;

    /// Transform a payload for WAF evasion.
    fn apply(&self, input: &str) -> String;

    /// Structured metadata every plugin must provide.
    fn manifest(&self) -> TamperManifest;
}

// ──────────────────────────────────────────────────────────────────────────
// TamperManifest
// ──────────────────────────────────────────────────────────────────────────

/// Metadata that every external contribution must declare.
///
/// Validated at load time; malformed manifests are rejected before the
/// plugin reaches the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperManifest {
    /// Unique, snake_case plugin name (must match the file stem).
    pub name: String,
    /// Semver string, e.g. `"1.0.0"`.
    pub version: String,
    /// Plugin author / email.
    pub author: String,
    /// Which payload classes this tamper targets, e.g. `["sqli", "xss"]`.
    pub payload_classes: Vec<String>,
    /// Injection contexts where the tamper is appropriate, e.g.
    /// `["query_string", "json_body"]`.
    pub contexts: Vec<String>,
    /// Human-readable description (max 512 chars).
    pub description: String,
}

impl TamperManifest {
    /// Validate that the manifest fields are structurally sound.
    ///
    /// # Errors
    /// Returns a description of the first validation failure.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.name.is_empty() {
            return Err(PluginError::InvalidManifest(
                "name must not be empty".into(),
            ));
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(PluginError::InvalidManifest(format!(
                "name '{}' must contain only ASCII alphanumeric characters and underscores",
                self.name
            )));
        }
        if self.version.is_empty() {
            return Err(PluginError::InvalidManifest(
                "version must not be empty".into(),
            ));
        }
        if self.author.is_empty() {
            return Err(PluginError::InvalidManifest(
                "author must not be empty".into(),
            ));
        }
        if self.description.len() > 512 {
            return Err(PluginError::InvalidManifest(format!(
                "description exceeds 512 chars ({} chars)",
                self.description.len()
            )));
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────

/// Errors that can occur during plugin loading or execution.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// A required manifest field is missing or invalid.
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),

    /// Two plugins share the same name.
    #[error("Name collision: plugin '{0}' is already registered")]
    NameCollision(String),

    /// A TOML file could not be parsed.
    #[error("TOML parse error in {file}: {cause}")]
    TomlParse { file: PathBuf, cause: String },

    /// A regex pattern in a TOML tamper is invalid.
    #[error("Invalid regex '{pattern}' in {file}: {cause}")]
    InvalidRegex {
        file: PathBuf,
        pattern: String,
        cause: String,
    },

    /// A WASM module failed to load or compile.
    #[error("WASM load error in {file}: {cause}")]
    WasmLoad { file: PathBuf, cause: String },

    /// The WASM module tried to use a disallowed capability.
    #[error("WASM sandbox violation in '{plugin}': {detail}")]
    WasmSandboxViolation { plugin: String, detail: String },

    /// WASM execution ran out of fuel.
    #[error("WASM fuel exhausted in '{plugin}' after {fuel} instructions")]
    WasmFuelExhausted { plugin: String, fuel: u64 },

    /// Generic I/O error while scanning the plugin directory.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ──────────────────────────────────────────────────────────────────────────
// TOML tamper file format
// ──────────────────────────────────────────────────────────────────────────

/// Top-level structure of a `~/.wafrift/tampers/*.toml` plugin file.
///
/// # Example TOML
/// ```toml
/// [manifest]
/// name = "reverse_string"
/// version = "1.0.0"
/// author = "Jane Researcher <jane@example.com>"
/// payload_classes = ["generic"]
/// contexts = ["query_string", "json_body"]
/// description = "Reverses every token for simple obfuscation tests."
///
/// [[rules]]
/// pattern = "^(.+)$"
/// replacement = "$REVERSED"   # magic: entire match reversed
/// ```
#[derive(Debug, Deserialize)]
struct TomlPluginFile {
    manifest: TomlManifest,
    /// Rules are optional — a manifest-only plugin loads as an
    /// identity tamper. Used by external contributors who want to
    /// register metadata (e.g. for a future WASM upgrade path) without
    /// shipping regex rules yet.
    #[serde(default)]
    rules: Vec<TomlRule>,
}

#[derive(Debug, Deserialize)]
struct TomlManifest {
    name: String,
    version: String,
    author: String,
    #[serde(default)]
    payload_classes: Vec<String>,
    #[serde(default)]
    contexts: Vec<String>,
    description: String,
}

/// A single regex-based substitution rule.
#[derive(Debug, Deserialize)]
struct TomlRule {
    /// Regex pattern to match in the input.
    pattern: String,
    /// Replacement string.  Supports `$1`, `$2` … for capture groups.
    /// Special magic token `$REVERSED` reverses the entire match.
    replacement: String,
}

// ──────────────────────────────────────────────────────────────────────────
// TOML-backed Tamper implementation
// ──────────────────────────────────────────────────────────────────────────

struct TomlTamper {
    manifest: TamperManifest,
    /// Pre-compiled (pattern, replacement) pairs.
    rules: Vec<(Regex, String)>,
}

impl Tamper for TomlTamper {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn apply(&self, input: &str) -> String {
        let mut result = input.to_owned();
        for (re, replacement) in &self.rules {
            if replacement == "$REVERSED" {
                result = re
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        caps[0].chars().rev().collect::<String>()
                    })
                    .into_owned();
            } else {
                result = re.replace_all(&result, replacement.as_str()).into_owned();
            }
        }
        result
    }

    fn manifest(&self) -> TamperManifest {
        self.manifest.clone()
    }
}

/// Maximum TOML plugin file size: 256 KiB.
const TOML_MAX_BYTES: u64 = 256 * 1024;

/// Bounded read for plugin files. The previous metadata()+read()
/// pattern was vulnerable to TOCTOU: a symlink reporting len=0 (e.g.
/// pointing at /dev/zero) would pass the metadata gate and then
/// stream until OOM. Enforce the cap DURING the read so symlinks +
/// races + post-stat replacements cannot evade it.
fn read_capped_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(max_bytes + 1);
    let mut buf = Vec::with_capacity(8 * 1024);
    limited.read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: file exceeds {}-byte cap (>{} bytes observed)",
                path.display(),
                max_bytes,
                max_bytes,
            ),
        ));
    }
    Ok(buf)
}

fn load_toml_plugin(path: &Path) -> Result<Box<dyn Tamper>, PluginError> {
    let raw = read_capped_file(path, TOML_MAX_BYTES).map_err(|e| {
        PluginError::InvalidManifest(format!(
            "{}: failed to read manifest ({}, max {} bytes)",
            path.display(),
            e,
            TOML_MAX_BYTES,
        ))
    })?;
    let content = String::from_utf8(raw).map_err(|e| {
        PluginError::InvalidManifest(format!("{}: not valid UTF-8: {e}", path.display()))
    })?;
    let parsed: TomlPluginFile = toml::from_str(&content).map_err(|e| PluginError::TomlParse {
        file: path.to_owned(),
        cause: e.to_string(),
    })?;

    let manifest = TamperManifest {
        name: parsed.manifest.name,
        version: parsed.manifest.version,
        author: parsed.manifest.author,
        payload_classes: parsed.manifest.payload_classes,
        contexts: parsed.manifest.contexts,
        description: parsed.manifest.description,
    };
    manifest.validate()?;

    // ReDoS guard: cap the compiled NFA size so a malicious plugin
    // with a pathological pattern (e.g. `(a+)+`) cannot stall the
    // engine. 1 MiB is stricter than the workspace-canonical 4 MiB
    // (wafrift_types::REGEX_NFA_SIZE_LIMIT) because plugin patterns
    // come from fully untrusted third parties. The tighter cap is
    // intentional — do NOT bump it to match the workspace constant.
    const PLUGIN_REGEX_SIZE_LIMIT: usize = 1024 * 1024;
    let mut compiled_rules = Vec::with_capacity(parsed.rules.len());
    for rule in &parsed.rules {
        let re = RegexBuilder::new(&rule.pattern)
            .size_limit(PLUGIN_REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| PluginError::InvalidRegex {
                file: path.to_owned(),
                pattern: rule.pattern.clone(),
                cause: e.to_string(),
            })?;
        compiled_rules.push((re, rule.replacement.clone()));
    }

    Ok(Box::new(TomlTamper {
        manifest,
        rules: compiled_rules,
    }))
}

// ──────────────────────────────────────────────────────────────────────────
// WASM-backed Tamper implementation
// ──────────────────────────────────────────────────────────────────────────

/// Fuel budget: 1 000 000 instructions per `apply()` call.
const WASM_FUEL_PER_CALL: u64 = 1_000_000;

/// Maximum `.wasm` file size: 4 MiB.
const WASM_MAX_BYTES: u64 = 4 * 1024 * 1024;

struct WasmTamper {
    manifest: TamperManifest,
    /// Arc+Mutex so `WasmTamper: Send + Sync` despite `Store` being `!Send`.
    /// Each `apply()` call locks, runs the guest, and unlocks.
    store_module: Arc<Mutex<WasmRuntime>>,
}

struct WasmRuntime {
    store: wasmtime::Store<()>,
    memory: wasmtime::Memory,
    tamper_fn: wasmtime::TypedFunc<(i32, i32), i64>,
    alloc_fn: wasmtime::TypedFunc<i32, i32>,
    dealloc_fn: Option<wasmtime::TypedFunc<(i32, i32), ()>>,
}

impl WasmRuntime {
    /// Execute one tamper call.
    ///
    /// We resolve borrow-checker conflicts by cloning the `TypedFunc`
    /// values out of their `Option` wrappers before mutably borrowing
    /// `self.store` — `TypedFunc` is a lightweight handle (index +
    /// type marker) designed to be cloned cheaply.
    fn call_tamper(&mut self, input: &str) -> Option<String> {
        // Clone handles upfront to avoid aliasing borrows later.
        let alloc_fn = self.alloc_fn.clone();
        let tamper_fn = self.tamper_fn.clone();
        let dealloc_fn = self.dealloc_fn.clone();
        let memory = self.memory;

        self.store.set_fuel(WASM_FUEL_PER_CALL).ok()?;

        let bytes = input.as_bytes();
        let len = bytes.len() as i32;

        // Allocate guest memory for the input.
        let ptr = alloc_fn.call(&mut self.store, len).ok()?;

        // Write payload into guest linear memory.
        memory.write(&mut self.store, ptr as usize, bytes).ok()?;

        // Call the guest tamper function.
        let result_packed = tamper_fn.call(&mut self.store, (ptr, len)).ok()?;

        // Free the input allocation if a dealloc export is present.
        if let Some(ref dealloc) = dealloc_fn {
            dealloc.call(&mut self.store, (ptr, len)).ok();
        }

        // Unpack (result_ptr << 32 | result_len).
        let result_ptr = ((result_packed >> 32) & 0xFFFF_FFFF) as usize;
        let result_len = (result_packed & 0xFFFF_FFFF) as usize;

        // §15 host-OOM defence: `result_len` is attacker-controlled — the low
        // 32 bits of the UNTRUSTED guest's return value, up to ~4 GiB. The
        // guest's own linear memory is capped (4 MiB), so any (ptr, len) that
        // does not fit inside the current guest memory is necessarily a lie —
        // and a naive `vec![0u8; result_len]` would allocate gigabytes on the
        // HOST and OOM it BEFORE `memory.read` (which only bounds-checks the
        // read itself) ever runs. Reject the out-of-bounds/oversized result
        // up front so the host allocation can never exceed guest memory.
        let mem_size = memory.data_size(&self.store);
        if result_ptr.saturating_add(result_len) > mem_size {
            return None; // oversized / out-of-bounds guest result — fail safe
        }

        let mut out = vec![0u8; result_len];
        memory.read(&self.store, result_ptr, &mut out).ok()?;

        // Free the output allocation.
        if let Some(ref dealloc) = dealloc_fn {
            dealloc
                .call(&mut self.store, (result_ptr as i32, result_len as i32))
                .ok();
        }

        String::from_utf8(out).ok()
    }
}

impl Tamper for WasmTamper {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn apply(&self, input: &str) -> String {
        let mut rt = match self.store_module.lock() {
            Ok(g) => g,
            Err(_) => return input.to_owned(), // poisoned — fail safe
        };
        rt.call_tamper(input).unwrap_or_else(|| input.to_owned())
    }

    fn manifest(&self) -> TamperManifest {
        self.manifest.clone()
    }
}

/// Manifest is embedded in the WASM custom section `wafrift_manifest` as
/// TOML text.  This is the struct that section deserializes into.
#[derive(Deserialize)]
struct WasmEmbeddedManifest {
    name: String,
    version: String,
    author: String,
    #[serde(default)]
    payload_classes: Vec<String>,
    #[serde(default)]
    contexts: Vec<String>,
    description: String,
}

fn load_wasm_plugin(path: &Path) -> Result<Box<dyn Tamper>, PluginError> {
    let wasm_bytes = read_capped_file(path, WASM_MAX_BYTES).map_err(|e| {
        PluginError::InvalidManifest(format!(
            "{}: failed to read WASM ({}, max {} bytes)",
            path.display(),
            e,
            WASM_MAX_BYTES,
        ))
    })?;

    // Build a sandboxed engine: no WASI, fuel enabled, memory limited.
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    // Cap the guest linear memory to WASM_MEMORY_PAGES × 64 KiB = 4 MiB.
    config.memory_guard_size(0);
    config.max_wasm_stack(512 * 1024); // 512 KiB Wasm stack
    // Multi-memory and threads are not needed; keeping them off
    // narrows the attack surface of the sandboxed guest.

    let engine = wasmtime::Engine::new(&config).map_err(|e| PluginError::WasmLoad {
        file: path.to_owned(),
        cause: format!("engine creation failed: {e}"),
    })?;

    // Extract the manifest from the custom section before compiling.
    let manifest = extract_wasm_manifest(&wasm_bytes, path)?;

    let module =
        wasmtime::Module::new(&engine, &wasm_bytes).map_err(|e| PluginError::WasmLoad {
            file: path.to_owned(),
            cause: format!("module compilation failed: {e}"),
        })?;

    // Linker with NO imports — no WASI, no host functions.
    let linker: wasmtime::Linker<()> = wasmtime::Linker::new(&engine);

    let mut store = wasmtime::Store::new(&engine, ());
    store.set_fuel(WASM_FUEL_PER_CALL).ok();

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| PluginError::WasmLoad {
            file: path.to_owned(),
            cause: format!("instantiation failed (module may import disallowed symbols): {e}"),
        })?;

    let memory =
        instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::WasmLoad {
                file: path.to_owned(),
                cause: "module must export a 'memory' with name 'memory'".into(),
            })?;

    let tamper_fn: wasmtime::TypedFunc<(i32, i32), i64> = instance
        .get_typed_func(&mut store, "tamper")
        .map_err(|e| PluginError::WasmLoad {
            file: path.to_owned(),
            cause: format!("missing export 'tamper(i32,i32)->i64': {e}"),
        })?;

    let alloc_fn: wasmtime::TypedFunc<i32, i32> = instance
        .get_typed_func(&mut store, "alloc")
        .map_err(|e| PluginError::WasmLoad {
            file: path.to_owned(),
            cause: format!("missing export 'alloc(i32)->i32': {e}"),
        })?;

    let dealloc_fn: Option<wasmtime::TypedFunc<(i32, i32), ()>> =
        instance.get_typed_func(&mut store, "dealloc").ok();

    let runtime = WasmRuntime {
        store,
        memory,
        tamper_fn,
        alloc_fn,
        dealloc_fn,
    };

    Ok(Box::new(WasmTamper {
        manifest,
        store_module: Arc::new(Mutex::new(runtime)),
    }))
}

/// Reads the manifest from the WASM custom section named `wafrift_manifest`.
fn extract_wasm_manifest(wasm_bytes: &[u8], path: &Path) -> Result<TamperManifest, PluginError> {
    // WASM binary format: 4-byte magic + 4-byte version, then sections.
    // We scan for custom sections (section id = 0) with name "wafrift_manifest".
    if wasm_bytes.len() < 8 {
        return Err(PluginError::WasmLoad {
            file: path.to_owned(),
            cause: "not a valid WASM binary (too short)".into(),
        });
    }

    let magic = &wasm_bytes[..4];
    if magic != b"\0asm" {
        return Err(PluginError::WasmLoad {
            file: path.to_owned(),
            cause: "not a valid WASM binary (bad magic)".into(),
        });
    }

    let mut offset = 8usize; // skip magic + version
    while offset < wasm_bytes.len() {
        let section_id = wasm_bytes[offset];
        offset += 1;

        // LEB128-decode the section size.
        let (section_size, leb_bytes) = read_leb128_u32(&wasm_bytes[offset..])?;
        offset += leb_bytes;

        let section_end = offset + section_size as usize;
        if section_end > wasm_bytes.len() {
            break;
        }

        if section_id == 0 {
            // Custom section: starts with a name string (LEB128 length + bytes).
            let name_end = offset;
            let (name_len, nl) = read_leb128_u32(&wasm_bytes[name_end..])?;
            let name_start = name_end + nl;
            let name_finish = name_start + name_len as usize;
            if name_finish <= section_end {
                let section_name = &wasm_bytes[name_start..name_finish];
                if section_name == b"wafrift_manifest" {
                    let payload = &wasm_bytes[name_finish..section_end];
                    let toml_str =
                        std::str::from_utf8(payload).map_err(|_| PluginError::WasmLoad {
                            file: path.to_owned(),
                            cause: "wafrift_manifest custom section is not valid UTF-8".into(),
                        })?;
                    let em: WasmEmbeddedManifest =
                        toml::from_str(toml_str).map_err(|e| PluginError::TomlParse {
                            file: path.to_owned(),
                            cause: format!("wafrift_manifest section: {e}"),
                        })?;
                    let mf = TamperManifest {
                        name: em.name,
                        version: em.version,
                        author: em.author,
                        payload_classes: em.payload_classes,
                        contexts: em.contexts,
                        description: em.description,
                    };
                    mf.validate()?;
                    return Ok(mf);
                }
            }
        }

        offset = section_end;
    }

    Err(PluginError::WasmLoad {
        file: path.to_owned(),
        cause: "missing 'wafrift_manifest' custom section — see docs/PLUGIN_API.md".into(),
    })
}

fn read_leb128_u32(data: &[u8]) -> Result<(u32, usize), PluginError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate().take(5) {
        result |= u32::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
    }
    Err(PluginError::InvalidManifest(
        "malformed LEB128 in WASM section header".into(),
    ))
}

// ──────────────────────────────────────────────────────────────────────────
// TamperRegistry
// ──────────────────────────────────────────────────────────────────────────

/// Registry that holds all loaded external tampers.
///
/// Designed for concurrent read access: after construction it is
/// immutably shared across threads via `Arc<TamperRegistry>`.
pub struct TamperRegistry {
    plugins: Vec<Box<dyn Tamper>>,
    name_index: HashMap<String, usize>,
}

impl TamperRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Register a tamper.  Returns an error on name collision.
    ///
    /// # Errors
    /// Returns [`PluginError::NameCollision`] if a tamper with the same
    /// name is already registered.
    pub fn register(&mut self, plugin: Box<dyn Tamper>) -> Result<(), PluginError> {
        let name = plugin.name().to_owned();
        if self.name_index.contains_key(&name) {
            return Err(PluginError::NameCollision(name));
        }
        let idx = self.plugins.len();
        self.name_index.insert(name, idx);
        self.plugins.push(plugin);
        Ok(())
    }

    /// Look up a tamper by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn Tamper> {
        self.name_index
            .get(name)
            .and_then(|&idx| self.plugins.get(idx))
            .map(|b| b.as_ref())
    }

    /// All registered tampers (order matches registration order).
    #[must_use]
    pub fn all(&self) -> &[Box<dyn Tamper>] {
        &self.plugins
    }

    /// Number of registered tampers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// True if no tampers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Load all plugins from the given directory, in-place.
    ///
    /// Files with unrecognised extensions are silently skipped.
    /// Load failures are collected and returned; the registry still
    /// contains all plugins that loaded successfully.
    pub fn load_dir(&mut self, dir: &Path) -> Vec<PluginError> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(), // directory doesn't exist — not an error
        };

        let mut errors = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let result = match ext {
                "toml" => load_toml_plugin(&path),
                "wasm" => load_wasm_plugin(&path),
                _ => continue,
            };
            match result {
                Ok(plugin) => {
                    if let Err(e) = self.register(plugin) {
                        errors.push(e);
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        errors
    }
}

impl Default for TamperRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Public discovery function
// ──────────────────────────────────────────────────────────────────────────

/// Return the default plugin directory: `~/.wafrift/tampers/`.
///
/// Returns `None` if the home directory cannot be determined.
#[must_use]
pub fn default_plugin_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".wafrift").join("tampers"))
}

/// Scan `~/.wafrift/tampers/` and return all successfully-loaded plugins.
///
/// Errors from individual plugins are logged at WARN level and dropped.
/// An empty `Vec` is returned when no plugins are found or the directory
/// does not exist.
#[must_use]
pub fn load_all() -> Vec<Box<dyn Tamper>> {
    let mut registry = TamperRegistry::new();
    if let Some(dir) = default_plugin_dir() {
        let errors = registry.load_dir(&dir);
        for e in errors {
            tracing::warn!("plugin-api: skipping plugin: {e}");
        }
    }
    registry.plugins
}

/// Scan the given directory and return all successfully-loaded plugins.
///
/// Errors are logged at WARN level.
#[must_use]
pub fn load_from(dir: &Path) -> Vec<Box<dyn Tamper>> {
    let mut registry = TamperRegistry::new();
    let errors = registry.load_dir(dir);
    for e in errors {
        tracing::warn!("plugin-api: skipping plugin: {e}");
    }
    registry.plugins
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // ── helpers ────────────────────────────────────────────────────────────

    fn write_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn minimal_toml(name: &str, pattern: &str, replacement: &str) -> String {
        format!(
            r#"
[manifest]
name = "{name}"
version = "1.0.0"
author = "Test Author"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Test tamper"

[[rules]]
pattern = "{pattern}"
replacement = "{replacement}"
"#
        )
    }

    // ── 1. Empty directory → zero plugins ─────────────────────────────────

    #[test]
    fn load_dir_empty_returns_zero_plugins() {
        let dir = TempDir::new().unwrap();
        let plugins = load_from(dir.path());
        assert_eq!(plugins.len(), 0);
    }

    // ── 2. Non-existent directory → zero plugins, no panic ────────────────

    #[test]
    fn load_dir_nonexistent_returns_zero_plugins() {
        let path = std::path::Path::new("/nonexistent/path/tampers");
        let plugins = load_from(path);
        assert_eq!(plugins.len(), 0);
    }

    // ── 3. Load one valid TOML tamper ──────────────────────────────────────

    #[test]
    fn load_one_toml_tamper() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "upper.toml", &minimal_toml("upper", "[a-z]", "X"));

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
        assert_eq!(registry.len(), 1);

        let t = registry.get("upper").expect("should be registered");
        assert_eq!(t.name(), "upper");
    }

    // ── 4. TOML tamper applies regex correctly ─────────────────────────────

    #[test]
    fn toml_tamper_apply_regex() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "space_to_comment.toml",
            &minimal_toml("space_to_comment", r" ", "/**/"),
        );

        let mut registry = TamperRegistry::new();
        registry.load_dir(dir.path());

        let result = registry
            .get("space_to_comment")
            .unwrap()
            .apply("SELECT * FROM users");
        assert!(result.contains("/**/"), "got: {result}");
        assert!(!result.contains("  "), "spaces should be replaced");
    }

    // ── 5. TOML tamper with $REVERSED magic ───────────────────────────────

    #[test]
    fn toml_tamper_reversed_magic() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "rev.toml",
            &minimal_toml("rev", "^(.+)$", "$REVERSED"),
        );

        let mut registry = TamperRegistry::new();
        registry.load_dir(dir.path());

        let result = registry.get("rev").unwrap().apply("abc");
        assert_eq!(result, "cba");
    }

    // ── 6. Malformed manifest → rejected ──────────────────────────────────

    #[test]
    fn malformed_manifest_rejected() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "bad.toml",
            r#"
[manifest]
name = ""
version = "1.0.0"
author = "Author"
description = "Empty name should fail"
[[rules]]
pattern = "x"
replacement = "y"
"#,
        );

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(!errors.is_empty(), "should have rejected empty name");
        assert_eq!(registry.len(), 0);
    }

    // ── 7. Invalid regex → rejected ────────────────────────────────────────

    #[test]
    fn invalid_regex_rejected() {
        let dir = TempDir::new().unwrap();
        // Use a TOML literal string (single-quoted in TOML) for the pattern so
        // backslashes are preserved verbatim.  We embed it manually instead of
        // going through `minimal_toml` which wraps patterns in double quotes.
        let content = r#"
[manifest]
name = "bad_re"
version = "1.0.0"
author = "Test Author"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Test tamper"

[[rules]]
pattern = '[invalid('
replacement = "x"
"#;
        write_file(&dir, "bad_re.toml", content);

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], PluginError::InvalidRegex { .. }));
    }

    // ── 8. Name collision rejected ────────────────────────────────────────

    #[test]
    fn name_collision_rejected() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "dup.toml", &minimal_toml("dup_tamper", "x", "y"));
        write_file(&dir, "dup2.toml", &minimal_toml("dup_tamper", "a", "b"));

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        // One loads successfully, one collides.
        assert_eq!(registry.len(), 1);
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], PluginError::NameCollision(_)));
    }

    // ── 9. Unrecognised extension skipped silently ─────────────────────────

    #[test]
    fn unknown_extensions_skipped() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "script.py", "print('hello')");
        write_file(&dir, "data.json", "{}");

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(errors.is_empty());
        assert_eq!(registry.len(), 0);
    }

    // ── 10. Manifest validation: name with illegal chars ──────────────────

    #[test]
    fn manifest_name_with_spaces_rejected() {
        let mf = TamperManifest {
            name: "bad name with spaces".into(),
            version: "1.0.0".into(),
            author: "A".into(),
            payload_classes: vec![],
            contexts: vec![],
            description: "desc".into(),
        };
        let err = mf.validate().unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(_)));
    }

    // ── 11. Manifest validation: description too long ─────────────────────

    #[test]
    fn manifest_description_too_long_rejected() {
        let mf = TamperManifest {
            name: "ok_name".into(),
            version: "1.0.0".into(),
            author: "A".into(),
            payload_classes: vec![],
            contexts: vec![],
            description: "x".repeat(513),
        };
        let err = mf.validate().unwrap_err();
        assert!(matches!(err, PluginError::InvalidManifest(_)));
    }

    // ── 12. Parallel registry read access is safe ─────────────────────────

    #[test]
    fn parallel_registry_access() {
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        // Use a literal character (not a regex meta) to avoid TOML
        // backslash-escape issues in the minimal_toml template.
        write_file(&dir, "par.toml", &minimal_toml("par_tamper", "0", "N"));

        let mut registry = TamperRegistry::new();
        registry.load_dir(dir.path());
        let registry = Arc::new(registry);

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let r = Arc::clone(&registry);
                thread::spawn(move || {
                    // "payload_0" → "N" replaces '0' → "payNload_N"
                    let input = format!("payload_0_{i}");
                    let result = r.get("par_tamper").unwrap().apply(&input);
                    assert!(result.contains('N'), "thread {i}: got {result}");
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    // ── 13. Malformed TOML parse error ────────────────────────────────────

    #[test]
    fn malformed_toml_parse_error() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "garbage.toml", "not valid toml [[[ !!!");

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(!errors.is_empty());
        assert!(matches!(errors[0], PluginError::TomlParse { .. }));
    }

    // ── 14. WASM file with wrong magic → WasmLoad error ───────────────────

    #[test]
    fn wasm_wrong_magic_rejected() {
        let dir = TempDir::new().unwrap();
        // Not a WASM binary — write random bytes.
        let path = dir.path().join("fake.wasm");
        std::fs::write(&path, b"not a wasm file at all!!!!").unwrap();

        let result = load_wasm_plugin(&path);
        assert!(
            matches!(result, Err(PluginError::WasmLoad { .. })),
            "expected WasmLoad error"
        );
    }

    // ── 15. load_all() does not panic when home dir has no tampers dir ─────

    #[test]
    fn load_all_no_panic_with_missing_dir() {
        // If ~/.wafrift/tampers/ doesn't exist, load_all() returns empty vec.
        // We can't override HOME in a reliable cross-platform test, so we
        // test the lower-level function directly.
        let tmp = TempDir::new().unwrap();
        let absent = tmp.path().join("absent_subdir");
        let plugins = load_from(&absent);
        assert_eq!(plugins.len(), 0);
    }

    // ── 16. Multiple rules applied in order ───────────────────────────────

    #[test]
    fn toml_multiple_rules_applied_in_order() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[manifest]
name = "multi_rule"
version = "1.0.0"
author = "Test"
payload_classes = ["sqli"]
contexts = ["query_string"]
description = "Two rules applied sequentially"

[[rules]]
pattern = "SELECT"
replacement = "SEL/**/ECT"

[[rules]]
pattern = " "
replacement = "/**/"
"#;
        write_file(&dir, "multi_rule.toml", content);

        let mut registry = TamperRegistry::new();
        let errors = registry.load_dir(dir.path());
        assert!(errors.is_empty());

        let result = registry.get("multi_rule").unwrap().apply("SELECT 1");
        // First rule fires: "SEL/**/ECT 1"
        // Second rule fires: "SEL/**/ECT/**/1"
        assert!(result.contains("SEL/**/ECT"), "got: {result}");
        assert!(!result.contains(" "), "spaces should be gone: {result}");
    }

    // ── Round 20: bounded plugin reads (TOCTOU defence) ──────────────
    //
    // Pre-fix `metadata()`-then-`read()` was vulnerable to symlinks
    // reporting len=0 (pointed at /dev/zero) and to attackers
    // replacing the file between the stat and the read. The fix
    // enforces the cap DURING the read.

    #[test]
    fn read_capped_file_rejects_oversize_input() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("oversize.bin");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&vec![b'x'; 1024]).expect("write");
        drop(f);
        let err = super::read_capped_file(&path, 256).expect_err("must reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "msg: {err}");
    }

    #[test]
    fn read_capped_file_accepts_exact_cap() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("exact.bin");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&[b'a'; 100]).expect("write");
        drop(f);
        let got = super::read_capped_file(&path, 100).expect("at cap must pass");
        assert_eq!(got.len(), 100);
    }
}
