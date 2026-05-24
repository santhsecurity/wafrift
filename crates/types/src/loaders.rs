//! Shared file-discovery primitives for `.toml` rule directories.
//!
//! Every crate that ships a bundled rule database (`wafrift-detect` for
//! WAF fingerprints, `wafrift-transport` for response profiles, future
//! crates for grammar / oracle catalogs) wants the same iteration
//! shape: list `.toml` files under a directory, sort by path for
//! deterministic load order, hand each entry's contents back to the
//! caller for parsing + post-processing.
//!
//! Pre-extract, that loop was hand-rolled in
//! `transport/src/signal.rs::ResponseProfileDb::load_dir` (lossy) and
//! `detect/src/waf_detect/rules.rs::RuleDb::load_directory` (strict),
//! each with its own `read_dir` + `extension == "toml"` filter +
//! `read_to_string` block. This helper carries the boilerplate so a
//! third loader can be added in <5 lines.
//!
//! Each caller keeps its own error policy: `read_toml_files_strict`
//! propagates the first read error, `read_toml_files_lossy` swallows
//! them silently (best-effort discovery). The deserialise step
//! intentionally lives at the call site because each crate's parsed
//! type and per-entry post-processing differ.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atomically write `bytes` to `path` using the tmp-file + fsync +
/// rename + parent-fsync dance. Crash-safe: a torn write leaves
/// `path` untouched and the tmp file orphaned (gc-able), never a
/// half-written file under `path`.
///
/// Multi-writer safe: the tmp filename embeds the writer's PID + a
/// nanosecond timestamp so two processes pointed at the same path
/// don't collide on each other's `<path>.tmp`. The last `rename`
/// wins — matching the existing single-writer semantics that callers
/// rely on. Pre-extract, this dance was hand-rolled at 3 sites
/// (`strategy::gene_bank::write_genome`, `proxy::gene_bank_io`,
/// `cli::seed`) with subtly different tmp-suffix policies and
/// parent-fsync behaviour.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = path.with_extension(format!("tmp.{pid}.{nanos}"));

    let write = (|| -> io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Best-effort parent-dir fsync so the rename is durable across a
    // crash. Failure here is non-fatal — the rename already happened
    // and most filesystems will recover the directory entry anyway.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent)
    {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Strict: enumerate every `.toml` file under `dir`, sorted by path,
/// returning `(path, contents)` pairs. Fails on the first I/O error.
///
/// Caller deserialises and handles parse errors itself.
pub fn read_toml_files_strict(dir: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .map(|e| e.path())
        .collect();
    entries.sort();

    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        let contents = std::fs::read_to_string(&path)?;
        out.push((path, contents));
    }
    Ok(out)
}

/// Lossy: same iteration as `read_toml_files_strict` but silently
/// skips files that fail to read (best-effort discovery). The outer
/// directory-open failure is also swallowed — callers that need to
/// distinguish "no such directory" from "no .toml files" should use
/// the strict variant.
#[must_use]
pub fn read_toml_files_lossy(dir: &Path) -> Vec<(PathBuf, String)> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries: Vec<PathBuf> = read
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .map(|e| e.path())
        .collect();
    entries.sort();

    entries
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(&path).ok().map(|c| (path, c)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wafrift-loaders-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, body: &str) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn strict_returns_sorted_toml_files() {
        let dir = tmp();
        write(&dir, "c.toml", "c body");
        write(&dir, "a.toml", "a body");
        write(&dir, "b.toml", "b body");
        let got = read_toml_files_strict(&dir).unwrap();
        let names: Vec<_> = got
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["a.toml", "b.toml", "c.toml"]);
    }

    #[test]
    fn strict_skips_non_toml_files() {
        let dir = tmp();
        write(&dir, "rules.toml", "good");
        write(&dir, "README.md", "ignored");
        write(&dir, "data.json", "ignored");
        let got = read_toml_files_strict(&dir).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "good");
    }

    #[test]
    fn strict_returns_contents() {
        let dir = tmp();
        write(&dir, "x.toml", "hello = 1\n");
        let got = read_toml_files_strict(&dir).unwrap();
        assert_eq!(got[0].1, "hello = 1\n");
    }

    #[test]
    fn strict_fails_on_missing_dir() {
        let nope = std::env::temp_dir().join("wafrift-loaders-does-not-exist-xyz");
        let _ = std::fs::remove_dir_all(&nope);
        assert!(read_toml_files_strict(&nope).is_err());
    }

    #[test]
    fn lossy_returns_empty_on_missing_dir() {
        let nope = std::env::temp_dir().join("wafrift-loaders-does-not-exist-xyz2");
        let _ = std::fs::remove_dir_all(&nope);
        assert!(read_toml_files_lossy(&nope).is_empty());
    }

    #[test]
    fn lossy_returns_sorted_toml_files() {
        let dir = tmp();
        write(&dir, "z.toml", "z");
        write(&dir, "a.toml", "a");
        let got = read_toml_files_lossy(&dir);
        let names: Vec<_> = got
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["a.toml", "z.toml"]);
    }

    #[test]
    fn ext_case_insensitive() {
        let dir = tmp();
        write(&dir, "lower.toml", "1");
        write(&dir, "UPPER.TOML", "2");
        write(&dir, "Mixed.ToMl", "3");
        let got = read_toml_files_strict(&dir).unwrap();
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn empty_dir_returns_empty_vec() {
        let dir = tmp();
        assert!(read_toml_files_strict(&dir).unwrap().is_empty());
        assert!(read_toml_files_lossy(&dir).is_empty());
    }

    // ── write_atomic ─────────────────────────────────────────

    #[test]
    fn write_atomic_creates_file_with_content() {
        let dir = tmp();
        let path = dir.join("foo.json");
        write_atomic(&path, b"hello world").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello world");
    }

    #[test]
    fn write_atomic_overwrites_existing_file() {
        let dir = tmp();
        let path = dir.join("foo.json");
        fs::write(&path, b"old content").unwrap();
        write_atomic(&path, b"new content").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new content");
    }

    #[test]
    fn write_atomic_leaves_no_tmp_file_on_success() {
        let dir = tmp();
        let path = dir.join("foo.json");
        write_atomic(&path, b"hi").unwrap();
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp."))
            .collect();
        assert!(
            leftover.is_empty(),
            "found leftover tmp files: {:?}",
            leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn write_atomic_handles_empty_bytes() {
        let dir = tmp();
        let path = dir.join("empty.json");
        write_atomic(&path, b"").unwrap();
        assert_eq!(fs::read(&path).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn write_atomic_fails_when_parent_missing() {
        let nope = std::env::temp_dir().join("wafrift-atomic-missing-parent/foo.json");
        let _ = std::fs::remove_dir_all(nope.parent().unwrap());
        assert!(write_atomic(&nope, b"x").is_err());
    }

    #[test]
    fn write_atomic_distinct_tmp_names_for_concurrent_writers() {
        // Two back-to-back calls in the same process — the per-nanos
        // suffix should still differ enough to avoid collision.
        let dir = tmp();
        let path = dir.join("seq.json");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }
}
