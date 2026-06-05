//! Bounded file readers — defence against decompression-bomb-style
//! attacks on operator-supplied paths.
//!
//! These are thin aliases over the canonical [`boundedio`] crate, which
//! enforces the cap DURING the read via `Read::take(cap + 1)` + post-check
//! (TOCTOU-safe: a symlink to `/dev/zero` reporting `len = 0` cannot evade
//! the gate). Kept as `pub(crate)` wrappers so existing call sites and the
//! "missing/corrupt → default" contract are unchanged.

use std::io;
use std::path::Path;

/// Read a file as UTF-8 text with the cap enforced during the read.
/// Returns `InvalidData` if the file exceeds the cap (so an EvoError
/// `Io` wrap surfaces it; callers can also fall back to default
/// where the contract is "missing/corrupt → default").
pub(crate) fn read_capped_text(path: &Path, max_bytes: usize) -> io::Result<String> {
    boundedio::read_file_capped_string(path, max_bytes)
}

/// Bytes variant — used by `edge_pop_coverage::load_or_default`,
/// which deserialises via `from_slice`.
pub(crate) fn read_capped_bytes(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    boundedio::read_file_capped(path, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversize_input() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "wafrift-evo-safeio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("big.bin");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(&vec![b'x'; 4096]).expect("write");
        }
        let err = read_capped_text(&path, 256).expect_err("must reject");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn accepts_exact_cap() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "wafrift-evo-safeio-exact-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("exact.bin");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(&[b'a'; 100]).expect("write");
        }
        let got = read_capped_text(&path, 100).expect("at cap must pass");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got.len(), 100);
    }
}
