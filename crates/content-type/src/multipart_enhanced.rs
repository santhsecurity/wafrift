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
