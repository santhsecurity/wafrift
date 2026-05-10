#[test]
fn test_url_parse_variants() {
    for u in ["http://0x7f000001/", "http://127.0.0.1%00.evil.com/", "http://@127.0.0.1/", "http://127.1/", "http://[::ffff:127.0.0.1]/", "http://0177.0.0.1/"] {
        println!("{} => {:?}", u, url::Url::parse(u));
    }
}
