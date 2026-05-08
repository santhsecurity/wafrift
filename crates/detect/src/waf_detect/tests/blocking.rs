use crate::waf_detect::is_blocked_response;

#[test]
fn is_blocked_403() {
    assert!(is_blocked_response(403, b"Forbidden"));
}

#[test]
fn is_blocked_200_with_waf_body() {
    assert!(is_blocked_response(
        200,
        b"Access Denied by Security Policy"
    ));
}

#[test]
fn is_not_blocked_200_clean() {
    assert!(!is_blocked_response(200, b"Welcome to our site"));
}

#[test]
fn is_blocked_captcha() {
    assert!(is_blocked_response(200, b"Please complete the CAPTCHA"));
}
