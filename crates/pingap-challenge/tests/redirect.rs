use pingap_challenge::redirect::validate_return_path;

#[test]
fn only_a_single_slash_relative_path_is_accepted() {
    assert!(validate_return_path("/account?next=1").is_ok());
    for bad in [
        "//evil.test",
        "/\\evil",
        "https://evil.test",
        "/x\r\ny",
        "/x\u{7f}",
    ] {
        assert!(validate_return_path(bad).is_err(), "accepted {bad:?}");
    }
}
