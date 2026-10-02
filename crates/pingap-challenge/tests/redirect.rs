use pingap_challenge::redirect::{safe_return_path, validate_return_path};

#[test]
fn a_relative_path_with_a_query_is_accepted() {
    assert!(validate_return_path("/account?next=1").is_ok());
}

#[test]
fn a_protocol_relative_path_is_refused() {
    // `//evil.test` is a URL to another origin in every browser's redirect
    // handling, so it is refused by shape rather than by host list.
    assert!(validate_return_path("//evil.test").is_err());
}

#[test]
fn a_backslash_rooted_path_is_refused() {
    // Browsers normalise `\` to `/` in URLs, so `/\evil` is `//evil` once
    // the client has its turn — refused here, before it is ever emitted.
    assert!(validate_return_path("/\\evil").is_err());
}

#[test]
fn an_absolute_url_is_refused() {
    assert!(validate_return_path("https://evil.test").is_err());
}

#[test]
fn a_crlf_in_the_path_is_refused() {
    // The response-splitting shape: a newline in a `Location` value is a
    // header boundary, not path text.
    assert!(validate_return_path("/x\r\ny").is_err());
}

#[test]
fn a_lone_line_feed_is_refused() {
    // `\r\n` is the classic split, but a lone `\n` ends a header line in the
    // same places — the check is per byte, not per pair.
    assert!(validate_return_path("/x\ny").is_err());
}

#[test]
fn any_other_control_byte_is_refused() {
    assert!(validate_return_path("/x\u{7f}").is_err());
}

#[test]
fn an_empty_or_non_relative_path_is_refused() {
    assert!(validate_return_path("").is_err());
    assert!(validate_return_path("account").is_err());
}

#[test]
fn an_unsafe_path_falls_back_to_the_root_rather_than_being_emitted() {
    // `safe_return_path` is what the solve response's `Location` carries:
    // an unacceptable target redirects home rather than redirecting
    // somewhere the client never asked to go.
    assert_eq!(safe_return_path("/account"), "/account");
    assert_eq!(safe_return_path("//evil.test"), "/");
    assert_eq!(safe_return_path("/x\r\ny"), "/");
}
