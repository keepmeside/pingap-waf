use pingap_challenge::Challenge;
use pingap_challenge::cookie::{cookie_value, set_cookie, sign, verify};
use pingap_config::PluginConf;
use std::time::{Duration, SystemTime};

#[test]
fn pass_cookie_is_signed_identity_bound_and_has_safe_attributes() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let value = sign(
        b"secret",
        "a.test",
        "203.0.113.9",
        Duration::from_secs(60),
        now,
    );
    let header = set_cookie(&value, Duration::from_secs(60));
    assert!(header.contains("HttpOnly"));
    assert!(header.contains("Secure"));
    assert!(header.contains("Path=/"));
    assert!(header.contains("SameSite=Lax"));
    assert!(!header.contains("Domain="));
    assert!(verify(b"secret", &value, "a.test", "203.0.113.9", now).is_some());
    assert!(verify(b"secret", &value, "b.test", "203.0.113.9", now).is_none());
    assert!(verify(b"secret", &value, "a.test", "198.51.100.4", now).is_none());
    assert!(cookie_value(Some(&format!("other=x; {header}"))).is_some());
}

/// A cookie an attacker builds cannot pass as a pass cookie: the same shape,
/// signed by the wrong key, is refused — and so is the honest cookie with one
/// tag nibble flipped, which isolates the signature from the shape. The
/// honest cookie still passes, so the refusals are the signature's doing and
/// not the parser's.
#[test]
fn a_valid_shaped_cookie_with_a_broken_signature_is_refused() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let honest = sign(
        b"secret",
        "a.test",
        "203.0.113.9",
        Duration::from_secs(60),
        now,
    );
    let wrong_key = sign(
        b"attacker",
        "a.test",
        "203.0.113.9",
        Duration::from_secs(60),
        now,
    );
    assert!(
        verify(b"secret", &wrong_key, "a.test", "203.0.113.9", now).is_none(),
        "a cookie signed by another key passed as a pass cookie"
    );
    let mut flipped = honest.clone();
    let nibble = flipped.pop().expect("a signed cookie ends in a tag nibble");
    flipped.push(if nibble == '0' { '1' } else { '0' });
    assert!(
        verify(b"secret", &flipped, "a.test", "203.0.113.9", now).is_none(),
        "a cookie with one tag nibble flipped passed as a pass cookie"
    );
    assert!(
        verify(b"secret", &honest, "a.test", "203.0.113.9", now).is_some(),
        "the honest cookie was refused beside the forged ones"
    );
}

#[test]
fn disabled_challenge_does_not_require_an_identity_anchor() {
    let conf: PluginConf = "enabled = false".parse().expect("config");
    Challenge::try_from(&conf).expect("disabled challenge is a no-op");
}
