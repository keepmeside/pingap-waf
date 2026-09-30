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

#[test]
fn disabled_challenge_does_not_require_an_identity_anchor() {
    let conf: PluginConf = "enabled = false".parse().expect("config");
    Challenge::try_from(&conf).expect("disabled challenge is a no-op");
}
