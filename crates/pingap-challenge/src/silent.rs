use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn fingerprint_cookie(
    secret: &[u8],
    token: &str,
    fingerprint: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts a non-empty key");
    mac.update(token.as_bytes());
    mac.update(b"|");
    mac.update(fingerprint.as_bytes());
    format!("{token}.{}", hex::encode(mac.finalize().into_bytes()))
}

pub fn verify(
    secret: &[u8],
    value: &str,
    token: &str,
    fingerprint: &str,
) -> bool {
    let Some(tag) = value.strip_prefix(token).and_then(|v| v.strip_prefix('.'))
    else {
        return false;
    };
    let expected = fingerprint_cookie(secret, token, fingerprint);
    pingap_core::constant_time_eq(
        expected.rsplit('.').next().unwrap_or_default().as_bytes(),
        tag.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_cookie_is_bound_to_the_token_and_signal_set() {
        let signed =
            fingerprint_cookie(b"secret", "token", "ua|en-US|1920x1080");
        assert!(verify(b"secret", &signed, "token", "ua|en-US|1920x1080"));
        assert!(!verify(b"secret", &signed, "other", "ua|en-US|1920x1080"));
        assert!(!verify(b"secret", &signed, "token", "ua|fr-FR|1920x1080"));
    }
}
