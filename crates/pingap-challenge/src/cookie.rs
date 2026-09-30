use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassCookie {
    pub key_id: String,
    pub expires_at: u64,
    pub domain: String,
    pub identity: String,
}

pub fn key_id(secret: &[u8]) -> String {
    let digest = Sha256::digest(secret);
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn sign(
    secret: &[u8],
    domain: &str,
    identity: &str,
    ttl: Duration,
    now: SystemTime,
) -> String {
    let expires = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(ttl.as_secs());
    let kid = key_id(secret);
    let payload = format!("{kid}|{expires}|{domain}|{identity}");
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(payload.as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    format!("v1.{payload}.{tag}")
}

pub fn verify(
    secret: &[u8],
    value: &str,
    domain: &str,
    identity: &str,
    now: SystemTime,
) -> Option<PassCookie> {
    let rest = value.strip_prefix("v1.")?;
    let (payload, tag) = rest.rsplit_once('.')?;
    let mut parts = payload.splitn(4, '|');
    let kid = parts.next()?;
    let expires = parts.next()?.parse::<u64>().ok()?;
    let cookie_domain = parts.next()?;
    let cookie_identity = parts.next()?;
    if kid != key_id(secret)
        || cookie_domain != domain
        || cookie_identity != identity
    {
        return None;
    }
    let payload = format!("{kid}|{expires}|{cookie_domain}|{cookie_identity}");
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if !pingap_core::constant_time_eq(expected.as_bytes(), tag.as_bytes()) {
        return None;
    }
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (expires > now).then(|| PassCookie {
        key_id: kid.to_string(),
        expires_at: expires,
        domain: cookie_domain.to_string(),
        identity: cookie_identity.to_string(),
    })
}

pub fn set_cookie(value: &str, max_age: Duration) -> String {
    format!(
        "pingap_challenge={value}; Max-Age={}; HttpOnly; Secure; Path=/; SameSite=Lax",
        max_age.as_secs()
    )
}

pub fn cookie_value(header: Option<&str>) -> Option<&str> {
    named_cookie(header, "pingap_challenge")
}

pub fn named_cookie<'a>(
    header: Option<&'a str>,
    name: &str,
) -> Option<&'a str> {
    let prefix = format!("{name}=");
    header?
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&prefix))
}

pub fn set_fingerprint_cookie(value: &str) -> String {
    format!(
        "pingap_challenge_fp={value}; Max-Age=300; HttpOnly; Secure; Path=/; SameSite=Lax"
    )
}
