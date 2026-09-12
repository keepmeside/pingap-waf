//! Credentials: password hashing, TOTP, and session tokens.
//!
//! Three separate secrets with three different lifetimes and three different threat
//! models, kept in one module because the mistakes are the same shape in each: storing
//! something recoverable, comparing something in variable time, or accepting something
//! twice.
//!
//! - **Passwords** are argon2id with the parameters embedded in the stored PHC string, so
//!   raising them later does not invalidate existing credentials.
//! - **TOTP secrets** are encrypted at rest, because unlike a password hash they are
//!   *shared* secrets — a leak lets an attacker generate valid codes forever.
//! - **Session and refresh tokens** are stored hashed and compared in constant time. They
//!   are bearer credentials, so the database must not hold anything replayable.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};

#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum AuthError {
    #[snafu(display("control-plane: password hashing failed: {reason}"))]
    Hash { reason: String },

    #[snafu(display(
        "control-plane: stored password hash is unreadable: {reason}"
    ))]
    CorruptHash { reason: String },

    #[snafu(display("control-plane: TOTP secret is unusable: {reason}"))]
    BadTotpSecret { reason: String },

    #[snafu(display(
        "control-plane: the TOTP encryption key is not configured. A 2FA secret \
         encrypted with a literal key is not encrypted"
    ))]
    MissingEncryptionKey,

    #[snafu(display(
        "control-plane: TOTP secret could not be decrypted: {reason}"
    ))]
    Decrypt { reason: String },
}

/// argon2id with deliberate parameters.
///
/// 19 MiB and 2 passes is the OWASP-recommended floor at the time of writing, and the
/// numbers live here rather than at a call site so there is one place to raise them. They
/// are also written into every hash, so raising them later leaves existing logins working
/// and upgrades them on next use.
fn hasher() -> Result<Argon2<'static>, AuthError> {
    let params =
        Params::new(19 * 1024, 2, 1, None).map_err(|e| AuthError::Hash {
            reason: e.to_string(),
        })?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a password for storage. Returns a PHC string carrying its own parameters and salt.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Hash {
            reason: e.to_string(),
        })?
        .to_string())
}

/// Verify a password against a stored PHC string.
///
/// A malformed stored hash is an error rather than a `false`. Treating it as a mismatch
/// would turn a corrupted row into an account that simply refuses every correct password,
/// which reads as a user error and gets debugged as one.
pub fn verify_password(
    password: &str,
    stored: &str,
) -> Result<bool, AuthError> {
    let parsed =
        PasswordHash::new(stored).map_err(|e| AuthError::CorruptHash {
            reason: e.to_string(),
        })?;
    Ok(hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// The number of 30-second steps either side of now that a code is accepted for.
///
/// One step, i.e. up to 30 seconds of clock skew in each direction. Zero would reject
/// users whose phone is a few seconds off; larger windows widen the replay surface that
/// [`TotpGuard`] exists to close.
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;
const TOTP_DIGITS: usize = 6;

/// Build the TOTP for a base32 secret.
fn totp_for(secret_base32: &str, account: &str) -> Result<TOTP, AuthError> {
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| AuthError::BadTotpSecret {
            reason: format!("{e:?}"),
        })?;
    TOTP::new(
        TotpAlgorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        bytes,
        Some("pingap".to_string()),
        account.to_string(),
    )
    .map_err(|e| AuthError::BadTotpSecret {
        reason: e.to_string(),
    })
}

/// The code an authenticator app would show for `secret_base32` at `now_secs`.
///
/// What a login test needs in order to complete a second factor honestly: the same
/// derivation the verifier runs, driven from the enrolled secret. Not for production use —
/// a server that can generate the code has nothing to verify — which is why it is behind
/// `cfg(any(test, feature = "test-support"))`.
#[cfg(any(test, feature = "test-support"))]
pub fn totp_code_for(
    secret_base32: &str,
    account: &str,
    now_secs: u64,
) -> Result<String, AuthError> {
    Ok(totp_for(secret_base32, account)?.generate(now_secs))
}

/// A fresh base32 secret for enrolment, plus the `otpauth://` URI for a QR code.
pub fn enrol_totp(account: &str) -> Result<(String, String), AuthError> {
    let secret = Secret::generate_secret();
    let base32 = secret.to_encoded().to_string();
    let url = totp_for(&base32, account)?.get_url();
    Ok((base32, url))
}

/// Encrypt a TOTP secret for storage.
///
/// Unlike a password, this is a *shared* secret: an attacker who reads it can mint valid
/// codes indefinitely, so hashing is not an option and plaintext is not acceptable. The
/// key comes from configuration; an absent key is an error rather than a fallback,
/// because a literal default key is indistinguishable from no encryption.
pub fn encrypt_totp_secret(
    secret_base32: &str,
    key: Option<&str>,
) -> Result<String, AuthError> {
    let key = key
        .filter(|k| !k.is_empty())
        .ok_or(AuthError::MissingEncryptionKey)?;
    pingap_util::aes_encrypt(key, secret_base32).map_err(|e| AuthError::Hash {
        reason: e.to_string(),
    })
}

/// Decrypt a stored TOTP secret.
pub fn decrypt_totp_secret(
    stored: &str,
    key: Option<&str>,
) -> Result<String, AuthError> {
    let key = key
        .filter(|k| !k.is_empty())
        .ok_or(AuthError::MissingEncryptionKey)?;
    pingap_util::aes_decrypt(key, stored).map_err(|e| AuthError::Decrypt {
        reason: e.to_string(),
    })
}

/// Rejects a TOTP code that has already been accepted.
///
/// RFC 6238 codes are valid for a whole time step, so without this a code observed once —
/// over the shoulder, in a proxy log, in a phishing relay — works again for the rest of
/// that step and, with skew, the next. Verification alone cannot tell the difference; only
/// remembering what was already spent can.
///
/// Keyed by user *and* step, so two users are never confused for one another and an entry
/// naturally expires when its step passes.
#[derive(Debug, Default)]
pub struct TotpGuard {
    spent: Mutex<HashMap<(String, u64), ()>>,
}

impl TotpGuard {
    /// Verify a code and consume it.
    ///
    /// `Ok(false)` for a wrong code, `Ok(false)` for a replayed one — the caller must not
    /// be able to distinguish them, or the difference becomes an oracle telling an
    /// attacker their captured code was genuine.
    pub fn verify_once(
        &self,
        user: &str,
        secret_base32: &str,
        code: &str,
        now_secs: u64,
    ) -> Result<bool, AuthError> {
        let totp = totp_for(secret_base32, user)?;
        if !totp.check(code, now_secs) {
            return Ok(false);
        }
        // The step the code belongs to, not the current step: a code accepted through the
        // skew window must be spent against *its own* step or the same code would be
        // accepted again once the clock rolls forward.
        let step =
            step_of(&totp, code, now_secs).unwrap_or(now_secs / TOTP_STEP);
        let mut spent = self
            .spent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Anything older than the widest window we would ever accept is unreachable.
        let floor = (now_secs / TOTP_STEP).saturating_sub(TOTP_SKEW as u64 + 1);
        spent.retain(|(_, s), _| *s >= floor);
        if spent.insert((user.to_string(), step), ()).is_some() {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Which step a valid code came from, searching the accepted skew window.
fn step_of(totp: &TOTP, code: &str, now_secs: u64) -> Option<u64> {
    let current = now_secs / TOTP_STEP;
    let skew = TOTP_SKEW as u64;
    (current.saturating_sub(skew)..=current + skew)
        .find(|step| totp.generate(step * TOTP_STEP) == code)
}

/// A fresh bearer token: 256 bits from the OS, hex-encoded.
///
/// Lives beside [`hash_token`] because the two are a pair — the token goes to the client,
/// only its hash goes to the store — and a caller with one and not the other is a caller
/// about to store something replayable.
pub fn new_token() -> String {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Hash a bearer token for storage.
///
/// SHA-256 rather than argon2, deliberately: a session token is 256 bits of entropy this
/// process generated, not a human-chosen password, so there is nothing to brute-force and
/// no reason to pay a KDF on every authenticated request.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Compare two token hashes without an early return.
pub fn tokens_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "PLpKJqvfkjTcYTDpauJf+2JnEayP+bm+0Oe60Jk=";

    #[test]
    fn a_password_hash_is_salted_and_verifiable() {
        let a = hash_password("correct horse battery staple")
            .expect("hashing succeeds");
        let b = hash_password("correct horse battery staple")
            .expect("hashing succeeds");
        assert_ne!(a, b, "two hashes of one password must not be identical");
        assert!(!a.contains("horse"), "the hash carries the password");
        assert!(
            verify_password("correct horse battery staple", &a)
                .expect("verify")
        );
        assert!(!verify_password("wrong", &a).expect("verify"));
    }

    #[test]
    fn the_stored_hash_carries_its_own_parameters() {
        // So raising the cost later leaves existing logins working rather than locking
        // every user out at once.
        let stored = hash_password("pw").expect("hashing succeeds");
        assert!(stored.starts_with("$argon2id$"), "not argon2id: {stored}");
        assert!(stored.contains("m=19456"), "memory cost absent: {stored}");
        assert!(stored.contains("t=2"), "time cost absent: {stored}");
    }

    #[test]
    fn a_corrupt_stored_hash_is_an_error_rather_than_a_mismatch() {
        // Reporting it as "wrong password" turns a damaged row into an account that
        // refuses every correct password, which gets debugged as a user error.
        let err = verify_password("pw", "not-a-phc-string")
            .expect_err("a malformed hash must not read as a mismatch");
        assert!(matches!(err, AuthError::CorruptHash { .. }));
    }

    #[test]
    fn a_totp_secret_round_trips_through_encryption_and_is_not_stored_readable()
    {
        let (secret, url) = enrol_totp("alice").expect("enrolment succeeds");
        assert!(url.starts_with("otpauth://totp/"), "unusable URI: {url}");
        assert!(url.contains("pingap"), "the issuer is missing: {url}");

        let stored = encrypt_totp_secret(&secret, Some(KEY)).expect("encrypts");
        assert!(
            !stored.contains(&secret),
            "the ciphertext contains the secret"
        );
        assert_eq!(
            decrypt_totp_secret(&stored, Some(KEY)).expect("decrypts"),
            secret
        );
    }

    #[test]
    fn an_absent_encryption_key_is_refused_rather_than_defaulted() {
        // A literal default key is indistinguishable from no encryption, and a shared
        // TOTP secret in the clear lets an attacker mint valid codes forever.
        for key in [None, Some("")] {
            assert_eq!(
                encrypt_totp_secret("JBSWY3DPEHPK3PXP", key),
                Err(AuthError::MissingEncryptionKey)
            );
            assert_eq!(
                decrypt_totp_secret("whatever", key),
                Err(AuthError::MissingEncryptionKey)
            );
        }
    }

    #[test]
    fn a_valid_code_is_accepted_once_and_then_rejected() {
        // The named criterion. RFC 6238 codes stay valid for a whole time step, so
        // without this a code seen over the shoulder or in a phishing relay works again
        // for the rest of that step.
        let (secret, _) = enrol_totp("alice").expect("enrolment succeeds");
        let totp = totp_for(&secret, "alice").expect("totp builds");
        let now = 1_760_000_000u64;
        let code = totp.generate(now);

        let guard = TotpGuard::default();
        assert!(
            guard
                .verify_once("alice", &secret, &code, now)
                .expect("verifies"),
            "a fresh code was refused"
        );
        assert!(
            !guard
                .verify_once("alice", &secret, &code, now)
                .expect("verifies"),
            "a replayed code was accepted"
        );
    }

    #[test]
    fn a_code_spent_by_one_user_is_still_available_to_another() {
        // Keyed by user as well as step. Sharing the key would let one account's login
        // lock another's out for thirty seconds — a denial of service by design.
        let (a_secret, _) = enrol_totp("alice").expect("enrolment succeeds");
        let now = 1_760_000_000u64;
        let code = totp_for(&a_secret, "alice")
            .expect("totp builds")
            .generate(now);
        let guard = TotpGuard::default();
        assert!(
            guard
                .verify_once("alice", &a_secret, &code, now)
                .expect("ok")
        );
        // Bob presenting alice's code against his own secret is simply wrong, not
        // replayed — the point is that the guard does not confuse the two users.
        let (b_secret, _) = enrol_totp("bob").expect("enrolment succeeds");
        let b_code = totp_for(&b_secret, "bob")
            .expect("totp builds")
            .generate(now);
        assert!(
            guard
                .verify_once("bob", &b_secret, &b_code, now)
                .expect("ok")
        );
    }

    #[test]
    fn a_replay_is_indistinguishable_from_a_wrong_code() {
        // Reporting them differently would tell an attacker their captured code was
        // genuine, which is the one thing a replay guard must not leak.
        let (secret, _) = enrol_totp("alice").expect("enrolment succeeds");
        let now = 1_760_000_000u64;
        let code = totp_for(&secret, "alice").expect("builds").generate(now);
        let guard = TotpGuard::default();
        guard.verify_once("alice", &secret, &code, now).expect("ok");
        let replayed =
            guard.verify_once("alice", &secret, &code, now).expect("ok");
        let wrong = guard
            .verify_once("alice", &secret, "000000", now)
            .expect("ok");
        assert_eq!(replayed, wrong, "both must be a plain false");
    }

    #[test]
    fn a_code_from_the_previous_step_is_accepted_but_only_once() {
        // The skew window exists so a phone a few seconds slow still works. It must not
        // become a second bite at the same code.
        let (secret, _) = enrol_totp("alice").expect("enrolment succeeds");
        let totp = totp_for(&secret, "alice").expect("builds");
        let now = 1_760_000_000u64;
        let earlier = totp.generate(now - TOTP_STEP);
        let guard = TotpGuard::default();
        assert!(
            guard
                .verify_once("alice", &secret, &earlier, now)
                .expect("ok"),
            "a code from one step ago should be inside the skew window"
        );
        assert!(
            !guard
                .verify_once("alice", &secret, &earlier, now)
                .expect("ok"),
            "the skew window gave the same code a second chance"
        );
    }

    #[test]
    fn a_new_token_is_64_hex_chars_and_never_repeats() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "two tokens from the OS were identical");
    }

    #[test]
    fn a_token_is_stored_hashed_and_compared_in_constant_time() {
        let token = "s3ssion-t0ken-with-plenty-of-entropy";
        let stored = hash_token(token);
        assert_eq!(stored.len(), 64);
        assert!(!stored.contains("s3ssion"), "the token is recoverable");
        assert!(tokens_match(&stored, &hash_token(token)));
        assert!(!tokens_match(&stored, &hash_token("other")));
        // Length mismatch is the one early return, and it leaks only the length of a
        // value whose length is fixed.
        assert!(!tokens_match(&stored, "short"));
    }
}
