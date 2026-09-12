//! Named access lists: an IP allowlist plus HTTP basic-auth users, attachable to many
//! domains.
//!
//! **Empty means "allow nothing", not "allow all".** This is the one inherited
//! convention the fusion deliberately inverts: the reference detector treated an empty
//! list as "no restriction", so a half-written config served unprotected traffic while
//! looking configured. An access list exists to gate; a gate with no keys is shut.
//!
//! Credentials are never logged and never compared byte-for-byte in variable time. What
//! is stored here is a hash, so a config file leak does not immediately yield a usable
//! password — see [`AccessList::new`] for the exact limits of that claim.

use pingap_util::IpRules;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Whether one satisfied condition is enough, or all configured ones must be.
///
/// Named and defaulted rather than left implicit: "IP allowlist plus basic auth" does
/// not say how the two combine, and an undefined combination rule in an access control
/// is a security bug rather than a documentation gap. `Any` mirrors nginx's
/// `satisfy any`, which is what "the office network, or a password from anywhere else"
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Satisfy {
    #[default]
    Any,
    All,
}

#[derive(Debug, PartialEq, Eq, snafu::Snafu)]
pub enum AccessListError {
    #[snafu(display(
        "acl: access list `{name}` entry `{entry}` is not `username:sha256hex` — \
         expected a user name, a colon, and 64 hex characters"
    ))]
    MalformedUser { name: String, entry: String },

    #[snafu(display(
        "acl: access list `{name}` lists `{value}`, which is not an IP address or \
         CIDR range"
    ))]
    BadCidr { name: String, value: String },
}

/// An access list as written in config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccessListConf {
    /// Addresses and CIDR ranges that satisfy the list without credentials.
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    /// `username:sha256hex` entries. The hash is of the password alone, not of
    /// `user:pass`, so a password can be rotated without the user name entering it.
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub satisfy: Satisfy,
}

/// A validated access list.
#[derive(Debug, Clone)]
pub struct AccessList {
    name: String,
    allowlist: IpRules,
    /// Kept separately because `IpRules` cannot report emptiness, and empty is the
    /// case with the security-relevant meaning here.
    allowlist_entries: usize,
    /// User name to lowercase hex SHA-256 of the password.
    users: BTreeMap<String, String>,
    satisfy: Satisfy,
}

impl AccessList {
    /// Validate and build.
    ///
    /// # On the choice of hash
    /// Unsalted SHA-256, verified per request. That is a deliberate, bounded claim: it
    /// keeps a recoverable password out of the config file and out of process memory,
    /// and it costs about a microsecond so it can run on the request path. It is **not**
    /// a password KDF — an attacker holding this file can brute-force a weak password
    /// offline, and no amount of salting at this layer would change that for a
    /// four-character password. Slow-KDF-at-rest belongs to the control-plane store,
    /// where a login happens once rather than per request.
    pub fn new(
        name: &str,
        conf: &AccessListConf,
    ) -> Result<Self, AccessListError> {
        let allowlist = IpRules::new(&conf.ip_allowlist);
        if allowlist.len() != conf.ip_allowlist.len() {
            let value = conf
                .ip_allowlist
                .iter()
                .find(|v| IpRules::new(std::slice::from_ref(*v)).is_empty())
                .cloned()
                .unwrap_or_default();
            return Err(AccessListError::BadCidr {
                name: name.to_string(),
                value,
            });
        }

        let mut users = BTreeMap::new();
        for entry in &conf.users {
            let Some((user, hash)) = entry.split_once(':') else {
                return Err(AccessListError::MalformedUser {
                    name: name.to_string(),
                    entry: entry.clone(),
                });
            };
            let valid = !user.is_empty()
                && hash.len() == 64
                && hash.bytes().all(|b| b.is_ascii_hexdigit());
            if !valid {
                return Err(AccessListError::MalformedUser {
                    name: name.to_string(),
                    entry: entry.clone(),
                });
            }
            users.insert(user.to_string(), hash.to_ascii_lowercase());
        }

        Ok(Self {
            name: name.to_string(),
            allowlist,
            allowlist_entries: conf.ip_allowlist.len(),
            users,
            satisfy: conf.satisfy,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether credentials are configured, so a caller knows whether a 401 challenge
    /// could ever be satisfied.
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// Whether this address satisfies the IP half of the list.
    ///
    /// An empty allowlist satisfies nothing. That is the inverted convention this
    /// module exists to state: a gate with no keys is shut.
    fn ip_satisfies(&self, client_ip: &str) -> bool {
        if self.allowlist_entries == 0 {
            return false;
        }
        self.allowlist.is_match(client_ip).unwrap_or(false)
    }

    /// Whether these credentials satisfy the user half.
    ///
    /// Returns false for an unknown user without revealing that it was the user rather
    /// than the password that was wrong — and without a short-circuit that would make
    /// "no such user" measurably faster than "wrong password".
    fn credentials_satisfy(&self, user: &str, password: &str) -> bool {
        let presented = hex_sha256(password.as_bytes());
        // An absent user is compared against a fixed non-matching digest, so the work
        // done is the same either way.
        const NEVER: &str =
            "0000000000000000000000000000000000000000000000000000000000000000";
        let expected =
            self.users.get(user).map(String::as_str).unwrap_or(NEVER);
        constant_time_eq(expected.as_bytes(), presented.as_bytes())
            && self.users.contains_key(user)
    }

    /// Whether the request gets through.
    ///
    /// `credentials` is the decoded `user:password` pair, or `None` when the request
    /// carried no usable `Authorization` header. Decoding belongs to the caller so this
    /// stays testable without an HTTP session.
    pub fn admits(
        &self,
        client_ip: &str,
        credentials: Option<(&str, &str)>,
    ) -> bool {
        let by_ip = self.ip_satisfies(client_ip);
        let by_password = credentials
            .map(|(user, password)| self.credentials_satisfy(user, password))
            .unwrap_or(false);

        match self.satisfy {
            Satisfy::Any => by_ip || by_password,
            // `All` means every *configured* condition must hold. An unconfigured half
            // is not a free pass, because an empty half never satisfies — so a list
            // with `satisfy = "all"` and no users at all admits nobody, which is the
            // fail-closed reading and is asserted by test.
            Satisfy::All => by_ip && by_password,
        }
    }
}

/// Lowercase hex SHA-256, the storage form for a password.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Compare without an early return, so the time taken does not depend on where the
/// first differing byte is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(conf: AccessListConf) -> AccessList {
        AccessList::new("office", &conf).expect("test list is valid")
    }

    fn with_user(password: &str) -> AccessListConf {
        AccessListConf {
            users: vec![format!("alice:{}", hex_sha256(password.as_bytes()))],
            ..Default::default()
        }
    }

    #[test]
    fn an_empty_list_admits_nobody() {
        // The inherited convention was the opposite: an empty list meant "no
        // restriction", so a half-written config served unprotected traffic while
        // looking configured.
        let shut = list(AccessListConf::default());
        assert!(!shut.admits("10.1.2.3", None));
        assert!(!shut.admits("10.1.2.3", Some(("alice", "secret"))));
    }

    #[test]
    fn an_empty_allowlist_does_not_admit_every_address() {
        let creds_only = list(with_user("secret"));
        assert!(
            !creds_only.admits("10.1.2.3", None),
            "an unconfigured IP half must not be a free pass"
        );
        assert!(creds_only.admits("10.1.2.3", Some(("alice", "secret"))));
    }

    #[test]
    fn an_allowlisted_address_needs_no_password_under_satisfy_any() {
        let office = list(AccessListConf {
            ip_allowlist: vec!["10.0.0.0/8".to_string()],
            ..with_user("secret")
        });
        assert!(office.admits("10.1.2.3", None));
        assert!(!office.admits("203.0.113.9", None));
        assert!(office.admits("203.0.113.9", Some(("alice", "secret"))));
    }

    #[test]
    fn satisfy_all_requires_both_and_admits_nobody_when_one_half_is_empty() {
        let both = list(AccessListConf {
            ip_allowlist: vec!["10.0.0.0/8".to_string()],
            satisfy: Satisfy::All,
            ..with_user("secret")
        });
        assert!(both.admits("10.1.2.3", Some(("alice", "secret"))));
        assert!(!both.admits("10.1.2.3", None));
        assert!(!both.admits("203.0.113.9", Some(("alice", "secret"))));

        // No users configured, so the credential half can never be satisfied.
        let impossible = list(AccessListConf {
            ip_allowlist: vec!["10.0.0.0/8".to_string()],
            satisfy: Satisfy::All,
            ..Default::default()
        });
        assert!(!impossible.admits("10.1.2.3", Some(("alice", "secret"))));
    }

    #[test]
    fn a_wrong_password_or_unknown_user_is_refused() {
        let office = list(with_user("secret"));
        assert!(!office.admits("10.1.2.3", Some(("alice", "wrong"))));
        assert!(!office.admits("10.1.2.3", Some(("bob", "secret"))));
        // The digest of the right password for the wrong user must not admit either.
        assert!(!office.admits("10.1.2.3", Some(("", "secret"))));
    }

    #[test]
    fn a_malformed_user_entry_is_refused_with_the_entry_named() {
        for bad in ["alice", "alice:", ":deadbeef", "alice:nothex", "alice:abc"]
        {
            let err = AccessList::new(
                "office",
                &AccessListConf {
                    users: vec![bad.to_string()],
                    ..Default::default()
                },
            )
            .expect_err("a malformed entry must fail");
            assert!(
                err.to_string().contains(bad),
                "the error must name the entry: {err}"
            );
        }
    }

    #[test]
    fn a_malformed_allowlist_entry_is_refused_with_the_value_named() {
        let err = AccessList::new(
            "office",
            &AccessListConf {
                ip_allowlist: vec!["10.0.0.0/8".into(), "office-lan".into()],
                ..Default::default()
            },
        )
        .expect_err("a malformed CIDR must fail");
        assert!(
            err.to_string().contains("office-lan"),
            "the error must name the value: {err}"
        );
    }

    #[test]
    fn the_stored_form_is_a_digest_rather_than_the_password() {
        // A config leak should not immediately yield a usable password. This is a
        // bounded claim — see the note on `AccessList::new` — but the storage form is
        // the part that has to actually hold.
        let digest = hex_sha256(b"secret");
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains("secret"));
        assert_eq!(digest, hex_sha256(b"secret"), "hashing must be stable");
        assert_ne!(digest, hex_sha256(b"secrer"));
    }
}
