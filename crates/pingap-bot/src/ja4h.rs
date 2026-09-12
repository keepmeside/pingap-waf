//! JA4H — the HTTP client fingerprint.
//!
//! A pure function of the request head: no session, no I/O, no knowledge that Pingora
//! exists. That is what lets it be checked against published vectors instead of only
//! against itself, which matters more here than anywhere else in this workspace.
//!
//! **A plausible-looking fingerprint that agrees with no other implementation is worse
//! than none**, because the whole value of a fingerprint is that a list of them can be
//! shared. This module's canonicalisation is therefore not inferred from prose — it is
//! pinned to FoxIO's own reference implementation and cross-checked against ten
//! request/fingerprint pairs from FoxIO's committed pcap fixtures. See `tests/ja4h.rs`.
//!
//! Format: `{a}_{b}_{c}_{d}`
//!
//! | Part | Content |
//! |---|---|
//! | `a` | method (2) + version (2) + cookie flag + referer flag + header count (2) + language (4) |
//! | `b` | SHA-256, first 12 hex, of the header names comma-joined **in the order sent** |
//! | `c` | the same, of the cookie **names**, sorted |
//! | `d` | the same, of the cookie `name=value` pairs, sorted by name |
//!
//! `Cookie` and `Referer` are excluded from both the count and `b` — they are already
//! represented by their flags and by `c`/`d`. Absent cookies give twelve zeros rather
//! than the hash of an empty string, which is the one place the format does not simply
//! hash what it has.

use sha2::{Digest, Sha256};

/// HTTP version, as JA4H spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
    /// Present for completeness. This crate does not *emit* a fingerprint for h2 — see
    /// [`crate::plugin`] — because Pingora does not preserve header order there.
    Http20,
}

impl Version {
    const fn digits(self) -> &'static str {
        match self {
            Self::Http10 => "10",
            Self::Http11 => "11",
            Self::Http20 => "20",
        }
    }
}

/// The parts of a request head the fingerprint is computed from.
///
/// `header_names` must be in **wire order and original case**, and must include `Cookie`
/// and `Referer` if they were sent — this function filters them, because the count and
/// the hash have to agree about what was excluded. Sorting or lowercasing the names
/// before passing them in produces a fingerprint that matches nobody.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestHead<'a> {
    pub method: &'a str,
    pub version_digits: &'a str,
    pub header_names: &'a [&'a str],
    /// The raw `Cookie` header value.
    pub cookie: Option<&'a str>,
    /// The raw `Accept-Language` header value.
    pub accept_language: Option<&'a str>,
}

impl<'a> RequestHead<'a> {
    pub fn new(
        method: &'a str,
        version: Version,
        header_names: &'a [&'a str],
    ) -> Self {
        Self {
            method,
            version_digits: version.digits(),
            header_names,
            cookie: None,
            accept_language: None,
        }
    }
}

/// SHA-256 of the comma-joined values, truncated to 12 lowercase hex characters.
fn sha_encode(values: &[&str]) -> String {
    let joined = values.join(",");
    let digest = Sha256::digest(joined.as_bytes());
    let mut out = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Whether a header name is excluded from the count and from `b`.
///
/// `cookie` matches by prefix and `referer` exactly, which is what the reference does.
/// HTTP/2 pseudo-headers (`:method` and friends) are dropped too; they are not headers
/// the client chose to send in an order.
fn is_excluded(name: &str) -> bool {
    if name.starts_with(':') {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.starts_with("cookie") || lower == "referer"
}

/// The 4-character language component.
///
/// Mirrors the reference exactly, including its lack of trimming: strip `-`, turn `;`
/// into `,`, lowercase, take everything before the first `,`, truncate to four
/// characters and right-pad with `0`. `en-US,en;q=0.9` becomes `enus`; `da, en-gb;q=0.8`
/// becomes `da00`. Deliberately not trimmed — a value written `da , en` yields `da 0` in
/// the reference too, and matching it matters more than tidiness.
fn language(value: &str) -> String {
    let normalised = value
        .replace('-', "")
        .replace(';', ",")
        .to_ascii_lowercase();
    let first = normalised.split(',').next().unwrap_or_default();
    let mut out: String = first.chars().take(4).collect();
    while out.len() < 4 {
        out.push('0');
    }
    out
}

/// Cookie name/value pairs, in the order sent.
fn cookie_pairs(header: &str) -> Vec<(&str, &str)> {
    header
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let name = part.split_once('=').map(|(n, _)| n).unwrap_or(part);
            (name.trim(), part)
        })
        .collect()
}

/// Whether a string is shaped like a JA4H.
///
/// Checked so a deny list cannot be filled with values that could never match anything —
/// a typo'd or truncated fingerprint is a rule the operator believes is enforcing.
/// Accepts one to three trailing hashes, because published lists routinely carry only the
/// `a_b` prefix: the cookie components identify a *session* rather than a client, so a
/// library entry for "python-requests" deliberately stops before them.
pub fn looks_like_ja4h(value: &str) -> bool {
    let Some((head, rest)) = value.split_once('_') else {
        return false;
    };
    // `a` is method(2) + version(2) + cookie(1) + referer(1) + count(2) + lang(4).
    let a: Vec<char> = head.chars().collect();
    if a.len() != 12 {
        return false;
    }
    let shaped = a[0].is_ascii_lowercase()
        && a[1].is_ascii_lowercase()
        && a[2].is_ascii_digit()
        && a[3].is_ascii_digit()
        && matches!(a[4], 'c' | 'n')
        && matches!(a[5], 'r' | 'n')
        && a[6].is_ascii_digit()
        && a[7].is_ascii_digit()
        && a[8..12].iter().all(|c| c.is_ascii_alphanumeric());
    if !shaped {
        return false;
    }
    let hashes: Vec<&str> = rest.split('_').collect();
    (1..=3).contains(&hashes.len())
        && hashes
            .iter()
            .all(|h| h.len() == 12 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Compute the fingerprint.
pub fn ja4h(head: &RequestHead<'_>) -> String {
    let counted: Vec<&str> = head
        .header_names
        .iter()
        .copied()
        .filter(|name| !is_excluded(name))
        .collect();

    let pairs = head.cookie.map(cookie_pairs).unwrap_or_default();
    let has_cookies = !pairs.is_empty();

    let method: String =
        head.method.to_ascii_lowercase().chars().take(2).collect();
    let cookie_flag = if has_cookies { 'c' } else { 'n' };
    let referer_flag = if head
        .header_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("referer"))
    {
        'r'
    } else {
        'n'
    };
    let count = counted.len().min(99);
    let lang = head
        .accept_language
        .map(language)
        .unwrap_or_else(|| "0000".to_string());

    let headers_hash = sha_encode(&counted);

    // Names sorted alphabetically; values sorted *by name*, carrying `name=value`.
    // Confirmed against the `http1-with-cookies` fixture, where the sent order was
    // `yummy_cookie, tasty_cookie` and both hashes correspond to the sorted order.
    let (cookies_hash, values_hash) = if has_cookies {
        let mut sorted = pairs.clone();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let names: Vec<&str> = sorted.iter().map(|(n, _)| *n).collect();
        let values: Vec<&str> = sorted.iter().map(|(_, v)| *v).collect();
        (sha_encode(&names), sha_encode(&values))
    } else {
        ("0".repeat(12), "0".repeat(12))
    };

    format!(
        "{method}{version}{cookie_flag}{referer_flag}{count:02}{lang}_\
         {headers_hash}_{cookies_hash}_{values_hash}",
        version = head.version_digits,
    )
}
