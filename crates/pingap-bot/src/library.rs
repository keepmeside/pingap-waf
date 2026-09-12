//! The seeded fingerprint library, and the known-good crawler list.
//!
//! **Every JA4H here was derived from a captured request, not transcribed and not
//! guessed.** That distinction is the whole point. A fingerprint library exists so that
//! an operator can block a client they have never seen; an entry derived from an
//! *assumed* header order silently matches nobody, and the operator concludes the client
//! is not using that library rather than that the entry is wrong.
//!
//! The reference product ships a larger library. It was treated as behavioural
//! inspiration only — its licence status was flagged in Phase 01, and more importantly its
//! values carry no originating request, so they could not have been verified even if
//! copying them were acceptable.
//!
//! ## How an entry was produced, and how to add one
//!
//! Point the client at a socket that echoes the request head, and read the header names
//! off the wire in order:
//!
//! ```text
//! printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' | nc -l 127.0.0.1 8099
//! ```
//!
//! Then feed those names, in that order, to [`crate::ja4h`]. Entries stop after the `a_b`
//! prefix on purpose: the `c` and `d` components hash cookie names and values, which
//! identify a *session* rather than a client, so including them would make a library entry
//! match exactly one request. [`crate::rule::ValidatedBotRule::matches`] compares an entry
//! as a prefix on `_` boundaries for that reason.
//!
//! ## What is deliberately absent
//!
//! `python-requests` is the headline client in the reference's deny library and it is
//! **not** seeded here, because it is not installed in the environment these entries were
//! captured in and its header order could therefore not be observed. A `user_agent`
//! pattern covers it instead. Shipping a plausible-looking JA4H for it would be the exact
//! failure this module's first paragraph warns about.

/// A client the library recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownClient {
    pub name: &'static str,
    /// The `a_b` prefix of the JA4H, or `None` when only a User-Agent pattern is known.
    pub ja4h: Option<&'static str>,
    /// A substring of the `User-Agent`, matched case-insensitively.
    pub user_agent: Option<&'static str>,
    /// Whether this is a crawler an operator usually wants to keep.
    pub known_good: bool,
    pub notes: &'static str,
}

/// Automation clients and crawlers, in no particular order.
///
/// Captured on 2026-09-03 against a socket echoing the request head, HTTP/1.1, default
/// options, no cookies, no `Accept-Language`, no `Referer`.
pub const fn library() -> &'static [KnownClient] {
    &[
        KnownClient {
            name: "python-urllib",
            // `Accept-Encoding, Host, User-Agent, Connection` — note the unusual
            // leading `Accept-Encoding`, which is what makes this distinctive.
            ja4h: Some("ge11nn040000_5b1e8b5f4d2d"),
            user_agent: Some("python-urllib"),
            known_good: false,
            notes: "captured: urllib.request.urlopen, CPython standard library",
        },
        KnownClient {
            name: "curl",
            // `Host, User-Agent, Accept`.
            ja4h: Some("ge11nn030000_fe444ad14866"),
            user_agent: Some("curl/"),
            known_good: false,
            notes: "captured: curl with default options",
        },
        KnownClient {
            name: "python-requests",
            // Not captured — see the module docs. UA only, deliberately.
            ja4h: None,
            user_agent: Some("python-requests"),
            known_good: false,
            notes: "user-agent only: header order was not observed in this environment",
        },
        KnownClient {
            name: "node-fetch",
            ja4h: None,
            user_agent: Some("node-fetch"),
            known_good: false,
            notes: "user-agent only: header order was not observed in this environment",
        },
        KnownClient {
            name: "Go-http-client",
            ja4h: None,
            user_agent: Some("Go-http-client"),
            known_good: false,
            notes: "user-agent only: header order was not observed in this environment",
        },
        KnownClient {
            name: "Googlebot",
            ja4h: None,
            user_agent: Some("Googlebot"),
            known_good: true,
            notes: "verify by reverse DNS before trusting; a UA is not proof",
        },
        KnownClient {
            name: "Bingbot",
            ja4h: None,
            user_agent: Some("bingbot"),
            known_good: true,
            notes: "verify by reverse DNS before trusting; a UA is not proof",
        },
        KnownClient {
            name: "DuckDuckBot",
            ja4h: None,
            user_agent: Some("DuckDuckBot"),
            known_good: true,
            notes: "verify by reverse DNS before trusting; a UA is not proof",
        },
        KnownClient {
            name: "Applebot",
            ja4h: None,
            user_agent: Some("Applebot"),
            known_good: true,
            notes: "verify by reverse DNS before trusting; a UA is not proof",
        },
    ]
}

/// Whether this User-Agent belongs to a crawler the library treats as known-good.
///
/// **A User-Agent is a claim, not evidence.** Anyone can send `Googlebot`. This exemption
/// exists so that a broad deny does not cost an operator their search ranking, and it is
/// the right trade for that purpose — the cost of a false *allow* here is that a scraper
/// impersonating Googlebot gets through, which the WAF and the ACL still see. It must not
/// be used to gate anything that matters; `notes` on each entry says to confirm by reverse
/// DNS, which is a control this crate does not implement.
pub fn is_known_good(user_agent: &str) -> bool {
    library().iter().any(|client| {
        client.known_good
            && client.user_agent.is_some_and(|needle| {
                user_agent.to_lowercase().contains(&needle.to_lowercase())
            })
    })
}

/// Self-declared client names, as bot rules.
///
/// These moved here from the WAF's detector set, and the move is the point: a bot verdict
/// has to come from one place. While the WAF also matched User-Agents, two subsystems
/// returned bot decisions with different precedence and different vocabulary — a scraper
/// could be refused with an anomaly score attached, which is not a thing a scraper has.
///
/// The tiering the WAF expressed with paranoia levels is expressed here with actions,
/// because the bot model has no score to tier:
///
/// | Class | Action | Why |
/// |---|---|---|
/// | Vulnerability scanners | `deny` | No legitimate reason to be pointed at someone else's origin |
/// | Site copiers, SEO crawlers | `log` | Unwanted is a bandwidth decision, not a security finding |
/// | Generic HTTP libraries | `log` | What a normal API integration sends; denying them breaks real clients |
///
/// Three of the reference's patterns are absent rather than narrowed: `\bscan\b`,
/// `\bharvest\b` and `\bextract\b` match ordinary words, and no amount of context rescues
/// a pattern whose signal is a common English verb.
///
/// Opt-in. Matching a client by the name it chose to send is a weak signal — a scanner
/// can claim to be Firefox — so this is a cheap first filter offered to operators, not a
/// default.
pub fn scanner_signatures() -> Vec<crate::rule::BotRule> {
    use crate::rule::{BotAction, BotRule};
    let rule = |pattern: &str, action: BotAction, remark: &str| BotRule {
        fingerprint_type: None,
        fingerprint: None,
        user_agent: Some(pattern.to_string()),
        action,
        enabled: true,
        remark: Some(remark.to_string()),
    };
    let deny =
        |pattern: &str| rule(pattern, BotAction::Deny, "vulnerability scanner");
    let note = |pattern: &str, why: &str| rule(pattern, BotAction::Log, why);
    vec![
        deny(r"(?i)\bsqlmap\b"),
        deny(r"(?i)\bnikto\b"),
        deny(r"(?i)\bnmap\b"),
        deny(r"(?i)\bmasscan\b"),
        deny(r"(?i)\bmetasploit\b"),
        deny(r"(?i)\bburp(?:suite)?\b"),
        deny(r"(?i)\bacunetix\b"),
        deny(r"(?i)\bnessus\b"),
        deny(r"(?i)\bowasp\b.{0,20}\bzap\b"),
        deny(r"(?i)\bdirbuster\b"),
        deny(r"(?i)\bgobuster\b"),
        deny(r"(?i)\bffuf\b"),
        deny(r"(?i)\bwpscan\b"),
        deny(r"(?i)\bjoomscan\b"),
        deny(r"(?i)\bw3af\b"),
        deny(r"(?i)\barachni\b"),
        deny(r"(?i)\bskipfish\b"),
        note(r"(?i)\bscrapy\b", "site copier"),
        note(r"(?i)\bwebharvest\b", "site copier"),
        note(r"(?i)\bhttrack\b", "site copier"),
        note(r"(?i)\bwebcopier\b", "site copier"),
        note(r"(?i)\boffline\s*explorer\b", "site copier"),
        note(r"(?i)\bteleport\s*pro\b", "site copier"),
        note(r"(?i)\bwebzip\b", "site copier"),
        note(r"(?i)\bsemrush(?:bot)?\b", "SEO crawler"),
        note(r"(?i)\bahrefsbot\b", "SEO crawler"),
        note(r"(?i)\bmj12bot\b", "SEO crawler"),
        note(r"(?i)\bdotbot\b", "SEO crawler"),
        note(r"(?i)\bseekport\b", "SEO crawler"),
        note(r"(?i)\bblexbot\b", "SEO crawler"),
        note(r"^python-requests", "HTTP library"),
        note(r"^python-urllib", "HTTP library"),
        note(r"^Java/", "HTTP library"),
        note(r"^libwww-perl", "HTTP library"),
        note(r"^Go-http-client", "HTTP library"),
        note(r"(?i)^curl/", "HTTP library"),
        note(r"(?i)^wget/", "HTTP library"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{BotAction, ValidatedBotRule};

    #[test]
    fn every_seeded_fingerprint_is_a_well_formed_ja4h() {
        // An entry that is not a JA4H would be refused at config load, so a library
        // shipping one would be a library nobody could enable.
        for client in library() {
            if let Some(value) = client.ja4h {
                assert!(
                    crate::ja4h::looks_like_ja4h(value),
                    "{} carries a malformed fingerprint: {value}",
                    client.name
                );
            }
        }
    }

    #[test]
    fn every_seeded_entry_identifies_its_client_somehow() {
        for client in library() {
            assert!(
                client.ja4h.is_some() || client.user_agent.is_some(),
                "{} matches nothing at all",
                client.name
            );
        }
    }

    #[test]
    fn a_seeded_fingerprint_records_how_it_was_obtained() {
        // The module's central claim is that no fingerprint here was guessed. An entry
        // with a fingerprint and no capture note is exactly how that claim rots.
        for client in library() {
            if client.ja4h.is_some() {
                assert!(
                    client.notes.contains("captured"),
                    "{} has a fingerprint but does not say where it came from",
                    client.name
                );
            }
        }
    }

    #[test]
    fn every_scanner_signature_compiles_and_only_scanners_deny() {
        let signatures = scanner_signatures();
        assert!(signatures.len() > 30, "the moved set looks truncated");
        for (index, spec) in signatures.iter().enumerate() {
            let remark = spec.remark.clone().unwrap_or_default();
            let action = spec.action;
            ValidatedBotRule::new(spec.clone(), index)
                .expect("every shipped signature must be loadable");
            if action == BotAction::Deny {
                assert_eq!(
                    remark, "vulnerability scanner",
                    "only scanners deny; {remark} should not"
                );
            }
        }
    }

    #[test]
    fn the_common_english_words_the_reference_matched_are_absent() {
        // `\bscan\b`, `\bharvest\b` and `\bextract\b` fire on ordinary product names.
        let joined = scanner_signatures()
            .iter()
            .filter_map(|r| r.user_agent.clone())
            .collect::<Vec<_>>()
            .join(" ");
        for word in [r"\bscan\b", r"\bharvest\b", r"\bextract\b"] {
            assert!(
                !joined.contains(word),
                "{word} came back; it matches ordinary words"
            );
        }
    }

    #[test]
    fn a_known_good_crawler_is_recognised_case_insensitively() {
        assert!(is_known_good("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(is_known_good("BINGBOT/2.0"));
        assert!(!is_known_good("python-urllib/3.11"));
        assert!(!is_known_good(""));
    }
}
