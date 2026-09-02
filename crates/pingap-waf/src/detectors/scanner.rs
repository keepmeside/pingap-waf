//! Scanner and abusive-client fingerprints (CRS 934 generic lineage).
//!
//! Ported from the reference's bot detector. Two changes of substance.
//!
//! **These patterns only inspect `User-Agent`.** A User-Agent naming `sqlmap`
//! identifies the client; the word `sqlmap` in a request body is someone writing
//! about tools. Scanning every field with client-fingerprint patterns manufactures
//! false positives that no pattern tuning can remove, so the scope is the header
//! and nothing else.
//!
//! **Legitimate HTTP libraries sit at paranoia 3.** `curl/`, `Go-http-client`,
//! `python-requests` and `Java/` are what most API integrations send. Flagging them
//! at the default level would mean flagging the majority of a typical API's real
//! traffic. They stay available for operators who genuinely serve browsers only,
//! and they are the reason paranoia exists as a dial rather than a constant.
//!
//! Three of the reference's patterns are dropped outright rather than narrowed:
//! `\bscan\b`, `\bharvest\b` and `\bextract\b` match ordinary words. `\bscan\b`
//! alone would fire on any User-Agent or product name containing "scan", and no
//! amount of context can rescue a pattern whose signal is a common English verb.
//!
//! Fingerprinting a client by its *self-declared* name is weak by nature — a
//! scanner can send any string it likes. This is a cheap first filter, not the bot
//! story; the TLS/HTTP fingerprint work is where that lives.

use super::{Spec, spec_in_header};
use crate::rule::Severity;

/// Everything here inspects this one header.
const UA: &str = "user-agent";

/// A scanner name at the default paranoia level: these tools have no legitimate
/// reason to be pointed at someone else's origin.
fn scanner(offset: u32, pattern: &str, severity: Severity) -> Spec {
    spec_in_header(offset, UA, pattern, severity, 1)
}

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Vulnerability scanners and exploitation frameworks ---------------
        scanner(1, r"(?i)\bsqlmap\b", Severity::Critical),
        scanner(2, r"(?i)\bnikto\b", Severity::Critical),
        scanner(3, r"(?i)\bnmap\b", Severity::Critical),
        scanner(4, r"(?i)\bmasscan\b", Severity::Critical),
        scanner(5, r"(?i)\bmetasploit\b", Severity::Critical),
        scanner(6, r"(?i)\bburp(?:suite)?\b", Severity::Critical),
        scanner(7, r"(?i)\bacunetix\b", Severity::Critical),
        scanner(8, r"(?i)\bnessus\b", Severity::Critical),
        scanner(9, r"(?i)\bowasp\b.{0,20}\bzap\b", Severity::Critical),
        scanner(10, r"(?i)\bdirbuster\b", Severity::Critical),
        scanner(11, r"(?i)\bgobuster\b", Severity::Critical),
        scanner(12, r"(?i)\bffuf\b", Severity::Critical),
        scanner(13, r"(?i)\bwpscan\b", Severity::Critical),
        scanner(14, r"(?i)\bjoomscan\b", Severity::Critical),
        scanner(15, r"(?i)\bw3af\b", Severity::Critical),
        scanner(16, r"(?i)\barachni\b", Severity::Critical),
        scanner(17, r"(?i)\bskipfish\b", Severity::Critical),
        // ---- Site copiers and scrapers ----------------------------------------
        scanner(50, r"(?i)\bscrapy\b", Severity::Warning),
        scanner(51, r"(?i)\bwebharvest\b", Severity::Warning),
        scanner(52, r"(?i)\bhttrack\b", Severity::Warning),
        scanner(53, r"(?i)\bwebcopier\b", Severity::Warning),
        scanner(54, r"(?i)\boffline\s*explorer\b", Severity::Warning),
        scanner(55, r"(?i)\bteleport\s*pro\b", Severity::Warning),
        scanner(56, r"(?i)\bwebzip\b", Severity::Warning),
        // ---- SEO crawlers ------------------------------------------------------
        //
        // Not attacks — they obey robots.txt and identify honestly. Paranoia 2,
        // because whether they are unwanted is a bandwidth decision an operator
        // makes, not a security finding.
        spec_in_header(80, UA, r"(?i)\bsemrush(?:bot)?\b", Severity::Notice, 2),
        spec_in_header(81, UA, r"(?i)\bahrefsbot\b", Severity::Notice, 2),
        spec_in_header(82, UA, r"(?i)\bmj12bot\b", Severity::Notice, 2),
        spec_in_header(83, UA, r"(?i)\bdotbot\b", Severity::Notice, 2),
        spec_in_header(84, UA, r"(?i)\bseekport\b", Severity::Notice, 2),
        spec_in_header(85, UA, r"(?i)\bblexbot\b", Severity::Notice, 2),
        // ---- Generic HTTP client libraries ------------------------------------
        //
        // Paranoia 3. These are what a normal API integration sends, so at the
        // default level they would flag most legitimate non-browser traffic.
        spec_in_header(120, UA, r"^python-requests", Severity::Notice, 3),
        spec_in_header(121, UA, r"^python-urllib", Severity::Notice, 3),
        spec_in_header(122, UA, r"^Java/", Severity::Notice, 3),
        spec_in_header(123, UA, r"^libwww-perl", Severity::Notice, 3),
        spec_in_header(124, UA, r"^Go-http-client", Severity::Notice, 3),
        spec_in_header(125, UA, r"(?i)^curl/", Severity::Notice, 3),
        spec_in_header(126, UA, r"(?i)^wget/", Severity::Notice, 3),
        // A missing or empty User-Agent is not a fingerprint at all, so it cannot
        // be expressed here; the plugin is where that check belongs if it is wanted.
    ]
}
