//! Turning a feed body into a validated entry list, with the counts that make a bad feed
//! visible.
//!
//! Ported from mango-waf `intelligence/feeds.go` at commit 7f2c30c (MIT); see ./NOTICE.
//! Rewritten for a parser that has to report what it could not read, because this one runs
//! behind an `IpRules` that discards what it cannot parse without saying so.
//!
//! # What the port contributed
//!
//! The line-level reading is sound and is kept: strip a trailing `#` or `;` comment, split
//! on whitespace, take the first field, validate it as an address or a network, and skip the
//! line if it is neither. Blank lines and lines *starting* with a comment marker are skipped
//! before any of that.
//!
//! # One documented fidelity loss
//!
//! For a multi-column range format — `start<TAB>end<TAB>count`, as DShield publishes — the
//! first field is the *start* address only, so a range covering 256 addresses contributes
//! one entry. Under-blocking part of a range from one feed is a documented limitation rather
//! than a silent one, and `tests/parse.rs` asserts the exact single entry so the behaviour
//! cannot widen or narrow unnoticed.
//!
//! # Why the counts exist
//!
//! A malformed line in a threat feed is a narrowing of coverage, and nothing downstream can
//! tell "this feed returned nothing" from "this feed returned 40,000 lines we could not
//! read" unless the parser counts them. Four counters, four different operator responses:
//!
//! - `dropped` — the line looked like a feed line and was not understood. A feed that
//!   changes format shows up here first.
//! - `skipped` — comments and blanks. Not a fault, and folding them into `dropped` would
//!   make every well-commented feed look broken.
//! - `duplicates` — collapsed. Feeds repeat themselves constantly, and counting a repeat as
//!   a drop would make the largest feeds look the most broken. Collapsing them narrows
//!   nothing, so it is not a drop.
//! - `truncated` — the entry cap was reached. Reported rather than applied to an arbitrary
//!   end: a cap over a hash set's iteration order would make which addresses are enforced
//!   depend on a hasher's seed.
//!
//! # The length check
//!
//! `pingap_util::IpRules::new` discards an entry it cannot parse and reports nothing — its
//! own doc comment claims a warning is logged, and the branch that would log it is empty.
//! That makes the comparison in [`Parsed::parse`] between the number of entries handed over
//! and the number the matcher actually stored the only thing standing between a feed and a
//! silent narrowing of coverage. It is performed here, inside the parser, so no caller has
//! to remember it. Any residual shortfall folds into `dropped`.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use pingap_util::IpRules;

/// What one trimmed feed line turned out to be.
enum Line<'a> {
    /// A comment or a blank. Counted as skipped.
    Skipped,
    /// Something that was meant to be an entry and was not understood. Counted as dropped.
    Malformed,
    /// A validated entry.
    Candidate(&'a str),
}

/// A parsed feed body.
///
/// Owns both the entry list and the matcher compiled from it, so the two cannot drift and no
/// caller can compile one without the other.
#[derive(Debug)]
pub struct Parsed {
    entries: Vec<String>,
    rules: IpRules,
    dropped: usize,
    skipped: usize,
    duplicates: usize,
    truncated: bool,
}

impl Parsed {
    /// Parses `body`, accepting at most `max_entries`.
    ///
    /// The cap is applied in feed order, after deduplication, and lines past it do not
    /// consume the dropped or skipped counts — the whole body is still read, so the counts
    /// describe the feed rather than the part of it that happened to fit.
    ///
    /// `max_entries` of zero accepts nothing and reports truncation. Config validation
    /// refuses it; the behaviour is coherent rather than surprising if it ever arrives.
    pub fn parse(body: &str, max_entries: usize) -> Self {
        let mut entries: Vec<String> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut dropped = 0;
        let mut skipped = 0;
        let mut duplicates = 0;
        let mut truncated = false;

        for line in body.lines() {
            match split_line(line) {
                Line::Skipped => skipped += 1,
                Line::Malformed => dropped += 1,
                Line::Candidate(candidate) => {
                    if !seen.insert(candidate) {
                        duplicates += 1;
                        continue;
                    }
                    if entries.len() >= max_entries {
                        truncated = true;
                        continue;
                    }
                    entries.push(candidate.to_string());
                },
            }
        }

        let rules = IpRules::new(&entries);
        // The length check. `entries` is deduplicated by text and every one of its members
        // parsed as an address or a network, so a shortfall here means this parser and
        // `IpRules` disagree about what a valid entry is — which is exactly the silent
        // narrowing the check exists to catch. Reported as drops, because that is what it
        // is from an operator's point of view.
        dropped += entries.len().saturating_sub(rules.len());

        Self {
            entries,
            rules,
            dropped,
            skipped,
            duplicates,
            truncated,
        }
    }

    /// The accepted entries, in feed order and deduplicated.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// The matcher compiled from [`Self::entries`].
    pub fn rules(&self) -> &IpRules {
        &self.rules
    }

    /// How many entries were accepted.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing was accepted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many lines looked like entries and were not understood.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// How many lines were comments or blank.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// How many accepted entries were repeats of an earlier one.
    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// Whether the entry cap was reached.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Trims a line and decides what it is.
fn split_line(line: &str) -> Line<'_> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return Line::Skipped;
    }
    match candidate(line) {
        Some(candidate) => Line::Candidate(candidate),
        None => Line::Malformed,
    }
}

/// The entry in one non-comment line, if the line has one.
fn candidate(line: &str) -> Option<&str> {
    let line = before_comment(before_comment(line, '#'), ';');
    let candidate = line.split_whitespace().next()?;
    parses_as_an_address(candidate).then_some(candidate)
}

/// Cuts a line at an inline comment marker.
fn before_comment(line: &str, marker: char) -> &str {
    match line.find(marker) {
        // `> 0` rather than `>= 0`, and deliberately: a line that *starts* with the marker
        // was already skipped by the caller, and cutting at index zero would turn it into an
        // empty candidate and report a comment as a malformed line.
        Some(index) if index > 0 => &line[..index],
        _ => line,
    }
}

/// Whether `candidate` is an address or a network.
///
/// Mirrors `IpRules::new` exactly — network first, then bare address — so that this parser
/// and the matcher it feeds cannot disagree, and the length check stays a check rather than
/// a routine source of false drops.
///
/// Crate-visible because `config.rs` validates the operator's manual entries with it: an
/// entry that would be discarded by the matcher has to be refused at config load, where the
/// operator can be told, rather than silently never matching.
pub(crate) fn parses_as_an_address(candidate: &str) -> bool {
    IpNet::from_str(candidate).is_ok() || IpAddr::from_str(candidate).is_ok()
}
