//! The small cross-plugin hand-off used by challenge decisions.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A request-side policy decided that the next plugin should verify the client.
///
/// The marker lives in this pure crate so ACL and WAF can publish it without
/// depending on the challenge implementation. The challenge plugin consumes it
/// from `Ctx::extensions` later in the same ordered plugin list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeMarker {
    /// The policy surface that requested verification (`acl` or `waf`).
    pub source: String,
    /// Human-readable reason retained for logs and diagnostics.
    pub reason: String,
    /// Requested challenge strength; the challenge plugin may escalate it.
    pub level: u8,
}

impl ChallengeMarker {
    pub fn new(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            reason: reason.into(),
            level: 0,
        }
    }
}

/// Marker writes this process has counted, by classified domain label.
///
/// A plain static rather than a `OnceLock` handle: there is nothing to
/// initialise but the map itself, and no reader needs a strong pointer.
static WRITTEN: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// Count one marker write for one domain label.
///
/// Counted at the write site rather than at the read: a challenge entry that is
/// out of order, wrongly configured or absent never reads the marker, so the read
/// side cannot observe its own gap — a non-zero row here beside a zero
/// `challenge.issued` row under the same label is the gap made visible from
/// metrics. The label is the classified domain label the challenge plugin keys
/// its rows by, passed in by the caller because this pure crate does not
/// classify; the classification bounds the key set to the registered hosts plus
/// the one overflow label.
pub fn count_write(domain: &str) {
    let mut rows = WRITTEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *rows.entry(domain.to_string()).or_default() += 1;
}

/// The published per-domain marker-written counts, for the metrics surface.
pub fn counters_snapshot() -> BTreeMap<String, u64> {
    WRITTEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}
