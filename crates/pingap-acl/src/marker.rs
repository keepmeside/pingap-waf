//! The small cross-plugin hand-off used by challenge decisions.

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
