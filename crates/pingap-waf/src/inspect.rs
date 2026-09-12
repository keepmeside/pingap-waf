//! Request-body accumulation for inspection, with byte-identical release.
//!
//! A WAF has to see the whole body before deciding, and it has to leave the body
//! intact for the upstream when the answer is "allow". Those two requirements are in
//! tension on a streaming proxy: bytes handed onward cannot be recalled.
//!
//! So chunks are **withheld** rather than copied. Each chunk is taken out of the
//! stream and appended here; nothing reaches the upstream until either the body ends
//! or the inspection limit is reached, at which point the accumulated bytes are put
//! back verbatim. A rejected request forwards nothing, and an allowed one forwards
//! exactly what the client sent — the same bytes, in order, with the same total
//! length, so `Content-Length` stays correct.
//!
//! Beyond the limit, buffering stops. Continuing would make the inspection buffer an
//! attacker-controlled memory amplifier; a WAF that can be made to hold a gigabyte
//! per connection is a denial-of-service tool aimed at its own host.
//!
//! This module is deliberately free of any proxy type, so the state machine is
//! testable without a running server.

/// What to do with a body that exceeds the inspection limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverCap {
    /// Inspect the prefix, forward the whole body, and record that the tail was not
    /// inspected. The default: a large upload is usually legitimate, and silently
    /// failing it is worse than inspecting less of it.
    #[default]
    InspectPrefix,
    /// Refuse the request. For operators who would rather drop an upload than accept
    /// one they could not fully inspect.
    Reject,
}

/// What the caller should do with the chunk it just fed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feed {
    /// Withhold the chunk. Nothing goes upstream yet.
    Hold,
    /// Inspect now, then release [`BodyBuffer::take`] upstream if allowed.
    Release,
    /// Already released; forward this chunk untouched and do not inspect it.
    PassThrough,
    /// Over the limit under [`OverCap::Reject`].
    Reject,
}

/// Accumulates request-body bytes up to a limit.
///
/// `Clone` only because `http::Extensions` requires it of anything parked on a
/// request context. Nothing clones one on the request path, and cloning one would
/// duplicate the buffer.
#[derive(Debug, Clone)]
pub struct BodyBuffer {
    limit: usize,
    policy: OverCap,
    buf: Vec<u8>,
    released: bool,
    truncated: bool,
}

impl BodyBuffer {
    pub fn new(limit: usize, policy: OverCap) -> Self {
        Self {
            limit,
            policy,
            buf: Vec::new(),
            released: false,
            truncated: false,
        }
    }

    /// Feed one chunk. `chunk` is `None` for an empty trailing call, which pingora
    /// makes to signal end of stream.
    pub fn feed(&mut self, chunk: Option<&[u8]>, end_of_stream: bool) -> Feed {
        if self.released {
            return Feed::PassThrough;
        }
        if let Some(bytes) = chunk {
            // No pre-emptive capacity reservation: `with_capacity(limit)` would let
            // any request that sends one byte allocate the whole limit.
            self.buf.extend_from_slice(bytes);
        }
        if self.buf.len() > self.limit {
            if self.policy == OverCap::Reject {
                return Feed::Reject;
            }
            // The tail past the limit is forwarded but never inspected, and that
            // fact travels with the verdict rather than being dropped silently.
            self.truncated = true;
            self.released = true;
            return Feed::Release;
        }
        if end_of_stream {
            self.released = true;
            return Feed::Release;
        }
        Feed::Hold
    }

    /// The prefix that was inspected. Never longer than the limit, even when more
    /// bytes are held for release.
    pub fn inspected(&self) -> &[u8] {
        let end = self.buf.len().min(self.limit);
        &self.buf[..end]
    }

    /// Whether bytes were forwarded without being inspected.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Take the accumulated bytes for release upstream. Exactly what was fed in, in
    /// order — this is what keeps an allowed body byte-identical.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

/// Overwrite a span with `*`, in place and at the same length.
///
/// Equal length is the whole point. A shorter replacement would leave
/// `Content-Length` describing a body that no longer exists, which on HTTP/1.1 means
/// the client either hangs waiting for bytes that will not arrive or reads the next
/// response as this one's tail. Rewriting the header instead would mean switching the
/// response to chunked encoding from a body hook, after the headers are already
/// downstream — which is not possible.
///
/// So redaction masks. The leak stops being readable, the framing stays valid, and
/// the fact that something was removed is visible to whoever reads the response.
pub fn mask(body: &mut [u8], from: usize, len: usize) -> bool {
    let end = from.saturating_add(len).min(body.len());
    if from >= end {
        return false;
    }
    for b in &mut body[from..end] {
        *b = b'*';
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_within_the_limit_is_held_then_released_whole() {
        let mut b = BodyBuffer::new(64, OverCap::InspectPrefix);
        assert_eq!(b.feed(Some(b"hello "), false), Feed::Hold);
        assert_eq!(b.feed(Some(b"world"), true), Feed::Release);
        assert_eq!(b.inspected(), b"hello world");
        assert!(!b.truncated());
        // Byte-identical: the concatenation of what was fed in, in order.
        assert_eq!(b.take(), b"hello world".to_vec());
    }

    #[test]
    fn nothing_is_forwarded_before_the_decision() {
        // The property the whole design exists for. A chunk that is `Hold` must not
        // have been released, or a malicious body's first chunk reaches the upstream
        // before the WAF has seen the rest of it.
        let mut b = BodyBuffer::new(1024, OverCap::InspectPrefix);
        for _ in 0..8 {
            assert_eq!(b.feed(Some(&[b'x'; 16]), false), Feed::Hold);
        }
        assert_eq!(b.inspected().len(), 128);
    }

    #[test]
    fn an_empty_trailing_chunk_still_ends_the_stream() {
        // pingora signals end of stream with a `None` body, so a buffer that only
        // releases on `Some` would hold a complete body forever.
        let mut b = BodyBuffer::new(64, OverCap::InspectPrefix);
        assert_eq!(b.feed(Some(b"payload"), false), Feed::Hold);
        assert_eq!(b.feed(None, true), Feed::Release);
        assert_eq!(b.take(), b"payload".to_vec());
    }

    #[test]
    fn a_body_with_no_content_at_all_releases_immediately() {
        let mut b = BodyBuffer::new(64, OverCap::InspectPrefix);
        assert_eq!(b.feed(None, true), Feed::Release);
        assert!(b.inspected().is_empty());
        assert!(b.take().is_empty());
    }

    #[test]
    fn over_cap_inspects_the_prefix_and_forwards_everything() {
        let mut b = BodyBuffer::new(8, OverCap::InspectPrefix);
        assert_eq!(b.feed(Some(b"0123456789"), false), Feed::Release);
        assert_eq!(b.inspected(), b"01234567", "inspection stops at the limit");
        assert!(b.truncated(), "an uninspected tail must be recorded");
        // Still byte-identical, including the part that was not inspected. Dropping
        // the tail would corrupt the upload instead of under-inspecting it.
        assert_eq!(b.take(), b"0123456789".to_vec());
        // Subsequent chunks stream through untouched rather than being re-buffered.
        assert_eq!(b.feed(Some(b"more"), false), Feed::PassThrough);
        assert_eq!(b.feed(None, true), Feed::PassThrough);
    }

    #[test]
    fn exactly_at_the_limit_is_not_over_cap() {
        let mut b = BodyBuffer::new(8, OverCap::Reject);
        assert_eq!(b.feed(Some(b"01234567"), true), Feed::Release);
        assert!(!b.truncated());
    }

    #[test]
    fn the_reject_policy_refuses_an_oversized_body() {
        let mut b = BodyBuffer::new(4, OverCap::Reject);
        assert_eq!(b.feed(Some(b"toolong"), false), Feed::Reject);
        // Nothing was released, so nothing reached the upstream.
        assert!(!b.buf.is_empty(), "the prefix is still held, not forwarded");
    }

    #[test]
    fn inspect_prefix_is_the_default_policy() {
        // A large upload is usually legitimate. Failing it silently is worse than
        // inspecting less of it, so the default trades coverage for availability —
        // and says so.
        assert_eq!(OverCap::default(), OverCap::InspectPrefix);
    }

    #[test]
    fn masking_preserves_length() {
        let mut body = b"secret=hunter2&ok=1".to_vec();
        let before = body.len();
        assert!(mask(&mut body, 7, 7));
        assert_eq!(body, b"secret=*******&ok=1".to_vec());
        assert_eq!(body.len(), before, "Content-Length must stay correct");
    }

    #[test]
    fn masking_is_clamped_and_never_panics() {
        let mut body = b"abc".to_vec();
        // Past the end, at the end, and zero-length: all no-ops rather than panics.
        // A response-side hit reports an offset into the inspected prefix, and a
        // caller that mismatched buffers must not take the gateway down.
        assert!(!mask(&mut body, 3, 5));
        assert!(!mask(&mut body, 9, 1));
        assert!(!mask(&mut body, 0, 0));
        assert_eq!(body, b"abc".to_vec());
        // Overlong length is clamped to the buffer rather than refused.
        assert!(mask(&mut body, 1, 99));
        assert_eq!(body, b"a**".to_vec());
    }
}
