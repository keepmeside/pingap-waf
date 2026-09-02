//! Which headers a detector inspects — one policy, one definition.
//!
//! The inherited implementation shipped **four** private "safe header" skip-lists
//! (`sql_injection.rs:36`, `xss_detector.rs:31`, `command_injection.rs:63`,
//! `path_traversal.rs:75` in the reference tree). Each excluded `user-agent`,
//! `content-type` and `host`, among others. The measured consequence:
//!
//! ```text
//! payload "Mozilla/5.0 (X11) ' UNION SELECT password FROM users --"
//!   as a query value      -> hit
//!   as a User-Agent       -> miss
//! ```
//!
//! Same bytes, opposite verdict, decided only by the field that carried them. That
//! is a bypass, not a tuning choice: User-Agent is a standard injection vector.
//!
//! **So the default here is to inspect every header.** Excluding a header is the
//! decision that created the bypass, so it is available but never implicit: the
//! skip list starts empty and an operator has to write one.
//!
//! The cost of inspecting more headers is real, and it is paid in pattern quality
//! rather than in skip-lists — a pattern that fires on `Content-Type: text/html;
//! charset=utf-8` is a broken pattern, and hiding it behind a skipped header
//! leaves it firing on every other field.

/// Header names never inspected, lowercased.
///
/// Empty by design. It exists as a named, documented constant rather than as
/// nothing at all so that the next person who wants to exclude a header finds this
/// comment first.
pub const NEVER_INSPECTED: &[&str] = &[];

/// Whether a header participates in detection.
///
/// Case-insensitive on the name, because HTTP/1.1 header names are
/// case-insensitive and the inherited code lowercased at every call site.
pub fn inspect_header(name: &str) -> bool {
    !NEVER_INSPECTED
        .iter()
        .any(|skip| skip.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_headers_that_carried_the_bypass_are_inspected() {
        // Each of these was in at least one of the four inherited skip-lists.
        for name in [
            "user-agent",
            "User-Agent",
            "content-type",
            "host",
            "referer",
            "origin",
            "cookie",
            "accept",
            "accept-encoding",
            "accept-language",
            "cache-control",
            "connection",
        ] {
            assert!(
                inspect_header(name),
                "`{name}` must be inspected — excluding it is how the bypass \
                 happened"
            );
        }
    }

    #[test]
    fn nothing_is_excluded_by_default() {
        assert!(
            NEVER_INSPECTED.is_empty(),
            "an exclusion added here silently blinds every detector to that \
             header; it needs its own justification in this test"
        );
    }
}
