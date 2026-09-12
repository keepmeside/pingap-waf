//! Bot management: client fingerprinting and fingerprint-driven policy.
//!
//! JA4H only. It is computed entirely from the HTTP request head — no TLS access, so it
//! works on plain HTTP — and it is what the reference product's shipped deny library
//! actually keys on: every blocking entry there is a JA4H, not a JA4. Full JA4 is gated
//! on the Phase 02 ClientHello spike and arrives, if at all, as another fingerprint type
//! behind the same rule model.
//!
//! Two surfaces, mirroring `pingap-waf` and `pingap-acl`:
//!
//! - [`ja4h`], [`rule`], [`library`] and [`analytics`] are pure Rust with no knowledge
//!   that Pingora exists, so the fingerprint can be checked against published vectors.
//! - [`plugin`] binds them into pingap and lives behind the `plugin` feature. It also
//!   owns the one decision that cannot be made in a pure function: whether header order
//!   is trustworthy for this request at all.
//!
//! **A fingerprint is a client-behaviour signal, not an identity.** JA4H reflects how an
//! HTTP client is written, which a determined attacker can imitate far more easily than a
//! TLS stack. Nothing security-critical should rest on it alone, and it must never be
//! presented as JA4.

pub mod analytics;
pub mod ja4h;
pub mod library;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod rule;

pub use analytics::{Analytics, Verdict};
pub use ja4h::{RequestHead, Version, ja4h};
pub use library::{KnownClient, library};
pub use rule::{
    BotAction, BotProfile, BotRule, FingerprintType, PolicyMode, RuleError,
};
