//! ACL rules and named access lists.
//!
//! One rule table, evaluated in written order, instead of a fifth restriction plugin
//! sitting beside pingap's existing four. The matcher primitives come from
//! `pingap-plugin` and `pingap-util` rather than being reimplemented here — a second
//! CIDR matcher or a second referer parser would let this crate and
//! `ip_restriction`/`referer_restriction` disagree about which requests a rule covers,
//! which is the failure this crate exists to avoid.
//!
//! Two surfaces, mirroring `pingap-waf`'s split:
//!
//! - [`evaluate`] and [`rule`] are pure Rust with no knowledge that Pingora exists, so
//!   they are unit-testable and fuzzable without a proxy.
//! - [`plugin`] binds them into pingap and lives behind the `plugin` feature.

pub mod access_list;
pub mod evaluate;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod rule;

pub use access_list::{AccessList, AccessListConf, AccessListError, Satisfy};
pub use evaluate::{DefaultAction, Outcome, RequestFacts, RuleSet};
pub use rule::{AclRule, Action, Field, Operator, RuleError, ValidatedRule};
