//! WAF rule engine and detectors.
//!
//! Native Rust rule matching with CRS-category parity. No libmodsecurity, no
//! SecLang, and no C++ in the request path, so the musl static build survives.
//!
//! The engine ([`engine::RuleEngine`]) is a pure function over its input: it does
//! no I/O, holds no session reference, and does not know Pingora exists. That is
//! what lets it be fuzzed and unit-tested in isolation, and it is worth defending
//! — when a detector needs something it cannot see, widen
//! [`engine::RequestInput`] rather than passing a session in.
//!
//! Two evaluation surfaces, one scoring model, **asymmetric enforcement**:
//! request-side can deny, response-side can only log or rewrite bytes. That
//! asymmetry is in the types ([`engine::RequestVerdict`] versus
//! [`engine::ResponseVerdict`]), not just in the documentation.
//!
//! Detectors land in a later change. This module set is the contract they fill:
//! rule identity, categories, scoring, the mode gate, and the time budget.

pub mod budget;
pub mod categories;
pub mod config;
pub mod engine;
pub mod rule;

pub use budget::{Budget, Exhausted, ExhaustedPolicy};
pub use categories::Category;
pub use config::{
    ConfigError, CustomRule, RequestMode, ResponseMode, ValidatedConfig,
    ValidatedCustomRule, WafConfig,
};
pub use engine::{
    Evaluation, RequestInput, RequestVerdict, ResponseInput, ResponseVerdict,
    RuleEngine,
};
pub use rule::{
    CUSTOM_RULE_ID_BASE, Hit, MatchedField, Paranoia, RequestRule,
    ResponseRule, Rule, RuleId, Severity,
};
