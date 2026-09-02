//! Data leakage in responses (CRS 950 lineage).
//!
//! Written new. The reference WAF has no response-side detection at all, so nothing
//! here is a port — these patterns are chosen against the response surface the
//! engine exposes.
//!
//! **This category can only detect or redact, never block.** By the time a response
//! body hook runs, the status line and headers are already downstream, so the
//! strongest available action is rewriting bytes. A finding here means "this
//! response disclosed something", not "this response was prevented".
//!
//! The bar for inclusion is that the pattern describes something that should never
//! legitimately appear in a response body a client can read. A stack trace, a
//! database error naming internal objects, a private key, a cloud credential. Not
//! anything merely sensitive-sounding: an email address in a response is usually the
//! product working, and a pattern that fires on those is a redactor that corrupts
//! ordinary pages.

use super::{Spec, spec, spec_at};
use crate::rule::Severity;

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Database error disclosure -----------------------------------------
        //
        // The classic SQL-injection oracle: the error text names tables, columns and
        // drivers, which is what turns a blind injection into an easy one.
        spec(
            1,
            r"(?i)\bmysql_(?:connect|error|query|fetch_\w+|num_rows)\s*\(",
            Severity::Error,
        ),
        spec(
            2,
            r"(?i)You have an error in your SQL syntax",
            Severity::Critical,
        ),
        spec(3, r"(?i)\bwarning\b.{0,40}\bmysqli?\b", Severity::Error),
        spec(4, r"ORA-\d{5}", Severity::Error),
        spec(5, r"(?i)\bPostgreSQL\b.{0,40}\bERROR\b", Severity::Error),
        spec(6, r"SQLSTATE\[", Severity::Error),
        spec(
            7,
            r"(?i)\b(?:Unclosed quotation mark|Incorrect syntax near)\b",
            Severity::Error,
        ),
        spec(
            8,
            r"(?i)SQLite3?::(?:query|exec|prepare)|sqlite3\.OperationalError",
            Severity::Error,
        ),
        // ---- Stack traces and debug output ------------------------------------
        spec(30, r"Traceback \(most recent call last\)", Severity::Error),
        spec(31, r"\bat [\w.$]+\([\w]+\.java:\d+\)", Severity::Error),
        spec(
            32,
            r"(?i)<b>(?:Fatal error|Warning|Notice)</b>:.{0,80}\bon line\b",
            Severity::Error,
        ),
        spec(33, r"(?i)\bStack trace:\s", Severity::Error),
        spec(
            34,
            r"(?i)\b(?:System\.\w+Exception|Microsoft\.\w+\.SqlException)\b",
            Severity::Error,
        ),
        // ---- Credentials and key material -------------------------------------
        //
        // A private key in a response body is never the product working.
        spec(
            60,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            Severity::Critical,
        ),
        spec(61, r"\bAKIA[0-9A-Z]{16}\b", Severity::Critical),
        spec(
            62,
            r"(?i)\baws_secret_access_key\b\s*[=:]",
            Severity::Critical,
        ),
        spec(63, r"\bgh[pousr]_[A-Za-z0-9]{36,}", Severity::Critical),
        spec(64, r"\bxox[baprs]-[A-Za-z0-9-]{10,}", Severity::Critical),
        spec(
            65,
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[=:]\s*['\x22][A-Za-z0-9_\-]{16,}",
            Severity::Error,
        ),
        // ---- Server internals --------------------------------------------------
        spec(90, r"(?i)<title>Index of /", Severity::Warning),
        spec(91, r"(?i)<title>phpinfo\(\)", Severity::Critical),
        spec(92, r"(?i)\bphpinfo\s*\(\s*\)", Severity::Error),
        // A DSN with an inline password. Paranoia 2 because the shape also appears
        // in documentation pages, which are a legitimate thing to serve.
        spec_at(
            93,
            r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb|redis|amqp)://[^\s:@/]+:[^\s:@/]+@",
            Severity::Critical,
            2,
        ),
    ]
}
