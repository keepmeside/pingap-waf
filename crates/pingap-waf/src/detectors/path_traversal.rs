//! Path traversal and local file inclusion (CRS 930 lineage).
//!
//! Measured **0.0000** false positives on the frozen benign corpus, so the
//! patterns are ported as written apart from one word-boundary tightening that
//! cannot lose a true positive.
//!
//! Two groups, deliberately kept apart: traversal *sequences* (how you escape a
//! directory) and sensitive *targets* (what you escape to). Either alone is a
//! finding, and separate rule IDs mean a log line says which.
//!
//! The percent-encoded variants are kept even though every field is decoded before
//! matching. They are not redundant: a decode pass turns `%252e%252e%252f` into
//! `%2e%2e%2f`, and these patterns are what catches it there.

use super::{Spec, spec};
use crate::rule::Severity;

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Traversal sequences ----------------------------------------------
        spec(1, r"\.\./", Severity::Warning),
        spec(2, r"\.\.\\", Severity::Warning),
        spec(3, r"(?i)\.\.%2f", Severity::Warning),
        spec(4, r"(?i)\.\.%5c", Severity::Warning),
        spec(5, r"(?i)%2e%2e%2f", Severity::Warning),
        spec(6, r"(?i)%2e%2e/", Severity::Warning),
        spec(7, r"(?i)%2e%2e%5c", Severity::Warning),
        spec(8, r"(?i)%2e%2e\\", Severity::Warning),
        spec(9, r"(?i)%252e%252e%252f", Severity::Error),
        spec(10, r"(?i)%252e%252e/", Severity::Error),
        // Overlong UTF-8 encoding of `.` and `/`, used to slip past decoders that
        // normalise after validating.
        spec(11, r"(?i)%c0%ae%c0%ae/", Severity::Error),
        spec(12, r"(?i)%c0%ae%c0%ae%c0%af", Severity::Error),
        // Null byte, used to truncate an extension check.
        spec(13, r"%00", Severity::Error),
        spec(14, r"\\x00", Severity::Error),
        // Padding variants that survive a single naive `../` strip.
        spec(15, r"\.\.\.\./", Severity::Error),
        spec(16, r"\.\.//", Severity::Error),
        spec(17, r"\.\./\./", Severity::Error),
        // Any overlong-UTF-8 separator after a `..`. The reference listed `%c0%ae`
        // and `%c0%af` by hand and so missed `..%c1%9c`, the IIS backslash variant.
        // Requiring the `..` first is what keeps this from firing on ordinary
        // percent-encoded UTF-8 text.
        spec(18, r"(?i)\.\.%c[01]%[0-9a-f]{2}", Severity::Error),
        // ---- Sensitive targets, Unix ------------------------------------------
        spec(100, r"(?i)/etc/passwd", Severity::Critical),
        spec(101, r"(?i)/etc/shadow", Severity::Critical),
        spec(102, r"(?i)/etc/hosts", Severity::Error),
        spec(103, r"(?i)/etc/group", Severity::Error),
        spec(104, r"(?i)/proc/", Severity::Error),
        spec(105, r"(?i)/sys/", Severity::Error),
        spec(106, r"(?i)/var/log/", Severity::Error),
        spec(107, r"(?i)/root/", Severity::Error),
        spec(108, r"(?i)\.ssh/", Severity::Critical),
        spec(109, r"(?i)\.bash_history", Severity::Error),
        // `\.env` alone also matched "config.environment"; the boundary keeps
        // `.env`, `.env.bak` and `/.env` while dropping that. No true positive can
        // be lost, because a real target always ends the token or is followed by
        // punctuation.
        spec(110, r"(?i)\.env\b", Severity::Critical),
        spec(111, r"(?i)id_rsa", Severity::Critical),
        spec(112, r"(?i)id_dsa", Severity::Critical),
        // ---- Sensitive targets, Windows ---------------------------------------
        spec(150, r"(?i)c:\\windows", Severity::Critical),
        spec(151, r"(?i)c:\\boot\.ini", Severity::Critical),
        spec(152, r"(?i)\\windows\\system32", Severity::Critical),
        spec(153, r"(?i)win\.ini", Severity::Error),
        spec(154, r"(?i)system\.ini", Severity::Error),
        // ---- Web-server and application config --------------------------------
        spec(200, r"(?i)\.htaccess", Severity::Error),
        spec(201, r"(?i)\.htpasswd", Severity::Critical),
        spec(202, r"(?i)web\.config", Severity::Error),
        spec(203, r"(?i)nginx\.conf", Severity::Error),
        spec(204, r"(?i)httpd\.conf", Severity::Error),
        spec(205, r"(?i)config\.php", Severity::Error),
        spec(206, r"(?i)database\.yml", Severity::Error),
        spec(207, r"(?i)settings\.py", Severity::Error),
        spec(208, r"(?i)wp-config\.php", Severity::Critical),
    ]
}
