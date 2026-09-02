//! Cross-site scripting (CRS 941 lineage).
//!
//! The one inherited detector that measured **0.0000** false positives on the
//! frozen benign corpus, so it is ported as written. Precision that was measured
//! rather than argued is not something to improve on speculatively.
//!
//! Together with path traversal, this is one of the two categories whose measured
//! rate makes blocking mode defensible out of the box. SQL injection (0.2375) and
//! command injection (0.1161) are not there yet.

use super::{Spec, spec};
use crate::rule::Severity;

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Script tags -------------------------------------------------------
        spec(1, r"(?i)<script[^>]{0,200}>", Severity::Critical),
        spec(2, r"(?i)</script>", Severity::Critical),
        // ---- Inline event handlers ---------------------------------------------
        //
        // `\bon\w+\s*=` needs the word boundary: without it `?json=…` and
        // `?zone=…` would both match. With it they do not, because the preceding
        // character is a word character.
        spec(10, r"(?i)\bon\w+\s*=", Severity::Error),
        // ---- Dangerous tags ----------------------------------------------------
        spec(20, r"(?i)<iframe[^>]{0,200}>", Severity::Error),
        spec(21, r"(?i)<object[^>]{0,200}>", Severity::Error),
        spec(22, r"(?i)<embed[^>]{0,200}>", Severity::Error),
        spec(23, r"(?i)<img[^>]{0,200}\bon\w+", Severity::Critical),
        spec(24, r"(?i)<body[^>]{0,200}\bon\w+", Severity::Critical),
        // `<link rel=import>` fetched and executed a remote document. The feature is
        // gone from current browsers, but the payload still appears in scanner
        // corpora and a user-supplied value has no reason to contain it.
        spec(
            25,
            r"(?i)<link[^>]{0,200}\brel\s*=\s*['\x22]?import",
            Severity::Error,
        ),
        // ---- Script-bearing URLs ----------------------------------------------
        //
        // The quote in the character class matters: `<base href='javascript:'>` puts
        // nothing but the closing quote after the scheme, so a `\w` requirement
        // misses it.
        spec(30, r"(?i)javascript:\s*[\w'\x22]", Severity::Critical),
        spec(31, r"(?i)data:text/html", Severity::Error),
        // ---- Script execution --------------------------------------------------
        spec(40, r"(?i)\beval\s*\(", Severity::Error),
        spec(41, r"(?i)\balert\s*\(", Severity::Warning),
        spec(42, r"(?i)expression\s*\(", Severity::Error),
    ]
}
