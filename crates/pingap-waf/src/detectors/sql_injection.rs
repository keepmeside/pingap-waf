//! SQL injection (CRS 942 lineage).
//!
//! Ported from the reference detector, which measured a **0.2375** false-positive
//! rate — the worst of the four. A handful of its patterns caused most of that,
//! and they shared one root cause: they matched a SQL *token* without requiring a
//! SQL *context*. `--` is a comment in SQL and a flag separator in every shell;
//! `select … from` is a query and also ordinary English.
//!
//! The fix is context, not deletion. Where a pattern still carries real signal but
//! cannot be made precise, it moves to paranoia 2 instead of being dropped, so it
//! participates only where an operator asked for more aggression.

use super::{Spec, spec, spec_at};
use crate::rule::Severity;

/// Identifier-ish characters, for column and table names. Includes the quoting
/// styles the major dialects use: `"pg"`, `` `mysql` ``, `[mssql]`.
const IDENT: &str = r#"[\w.'"`\[\]]+"#;

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Union-based injection --------------------------------------------
        //
        // Was `\bunion\b.*\bselect\b`, which fired on "The union representative and
        // select committee met". Only whitespace, parens and an optional `ALL` may
        // separate the two words now — which is all SQL allows anyway, so this is
        // more faithful to the language as well as quieter.
        spec(
            1,
            r"(?i)\bunion\b[\s(]+(?:all[\s(]+)?\bselect\b",
            Severity::Critical,
        ),
        // ---- Boolean injection ------------------------------------------------
        //
        // Hex operands are allowed because `' OR 0x31=0x31 --` is the same attack
        // written to dodge a decimal-only pattern, and `having` because
        // `HAVING 1=1` is the same tautology in a different clause.
        spec(
            10,
            r"(?i)\b(?:or|and|having)\b\s+(?:0x[0-9a-f]+|\d+)\s*=\s*(?:0x[0-9a-f]+|\d+)",
            Severity::Critical,
        ),
        spec(11, r"(?i)'\s*(?:or|and)\s*'", Severity::Critical),
        // `or x = y` with quoted or bare operands. Real signal, but it also appears
        // in prose and in filter-expression query parameters, so it waits for
        // paranoia 2.
        spec_at(
            12,
            r#"(?i)\bor\b\s+["']?\w+["']?\s*=\s*["']?\w+["']?"#,
            Severity::Warning,
            2,
        ),
        // String-concatenation injection, the Oracle and PostgreSQL idiom:
        // `'||(SELECT version())||'`. A quote next to `||` is not something a
        // pipe-delimited value ever contains, which is what separates this from the
        // `\|\s*\w` pattern that produced 3.6% false positives.
        spec(13, r"(?i)['\x22]\s*\|\|", Severity::Critical),
        spec(14, r"(?i)\|\|\s*\(?\s*select\b", Severity::Critical),
        // A quote followed by a clause keyword: `1' ORDER BY 9 --`, the standard
        // column-count probe, and its GROUP BY / HAVING variants.
        spec(
            15,
            r"(?i)['\x22]\s*(?:order\s+by|group\s+by|having)\b",
            Severity::Critical,
        ),
        // A subquery hung off a boolean operator: `1 AND (SELECT COUNT(*) …)`.
        spec(
            16,
            r"(?i)\b(?:and|or)\b\s*\(\s*select\b",
            Severity::Critical,
        ),
        // ---- Statement comments -----------------------------------------------
        //
        // `--[^\r\n]*$` was the single largest false-positive source at 11.6%: em-dash
        // prose ("inconclusive -- see appendix B") and every CLI flag string ("npm
        // run build -- --mode=production"). A SQL comment used as an injection
        // terminates something first, so it must now follow a quote, a closing
        // bracket, or a statement separator.
        spec(20, r#"['");\]]\s*--"#, Severity::Critical),
        // Inline comment, used both to comment out the rest of a statement and to
        // split keywords past naive filters (`UN/**/ION`).
        spec(21, r"/\*[^*]{0,200}\*/", Severity::Warning),
        // ---- Data manipulation -------------------------------------------------
        //
        // Each of these was `\bverb\b.*\bnoun\b` and fired on ordinary English.
        // They now require the shape the statement actually has.
        //
        // `select * from` and `select a, b from`: a column list is what separates a
        // query from "Please select from the following options".
        spec(30, r"(?i)\bselect\b\s+\*\s*\bfrom\b", Severity::Critical),
        spec(
            31,
            &format!(
                r"(?i)\bselect\b\s+{IDENT}\s*,\s*[\w.'\x22`\[\], ]{{0,120}}\bfrom\b"
            ),
            Severity::Critical,
        ),
        // A single-column select is weak on its own — "select one from the list" has
        // the same shape — so it needs a clause keyword, a delimiter, or the end of
        // the value after the table name. `SELECT name FROM users LIMIT 1` has one;
        // English prose continues with more prose.
        spec(
            32,
            &format!(
                r"(?i)\bselect\b\s+{IDENT}\s+\bfrom\b\s+{IDENT}\s*(?:\bwhere\b|\blimit\b|\border\s+by\b|\bgroup\s+by\b|\bhaving\b|\bunion\b|[),;]|--|$)"
            ),
            Severity::Critical,
        ),
        // An aggregate call straight after SELECT: `SELECT COUNT(*) FROM users`.
        // No sentence in English puts a function call there.
        spec(
            33,
            r"(?i)\bselect\b\s+(?:count|sum|avg|min|max|group_concat|string_agg)\s*\(",
            Severity::Critical,
        ),
        // `insert into <table>` followed by what a statement actually continues
        // with. "Insert into the slot at the top" continues with prose instead.
        spec(
            40,
            &format!(
                r"(?i)\binsert\b\s+into\b\s+{IDENT}\s*(?:[({{]|\bvalues\b|\bselect\b|\binto\b|\bset\b|;|--|$)"
            ),
            Severity::Critical,
        ),
        // `delete from <table>` must be followed by a WHERE, a statement end, or a
        // comment. "Delete from your cart before checkout" continues with prose.
        spec(
            50,
            &format!(
                r"(?i)\bdelete\b\s+from\b\s+{IDENT}\s*(?:\bwhere\b|;|--|$)"
            ),
            Severity::Critical,
        ),
        // `drop table x` — "Drop the table linens off" has a word between the two,
        // which SQL does not allow.
        spec(
            60,
            &format!(r"(?i)\bdrop\b\s+(?:table|database)\b\s+{IDENT}"),
            Severity::Critical,
        ),
        // `update x set y =` — the assignment is the part prose does not have.
        spec(
            70,
            &format!(r"(?i)\bupdate\b\s+{IDENT}\s+\bset\b\s+{IDENT}\s*="),
            Severity::Critical,
        ),
        // ---- Stacked statements and execution ---------------------------------
        spec(
            80,
            r"(?i);\s*\b(?:drop|delete|update|insert|truncate|alter)\b",
            Severity::Critical,
        ),
        spec(81, r"(?i)\b(?:exec|execute)\s*\(", Severity::Critical),
        spec(82, r"(?i)\b(?:xp_|sp_)\w+", Severity::Error),
        // ---- Time-based blind injection ---------------------------------------
        spec(
            90,
            r"(?i)\b(?:benchmark|pg_sleep|waitfor\s+delay)\s*\(",
            Severity::Critical,
        ),
        spec(91, r"(?i)\bsleep\s*\(\s*\d", Severity::Error),
        // ---- Hex literal bypass ------------------------------------------------
        //
        // `0x[0-9a-f]{2,}` fired on 5.4% of benign traffic: CSS colours, git SHAs,
        // ETags. A SQL hex literal appears as a *value*, so it must now follow an
        // assignment, a paren or a comma — and even then it waits for paranoia 2,
        // because `?token=0xabc…` is a shape a legitimate API might use.
        spec_at(95, r"(?i)[=(,]\s*0x[0-9a-f]{4,}", Severity::Notice, 2),
        // The unnarrowed original, at paranoia 3. A bare hex literal genuinely
        // cannot be told apart from a git SHA, an ETag or a colour token, so the
        // choice is between missing `?id=0x414243` and firing on 5.4% of benign
        // traffic. Paranoia is where that choice belongs — the operator makes it,
        // visibly, instead of the pattern making it for them.
        spec_at(96, r"(?i)\b0x[0-9a-f]{2,}\b", Severity::Notice, 3),
    ]
}
