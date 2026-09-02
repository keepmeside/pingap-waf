//! Command injection (CRS 932 lineage).
//!
//! Measured **0.1161** false positives, and two of its patterns accounted for 65 of
//! the 198 total across the whole detector set:
//!
//! - `;\s*\w` — 45 benign cases (8.0%). It matches every `Content-Type:
//!   text/html; charset=utf-8`, which is to say essentially every request with a
//!   body.
//! - `\|\s*\w` — 20 more (3.6%). It matches any pipe-delimited value, such as a
//!   column list.
//!
//! The root cause is that a chaining *operator* is not evidence of anything on its
//! own; `;` and `|` are ordinary punctuation. What makes it injection is the
//! **command on the other side**. So the five bare operator patterns
//! (`;`, `|`, `||`, `&&`, newline) collapse into one rule that requires a shell
//! target, and the reference's separate per-command patterns are kept as the
//! second, independent signal.
//!
//! Two further defects the corpus could not surface, because its cases are all
//! single-line values with no markup:
//!
//! - `\n\s*\w` matched any multi-line body. Every JSON payload with newlines.
//! - `<\s*/` matched `</div>`, so any HTML body was a command injection.
//!
//! Both are fixed by the same "require a shell target" rule.
//!
//! The reference's percent-encoded operator patterns (`%3b`, `%7c`, `%26`, `%60`)
//! are **dropped rather than ported**: every field is now decoded before matching,
//! so `%3b` is evaluated as `;` by the rules below, while the raw patterns would
//! have fired on any ordinary encoded query string — `%26` is `&`, which appears in
//! encoded URLs constantly.

use super::{Spec, spec, spec_at};
use crate::rule::Severity;

/// Commands whose appearance after a chaining operator, or with arguments, is what
/// turns punctuation into an injection.
///
/// `id` is here even though it is two letters of ordinary English. It is only ever
/// reached through the chaining rule, which requires a `;`, `|` or newline in front
/// of it — `|| id` is unambiguous where a bare `id` would fire on every `?id=`
/// parameter and every `"id"` JSON key.
const SHELL_COMMANDS: &str = "cat|head|tail|less|more|ls|dir|rm|del|rmdir|\
     mv|cp|dd|touch|echo|env|export|eval|exec|wget|curl|nc|netcat|ncat|\
     bash|sh|zsh|ksh|csh|dash|python[23]?|perl|ruby|php|node|\
     chmod|chown|chgrp|sudo|su|kill|killall|pkill|nohup|\
     id|whoami|uname|hostname|ifconfig|ipconfig|netstat|ping|nslookup|dig";

/// Absolute paths that only appear when someone is naming a binary or a target.
const SHELL_PATHS: &str = r"/(?:bin|sbin|usr|etc|dev|proc|tmp|var|home|root)/";

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- Chaining, with a target -------------------------------------------
        //
        // `;`, `&`, `|`, `||`, `&&` and a bare newline, each requiring a shell
        // command or an absolute system path on the right. This one rule replaces
        // the five that produced most of this detector's false positives.
        spec(
            1,
            &format!(
                r"(?i)[;&|\r\n]{{1,2}}\s*(?:{SHELL_PATHS}|\b(?:{SHELL_COMMANDS})\b)"
            ),
            Severity::Critical,
        ),
        // ---- Command substitution ---------------------------------------------
        spec(10, r"\$\(\s*\w", Severity::Critical),
        spec(11, r"\$\{\s*\w", Severity::Warning),
        // Backticks. Legitimate in a Markdown body, which is why it is a warning
        // rather than critical and why the bound keeps it linear.
        spec(12, r"`[^`\r\n]{1,200}`", Severity::Warning),
        // ---- Redirection -------------------------------------------------------
        //
        // The reference matched `>\s*/` and `<\s*/`, so every `</div>` in an HTML
        // body was a command injection. Requiring a system path keeps the signal
        // and drops the markup.
        spec(
            20,
            &format!(r"(?i)>{{1,2}}\s*{SHELL_PATHS}"),
            Severity::Error,
        ),
        spec(21, &format!(r"(?i)<\s*{SHELL_PATHS}"), Severity::Error),
        spec(22, r"2>&1", Severity::Warning),
        // ---- Commands with arguments ------------------------------------------
        //
        // Independent of the chaining rule: `cat /etc/passwd` as a whole parameter
        // value needs no operator in front of it.
        spec(
            30,
            r"(?i)\b(?:cat|head|tail|less|more)\s+/",
            Severity::Critical,
        ),
        spec(31, r"(?i)\b(?:ls|dir)\s+(?:-\w+\s+)?/", Severity::Error),
        spec(
            32,
            r"(?i)\b(?:rm|del|rmdir)\s+(?:-\w+\s+)",
            Severity::Critical,
        ),
        // A fetcher pointed at a URL is the shape that pulls in a second stage.
        // A bare `curl --silent --location` is someone documenting a command, and it
        // was the only false positive left on the benign corpus, so it waits for
        // paranoia 2.
        spec(
            33,
            r"(?i)\b(?:wget|curl)\s+(?:-\S+\s+)*(?:https?|ftp)://",
            Severity::Critical,
        ),
        spec_at(34, r"(?i)\b(?:wget|curl)\s+\S", Severity::Warning, 2),
        spec(35, r"(?i)\b(?:nc|netcat|ncat)\s+\S", Severity::Critical),
        spec(
            36,
            r"(?i)\b(?:bash|sh|zsh|ksh|csh|dash)\s+-",
            Severity::Critical,
        ),
        spec(
            37,
            r"(?i)\b(?:python[23]?|perl|ruby|php)\s+-",
            Severity::Critical,
        ),
        spec(38, r"(?i)\b(?:chmod|chown|chgrp)\s+\S", Severity::Critical),
        spec(39, r"(?i)\bsudo\s+\S", Severity::Critical),
        spec(40, r"(?i)\b(?:kill|killall|pkill)\s+\S", Severity::Error),
        spec(41, r"(?i)\bping\s+-", Severity::Warning),
        // ---- Reconnaissance commands ------------------------------------------
        //
        // `\b(whoami|id|uname)\b` was the reference's shape. Bare `id` is dropped:
        // it matches every `?id=` parameter and every `"id"` JSON key, which would
        // have made this detector fire on most API traffic. `; id` is still caught
        // by the chaining rule, where the operator supplies the missing context.
        spec(50, r"(?i)\b(?:whoami|uname\s+-)\b", Severity::Error),
        spec(51, r"(?i)\b(?:useradd|userdel|usermod)\b", Severity::Error),
        spec_at(
            52,
            r"(?i)\b(?:ifconfig|ipconfig|netstat)\b",
            Severity::Notice,
            2,
        ),
        // ---- Shell binaries and interpreters ----------------------------------
        spec(
            60,
            r"(?i)/bin/(?:sh|bash|zsh|ksh|csh|dash)",
            Severity::Critical,
        ),
        spec(
            61,
            r"(?i)/usr/bin/(?:sh|bash|python[23]?|perl|ruby|php)",
            Severity::Critical,
        ),
        spec(62, r"(?i)cmd\.exe", Severity::Critical),
        spec(63, r"(?i)powershell", Severity::Error),
        // ---- Environment variable access --------------------------------------
        spec(70, r"\$PATH\b", Severity::Warning),
        spec(71, r"\$HOME\b", Severity::Warning),
        spec(72, r"\$USER\b", Severity::Warning),
        spec(73, r"\$SHELL\b", Severity::Warning),
        spec(74, r"(?i)%systemroot%", Severity::Error),
        spec(75, r"(?i)%comspec%", Severity::Error),
    ]
}
