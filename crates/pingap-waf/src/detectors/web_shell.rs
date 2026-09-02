//! Web shells in responses (CRS 955 lineage).
//!
//! Written new, like [`super::data_leakage`] — the reference WAF has no
//! response-side detection.
//!
//! A web shell is already-successful compromise: someone uploaded a file and the
//! server is executing it. So the signal is different in kind from a request-side
//! detector. Request-side rules look for an *attempt*; these look for the
//! *aftermath*, which means two things:
//!
//! 1. A hit here is an incident, not a tuning data point. Severity is high across
//!    the board and the finding matters even in detect mode.
//! 2. Redaction is the weakest possible response and should never be mistaken for
//!    remediation. Rewriting the shell's output out of one response leaves the shell
//!    on disk and running.
//!
//! Two families: the source of a shell being echoed back (a `.php` file served as
//! text, or a shell's own uploader page), and the *output* of shell commands
//! appearing in an HTML body.

use super::{Spec, spec};
use crate::rule::Severity;

pub fn specs() -> Vec<Spec> {
    vec![
        // ---- PHP shell source echoed into a response ---------------------------
        //
        // Superglobals passed straight to an executor. This is the defining shape of
        // a PHP web shell, and there is no benign version of it.
        spec(
            1,
            r"(?i)\b(?:eval|assert|passthru|shell_exec|system|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)",
            Severity::Critical,
        ),
        spec(
            2,
            r"(?i)\bbase64_decode\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)",
            Severity::Critical,
        ),
        spec(
            3,
            r"(?i)\bpreg_replace\s*\(\s*['\x22].{0,40}/e['\x22]",
            Severity::Critical,
        ),
        spec(
            4,
            r"(?i)\$_(?:POST|GET|REQUEST)\s*\[[^\]]{0,40}\]\s*\(",
            Severity::Critical,
        ),
        // ---- Named shells ------------------------------------------------------
        //
        // Long-circulating kits whose banners are stable.
        spec(30, r"(?i)\bc99shell\b", Severity::Critical),
        spec(31, r"(?i)\br57shell\b", Severity::Critical),
        spec(32, r"(?i)\bb374k\b", Severity::Critical),
        spec(33, r"(?i)\bweevely\b", Severity::Critical),
        spec(34, r"(?i)\bWSO\s+\d+\.\d+", Severity::Critical),
        spec(35, r"(?i)\bChina\s*Chopper\b", Severity::Critical),
        spec(
            36,
            r"(?i)<title>\s*(?:.{0,40}\bshell\b.{0,40})</title>",
            Severity::Error,
        ),
        // ---- Shell command output in a response body ---------------------------
        //
        // `id` output: the single most common thing an operator of a fresh shell
        // runs. `uid=0(root)` in an HTML body is not something an application emits.
        spec(
            60,
            r"\buid=\d+\([\w.-]+\)\s+gid=\d+\([\w.-]+\)",
            Severity::Critical,
        ),
        // `/etc/passwd` contents: at least two colon-delimited account lines.
        spec(
            61,
            r"(?m)^[\w.-]+:[^:\r\n]*:\d+:\d+:[^:\r\n]*:[^:\r\n]*:/(?:bin|usr|sbin)/\S*$",
            Severity::Critical,
        ),
        // A shell prompt or directory listing echoed back.
        spec(
            62,
            r"(?i)\b(?:drwx|-rw-)[rwxsStT-]{6,7}\s+\d+\s+\w+\s+\w+\s+\d+",
            Severity::Error,
        ),
        spec(
            63,
            r"(?i)\bLinux\s+\S+\s+\d+\.\d+\.\d+\S*\s+#\d+",
            Severity::Error,
        ),
        // Windows equivalents.
        spec(
            64,
            r"(?i)\bVolume\s+in\s+drive\s+[A-Z]\s+(?:is|has no label)",
            Severity::Error,
        ),
        spec(65, r"(?i)\bnt authority\\system\b", Severity::Critical),
    ]
}
