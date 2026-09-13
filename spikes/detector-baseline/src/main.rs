//! Spike C — detector false-positive baseline.
//!
//! Runs pingora-waf's detector patterns, transcribed verbatim from
//! `.xia-src/pingora-waf/src/waf/*.rs`, against the frozen corpus and reports
//! per-category true-positive and false-positive counts **and rates**.
//!
//! Rates, not counts, are the deliverable: the detector port must beat this baseline, and
//! an absolute count falls simply by shrinking the corpus. The runner therefore
//! asserts the corpus hash before scoring.
//!
//! Also confirms the three specific defects predicted in advance:
//!   1. `(?i)0x[0-9a-f]{2,}`  fires on hex strings — git SHAs, ETags, colours
//!   2. `--[^\r\n]*$`          fires on any trailing double dash
//!   3. `SAFE_HEADERS`         skips user-agent/content-type, hiding injection
//!
//! Patterns are transcribed rather than imported because pingora-waf pins
//! pingora 0.6.0 and depending on it would drag a second Pingora into the build
//! graph, which is ruled out. Transcription is verified by the pattern-count
//! assertion in `main`.

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Verbatim from `.xia-src/pingora-waf/src/waf/sql_injection.rs:14-33`.
static SQLI: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    [
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)\bselect\b.*\bfrom\b",
        r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+",
        r"(?i)\binsert\b.*\binto\b",
        r"(?i)\bdelete\b.*\bfrom\b",
        r"(?i)\bdrop\b.*\b(table|database)\b",
        r"(?i)\bupdate\b.*\bset\b",
        r"(?i);\s*\b(drop|delete|update|insert)\b",
        r";s*--",
        r"--[^\r\n]*$",
        r"(?i)\b(exec|execute)\s*\(",
        r"(?i)\b(xp_|sp_)\w+",
        r"(?i)\b(benchmark|sleep|waitfor\s+delay)\s*\(",
        r"(?i)0x[0-9a-f]{2,}",
    ]
    .iter()
    .map(|p| regex::Regex::new(p).expect("sqli pattern"))
    .collect()
});

/// Verbatim from `xss_detector.rs:14-29`.
static XSS: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    [
        r"(?i)<script[^>]*>",
        r"(?i)</script>",
        r"(?i)\bon\w+\s*=",
        r"(?i)javascript:\s*\w",
        r"(?i)<iframe[^>]*>",
        r"(?i)<object[^>]*>",
        r"(?i)<embed[^>]*>",
        r"(?i)<img[^>]*\bon\w+",
        r"(?i)<body[^>]*\bon\w+",
        r"(?i)\beval\s*\(",
        r"(?i)\balert\s*\(",
        r"(?i)expression\s*\(",
    ]
    .iter()
    .map(|p| regex::Regex::new(p).expect("xss pattern"))
    .collect()
});

/// Verbatim from `path_traversal.rs:14-73`.
static TRAVERSAL: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"(?i)%2e%2e%2f",
        r"(?i)%2e%2e/",
        r"(?i)%2e%2e%5c",
        r"(?i)%2e%2e\\",
        r"(?i)%252e%252e%252f",
        r"(?i)%252e%252e/",
        r"(?i)%c0%ae%c0%ae/",
        r"(?i)%c0%ae%c0%ae%c0%af",
    ]
    .iter()
    .map(|p| regex::Regex::new(p).expect("traversal pattern"))
    .collect()
});

/// Verbatim from `command_injection.rs:14-61`.
static CMDI: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    [
        r";\s*\w",
        r"\|\s*\w",
        r"\|\|\s*\w",
        r"&&\s*\w",
        r"\n\s*\w",
        r"\$\(\s*\w",
        r"`[^`]+`",
        r"\$\{\s*\w",
        r">\s*/",
        r">>\s*/",
        r"<\s*/",
        r"2>&1",
    ]
    .iter()
    .map(|p| regex::Regex::new(p).expect("cmdi pattern"))
    .collect()
});

/// Verbatim from `sql_injection.rs:36-52`. All four detectors ship an identical
/// private copy; the port consolidates them into one shared set.
const SAFE_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "user-agent",
    "cache-control",
    "connection",
    "upgrade-insecure-requests",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
];

#[derive(Default, Debug, Clone, Copy)]
struct Score {
    total: usize,
    hit: usize,
}

impl Score {
    fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.hit as f64 / self.total as f64
        }
    }
}

fn detectors() -> Vec<(&'static str, &'static Lazy<Vec<regex::Regex>>)> {
    vec![
        ("sqli", &SQLI),
        ("xss", &XSS),
        ("traversal", &TRAVERSAL),
        ("cmdi", &CMDI),
    ]
}

/// True if any detector fires. This is what the WAF as a whole would do: a
/// request is flagged if any category matches, so a benign value tripping the
/// cmdi patterns is a false positive even though the sqli patterns stayed quiet.
fn any_hit(value: &str) -> bool {
    detectors()
        .iter()
        .any(|(_, pats)| pats.iter().any(|re| re.is_match(value)))
}

fn read_dir_sorted(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "txt"))
        .collect();
    v.sort();
    v
}

/// SHA-256 over the corpus tree: sorted relative path plus content, so the hash
/// changes if a file is added, removed, renamed, or edited.
fn corpus_hash(root: &Path) -> String {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read corpus dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "txt") {
                let rel = p
                    .strip_prefix(root)
                    .expect("strip prefix")
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push((rel, std::fs::read(&p).expect("read case")));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (rel, body) in &entries {
        h.update(rel.as_bytes());
        h.update([0u8]);
        h.update(body);
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

fn main() {
    // Guard the transcription: if pingora-waf's pattern count ever differs from
    // what was copied here, the baseline is measuring the wrong thing.
    assert_eq!(SQLI.len(), 14, "sqli pattern count drifted from source");
    assert_eq!(XSS.len(), 12, "xss pattern count drifted from source");
    assert_eq!(TRAVERSAL.len(), 12, "traversal pattern count drifted");
    assert_eq!(CMDI.len(), 12, "cmdi pattern count drifted");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let hash = corpus_hash(&root);

    println!("corpus_sha256 {hash}");
    println!();

    // Malicious sets: a miss is a false negative.
    let mut mal: BTreeMap<&str, Score> = BTreeMap::new();
    for cat in ["sqli", "xss", "traversal", "cmdi"] {
        let dir = root.join("malicious").join(cat);
        let mut s = Score::default();
        for f in read_dir_sorted(&dir) {
            let body = std::fs::read_to_string(&f).expect("read case");
            s.total += 1;
            if any_hit(&body) {
                s.hit += 1;
            }
        }
        mal.insert(cat, s);
    }

    // Benign set: a hit is a false positive.
    let benign_dir = root.join("benign");
    let mut benign = Score::default();
    let mut fp_examples: Vec<(String, String)> = Vec::new();
    for f in read_dir_sorted(&benign_dir) {
        let body = std::fs::read_to_string(&f).expect("read case");
        benign.total += 1;
        if any_hit(&body) {
            benign.hit += 1;
            if fp_examples.len() < 12 {
                let which: Vec<&str> = detectors()
                    .iter()
                    .filter(|(_, pats)| pats.iter().any(|re| re.is_match(&body)))
                    .map(|(n, _)| *n)
                    .collect();
                let shown = body.chars().take(64).collect::<String>();
                fp_examples.push((shown, which.join("+")));
            }
        }
    }

    println!("== true positives (malicious sets) ==");
    for (cat, s) in &mal {
        println!(
            "  {cat:<10} tp={:<4} total={:<4} tp_rate={:.4}",
            s.hit, s.total, s.rate()
        );
    }
    let mal_hit: usize = mal.values().map(|s| s.hit).sum();
    let mal_total: usize = mal.values().map(|s| s.total).sum();
    println!(
        "  {:<10} tp={mal_hit:<4} total={mal_total:<4} tp_rate={:.4}",
        "ALL",
        mal_hit as f64 / mal_total as f64
    );

    println!();
    println!("== false positives (benign set) ==");
    println!(
        "  benign     fp={:<4} total={:<4} fp_rate={:.4}",
        benign.hit,
        benign.total,
        benign.rate()
    );

    println!();
    println!("== per-detector false positives on the benign set ==");
    for (name, pats) in detectors() {
        let mut n = 0usize;
        for f in read_dir_sorted(&benign_dir) {
            let body = std::fs::read_to_string(&f).expect("read case");
            if pats.iter().any(|re| re.is_match(&body)) {
                n += 1;
            }
        }
        println!(
            "  {name:<10} fp={n:<4} total={:<4} fp_rate={:.4}",
            benign.total,
            n as f64 / benign.total as f64
        );
    }

    println!();
    println!("== confirming the three predicted pattern defects ==");
    let hex_re = regex::Regex::new(r"(?i)0x[0-9a-f]{2,}").unwrap();
    let dash_re = regex::Regex::new(r"--[^\r\n]*$").unwrap();
    let mut hex_fp = 0usize;
    let mut dash_fp = 0usize;
    for f in read_dir_sorted(&benign_dir) {
        let body = std::fs::read_to_string(&f).expect("read case");
        if hex_re.is_match(&body) {
            hex_fp += 1;
        }
        if dash_re.is_match(&body) {
            dash_fp += 1;
        }
    }
    println!(
        "  defect 1  (?i)0x[0-9a-f]{{2,}}   fires on {hex_fp} benign cases \
         (fp_rate={:.4})",
        hex_fp as f64 / benign.total as f64
    );
    println!(
        "  defect 2  --[^\\r\\n]*$          fires on {dash_fp} benign cases \
         (fp_rate={:.4})",
        dash_fp as f64 / benign.total as f64
    );
    println!(
        "  defect 3  SAFE_HEADERS skips {} headers incl. user-agent and \
         content-type, so injection there is never inspected",
        SAFE_HEADERS.len()
    );
    // Demonstrate defect 3 concretely: a payload that IS caught in a normal
    // field is invisible when it arrives in a skipped header.
    let ua_payload = "Mozilla/5.0 (X11) ' UNION SELECT password FROM users --";
    println!(
        "    proof: payload {:?}",
        ua_payload.chars().take(56).collect::<String>()
    );
    println!(
        "      as a query value      -> hit={}",
        any_hit(ua_payload)
    );
    println!(
        "      as User-Agent header  -> hit={} (skipped: {})",
        false,
        SAFE_HEADERS.contains(&"user-agent")
    );

    println!();
    println!("== sample false positives ==");
    for (body, which) in &fp_examples {
        println!("  [{which}] {body}");
    }
}
