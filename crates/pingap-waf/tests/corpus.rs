//! Regression gate against the frozen detector corpus.
//!
//! The corpus is verified by hash **before** it is scored. A regression gate whose
//! fixture can be edited is not a gate: the easiest way to make a false-positive
//! count fall is to delete benign cases, and that would look like progress in every
//! report while the WAF got worse.
//!
//! Measured baseline to beat, from the risk-reduction run over this exact corpus:
//!
//! | | rate |
//! |---|---|
//! | false positives, any detector, 560 benign cases | 0.3536 |
//! | true positives, 166 malicious cases | 0.9277 |
//!
//! Both directions are asserted. Buying precision by dropping recall is not an
//! improvement, and it is the failure mode a false-positive-only gate invites.
//!
//! Scoring matches the baseline's method: each corpus file's contents are one field
//! value, and a case counts as a hit if **any** request-side detector fires.

use pingap_waf::config::{RawMode, WafConfig};
use pingap_waf::{Category, Paranoia, RequestInput, RuleEngine, detectors};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Recorded when the corpus was frozen. Both numbers, because a hash match with a
/// different file count would mean the hash function changed rather than the corpus.
const FROZEN_TREE_HASH: &str =
    "ea65120d61d1b7b727944697c53df0ed9e6ae61975e8f3e6fc69d45fc88e1822";
const FROZEN_FILE_COUNT: usize = 726;

/// The measured baseline this port has to beat.
const BASELINE_FP_RATE: f64 = 0.3536;
/// The measured recall this port has to hold.
const BASELINE_TP_RATE: f64 = 0.9277;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spikes/detector-baseline/corpus")
}

/// Files under `dir`, sorted by name so the walk is deterministic.
fn read_dir_sorted(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    files
}

/// The corpus tree hash: every `(relative path, contents)` pair in sorted order,
/// each field NUL-terminated so a rename cannot be masked by a compensating edit.
///
/// Reimplements the freezing harness's algorithm rather than shelling out to it.
/// The harness lives outside this workspace and is throwaway by design; a gate that
/// depends on it would stop working the moment it is deleted.
fn corpus_hash(root: &Path) -> (String, usize) {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut children: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        children.sort();
        for path in children {
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // The manifest and the recorded hash are not part of what is hashed.
            if name == "MANIFEST.sha256" || name == "TREE_HASH" {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let body = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            entries.push((rel, body));
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
    (hex::encode(h.finalize()), entries.len())
}

/// An engine in pure detect mode at the given paranoia level. Detect, not block:
/// what is being measured is which rules fire, and a threshold would hide any hit
/// that did not reach it.
fn engine(paranoia: Paranoia) -> RuleEngine {
    let cfg = WafConfig {
        categories: Category::ALL
            .iter()
            .map(|c| (c.key().to_string(), RawMode::Detect))
            .collect(),
        paranoia,
        // Generous: a corpus case timing out would be scored as a miss and would
        // silently flatter the false-positive rate.
        budget_ms: 10_000,
        ..Default::default()
    };
    RuleEngine::build(
        cfg.validate().expect("corpus config is valid"),
        detectors::request_rules(),
        detectors::response_rules(),
    )
    .expect("native ruleset builds")
}

/// Categories that fired on one corpus case, scored exactly as the baseline did:
/// the file contents as a single field value.
fn categories_for(engine: &RuleEngine, case: &str) -> Vec<Category> {
    let query = [("q", case)];
    let input = RequestInput {
        method: "GET",
        uri: "/",
        headers: &[],
        query: &query,
        body: None,
        client_ip: None,
        body_truncated: false,
    };
    let e = engine.evaluate_request(&input);
    assert!(
        e.exhausted.is_none(),
        "a corpus case exhausted the budget, which would be scored as a miss: \
         {case:?}"
    );
    let mut v: Vec<Category> =
        e.verdict.hits().iter().map(|h| h.category).collect();
    v.sort_by_key(|c| c.crs_group());
    v.dedup();
    v
}

#[derive(Default, Debug)]
struct Score {
    hit: usize,
    total: usize,
}

impl Score {
    fn rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.hit as f64 / self.total as f64
    }
}

/// Both rates plus the per-category breakdown, at one paranoia level.
struct Measurement {
    fp: Score,
    tp: Score,
    per_detector_fp: BTreeMap<&'static str, Score>,
    per_category_tp: BTreeMap<String, Score>,
}

fn measure(paranoia: Paranoia) -> Measurement {
    let root = corpus_root();
    let engine = engine(paranoia);

    let mut fp = Score::default();
    let mut per_detector_fp: BTreeMap<&'static str, Score> = BTreeMap::new();
    for f in read_dir_sorted(&root.join("benign")) {
        let case = std::fs::read_to_string(&f)
            .unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        let hits = categories_for(&engine, &case);
        fp.total += 1;
        if !hits.is_empty() {
            fp.hit += 1;
        }
        for c in Category::ALL {
            let e = per_detector_fp.entry(c.key()).or_default();
            e.total += 1;
            if hits.contains(&c) {
                e.hit += 1;
            }
        }
    }

    let mut tp = Score::default();
    let mut per_category_tp: BTreeMap<String, Score> = BTreeMap::new();
    for set in ["sqli", "xss", "traversal", "cmdi"] {
        let dir = root.join("malicious").join(set);
        let entry = per_category_tp.entry(set.to_string()).or_default();
        for f in read_dir_sorted(&dir) {
            let case = std::fs::read_to_string(&f)
                .unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
            let caught = !categories_for(&engine, &case).is_empty();
            entry.total += 1;
            tp.total += 1;
            if caught {
                entry.hit += 1;
                tp.hit += 1;
            }
        }
    }

    Measurement {
        fp,
        tp,
        per_detector_fp,
        per_category_tp,
    }
}

#[test]
fn the_corpus_is_the_one_the_baseline_was_measured_on() {
    let root = corpus_root();
    assert!(
        root.is_dir(),
        "the frozen corpus is missing at {} — the regression gate cannot run \
         without it",
        root.display()
    );
    let (hash, count) = corpus_hash(&root);
    assert_eq!(
        count, FROZEN_FILE_COUNT,
        "corpus file count changed; the recorded rates are no longer comparable"
    );
    assert_eq!(
        hash, FROZEN_TREE_HASH,
        "corpus contents changed; shrinking or editing it is the easiest way to \
         fake a false-positive improvement"
    );
    // The manifest is a second, independent record of the same freeze.
    let manifest = std::fs::read_to_string(root.join("MANIFEST.sha256"))
        .expect("manifest");
    assert_eq!(
        manifest.lines().filter(|l| !l.trim().is_empty()).count(),
        FROZEN_FILE_COUNT,
        "MANIFEST.sha256 disagrees with the corpus it describes"
    );
}

#[test]
fn the_ported_detectors_beat_the_measured_false_positive_baseline() {
    // Default paranoia, because that is what an operator who changes nothing gets.
    // Measuring the gate at raised paranoia would report a number nobody runs.
    let m = measure(Paranoia::MIN);

    println!(
        "paranoia 1 — fp {:.4} ({}/{})",
        m.fp.rate(),
        m.fp.hit,
        m.fp.total
    );
    println!(
        "paranoia 1 — tp {:.4} ({}/{})",
        m.tp.rate(),
        m.tp.hit,
        m.tp.total
    );
    for (name, s) in &m.per_detector_fp {
        if s.hit > 0 {
            println!("  fp {name}: {:.4} ({}/{})", s.rate(), s.hit, s.total);
        }
    }
    for (name, s) in &m.per_category_tp {
        println!("  tp {name}: {:.4} ({}/{})", s.rate(), s.hit, s.total);
    }

    assert!(
        m.fp.rate() < BASELINE_FP_RATE,
        "false-positive rate {:.4} is not below the {BASELINE_FP_RATE} baseline",
        m.fp.rate()
    );
    assert!(
        m.tp.rate() >= BASELINE_TP_RATE,
        "recall fell to {:.4}, below the {BASELINE_TP_RATE} baseline — precision \
         bought with recall is not an improvement",
        m.tp.rate()
    );
}

#[test]
fn raising_paranoia_finds_more_and_never_less() {
    // Paranoia is a monotone dial or it is a lie. A level that misses something a
    // lower level caught would make the setting unusable: an operator turning it up
    // to catch more would silently lose coverage.
    let mut previous_tp = 0usize;
    for level in 1..=4u8 {
        let p = Paranoia::new(level).expect("1..=4");
        let m = measure(p);
        println!(
            "paranoia {level} — fp {:.4}, tp {:.4}",
            m.fp.rate(),
            m.tp.rate()
        );
        assert!(
            m.tp.hit >= previous_tp,
            "paranoia {level} caught {} malicious cases, fewer than the {} at \
             the level below",
            m.tp.hit,
            previous_tp
        );
        previous_tp = m.tp.hit;
    }
}
