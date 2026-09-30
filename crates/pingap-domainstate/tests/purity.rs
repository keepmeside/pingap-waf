//! The container knows nothing about what it holds or who is asking.
//!
//! Two properties, both easy to lose one commit at a time. A generic container that grows a
//! `should_block`-shaped method has become a policy engine, and a policy engine that four
//! subsystems share is a place where one subsystem's decision silently changes another's. The
//! check is a test rather than a review rule because the drift is gradual and always looks
//! reasonable at the diff that introduces it.

use std::path::{Path, PathBuf};

/// Names of the subsystems that consume this crate.
///
/// Matched as whole words, not substrings: a raw substring search for one of these finds
/// "both" and every other ordinary English word that happens to contain a three-letter
/// sequence, which would make the check fire on prose and get weakened rather than obeyed.
const CONSUMER_NAMES: [&str; 7] = [
    "waf",
    "bot",
    "acl",
    "challenge",
    "intel",
    "behaviour",
    "adaptive",
];

/// Method-name fragments that imply the container reaches a decision rather than storing a
/// value. Storing is this crate's whole contract; deciding is the caller's.
const DECISION_VOCABULARY: [&str; 8] = [
    "should", "block", "deny", "allow", "permit", "refuse", "reject", "verdict",
];

fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn sources() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![source_dir()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path)
                    .expect("this crate's source is UTF-8");
                out.push((path, text));
            }
        }
    }
    assert!(
        out.len() >= 3,
        "found {} source files; this crate has three, so the walk is broken",
        out.len()
    );
    out
}

/// Words in a line, split on everything that is not part of an identifier.
fn words(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
}

#[test]
fn the_container_names_no_consumer() {
    let mut offenders = Vec::new();
    for (path, text) in sources() {
        for (lineno, line) in text.lines().enumerate() {
            for word in words(line) {
                // Underscore-joined identifiers split on `_` above only if `_` is excluded;
                // it is not, so `challenge_token` arrives whole and must be matched as a
                // prefix of itself. Splitting again on `_` catches compound names.
                for part in word.split('_') {
                    if CONSUMER_NAMES.contains(&part) {
                        offenders.push(format!(
                            "{}:{} names `{part}`",
                            path.display(),
                            lineno + 1
                        ));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the container must not know who consumes it. Naming a subsystem here is how a payload \
         type or a policy rule eventually follows: {offenders:?}"
    );
}

#[test]
fn no_public_method_name_implies_a_decision() {
    let mut offenders = Vec::new();
    for (path, text) in sources() {
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let Some(signature) = trimmed.strip_prefix("pub fn ") else {
                continue;
            };
            let name = signature.split('(').next().unwrap_or(signature);
            if DECISION_VOCABULARY.iter().any(|word| name.contains(word)) {
                offenders.push(format!(
                    "{}:{} `pub fn {name}`",
                    path.display(),
                    lineno + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a decision-shaped method here means the container has become a policy engine shared by \
         every consumer, so one subsystem's rule silently changes another's: {offenders:?}"
    );
}

#[test]
fn the_payload_type_is_never_named_in_the_public_api() {
    // `V` is the payload parameter and must stay unconstrained. A bound naming a concrete type,
    // or a `where` clause requiring serialisation, would make the container know something
    // about what it holds and couple four crates to one payload shape.
    for (path, text) in sources() {
        for (lineno, line) in text.lines().enumerate() {
            if line.contains("V:") && line.contains("serde") {
                panic!(
                    "{}:{} bounds the payload on serialisation: {line}",
                    path.display(),
                    lineno + 1
                );
            }
        }
    }
}
