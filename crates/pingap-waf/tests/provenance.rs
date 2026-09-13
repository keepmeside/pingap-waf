//! The source boundary between this fork and the repositories it surveyed.
//!
//! `./NOTICE` records what was taken from where, and why. Prose in a legal file does
//! not stop an implementer pasting foreign source into a Rust file mid-phase, so the
//! claims that matter are asserted here instead of trusted to review:
//!
//! - **No unlicensed material.** Two of the surveyed projects ship no licence at all —
//!   no `LICENSE` file, no `license` field in their manifests — so there is no grant and
//!   therefore nothing that may be copied from them. A file under a code root that names
//!   either project is a file that was written from it.
//! - **No foreign build input.** Nothing cargo compiles may be a `.go`, `.py`, `.pyc` or
//!   `.pkl` file. The surveyed projects are Go and Python, so a checked-in source file or
//!   a pickled model blob would arrive through a crate directory.
//! - **Attribution stays attached.** The one licensed donor, mango-waf, *is* ported from,
//!   so its name legitimately appears in this tree — but only inside the attribution
//!   headers `NOTICE` prescribes. A header is what tells a future reader the file is a
//!   deliberate rewrite rather than a translation to be "fixed" back toward the original,
//!   so a mention outside one is a ported file that lost its attribution.
//!
//! Scoped to code roots rather than the whole tree, on purpose. `docs/` and `plans/`
//! discuss all of these projects freely and must keep doing so: a check that fires on
//! legitimate prose gets weakened instead of obeyed.

use std::path::{Path, PathBuf};

/// Extensions that are not Rust source and must not sit under a path cargo compiles.
const FOREIGN_BUILD_INPUT: [&str; 4] = ["go", "py", "pyc", "pkl"];

/// The subpaths of a crate directory that cargo actually compiles.
///
/// Not the whole directory. The root crate's directory *is* the workspace, which also
/// holds `.xia-src/` — the read-only reference checkouts this fork ported from, and full
/// of legitimately foreign source — alongside `web/`, `docs/`, `plans/` and `website/`.
const BUILT_SUBPATHS: [&str; 4] = ["src", "tests", "benches", "examples"];

/// Directories that hold generated output rather than authored source: cargo's build
/// directory, and the two cargo-fuzz leaves where it stores seed inputs and crashes.
///
/// Skipping the corpus matters for correctness, not speed. Fuzzing *appends* to it, so a
/// random payload that happens to contain one of the forbidden substrings would fail a
/// licence boundary on bytes nobody wrote.
const GENERATED_DIRS: [&str; 3] = ["target", "corpus", "artifacts"];

/// The two surveyed projects that ship no licence grant.
///
/// Assembled from halves so this file — which lives under `crates/`, inside the roots it
/// polices — does not itself contain the strings it forbids. Naming them literally would
/// require exempting this file from the walk, and an exemption is a hole.
fn unlicensed_names() -> [String; 2] {
    [format!("{}{}", "ki", "ro"), format!("{}{}", "ni", "ds")]
}

/// The one surveyed project whose licence permits porting, and so whose name belongs in
/// attribution headers. Split for the same reason as [`unlicensed_names`]: an assertion
/// that names its own needle literally fails on itself.
fn donor_name() -> String {
    format!("{}{}", "man", "go")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/pingap-waf sits two levels below the workspace root")
        .to_path_buf()
}

/// Every crate cargo builds: the binary crate at the root, the vendored `pingap-*`
/// crates, and the fork crates under `crates/`.
///
/// Found by globbing rather than copied out of `[workspace] members`, so a crate is
/// policed from the moment it exists rather than from the moment someone remembers to
/// update a second list. `.xia-src/` and `spikes/` fall outside naturally: neither has a
/// manifest one level below the root, and both are developer-local.
fn crate_dirs() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut dirs = vec![root.clone()];

    let mut collect = |base: &Path, prefix: Option<&str>| {
        let Ok(entries) = std::fs::read_dir(base) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let named_right = prefix.is_none_or(|p| {
                path.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(p))
            });
            if path.is_dir() && named_right && path.join("Cargo.toml").is_file()
            {
                dirs.push(path);
            }
        }
    };

    collect(&root, Some("pingap-"));
    collect(&root.join("crates"), None);
    dirs
}

/// The conventional cargo subpaths of every crate, whether or not that crate declares
/// them. The root crate's `examples/` holds configuration samples rather than cargo
/// examples, and is checked all the same: it is distributed content, so a foreign source
/// file dropped there would ship.
fn built_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in crate_dirs() {
        for sub in BUILT_SUBPATHS {
            let path = dir.join(sub);
            if path.is_dir() {
                out.push(path);
            }
        }
        for file in ["build.rs", "fuzz/src"] {
            let path = dir.join(file);
            if path.exists() {
                out.push(path);
            }
        }
    }
    out
}

/// The roots the string checks apply to: `crates/` in full, its tests being code too,
/// plus `src/` and each vendored crate's `src/`.
fn code_roots() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut roots = vec![root.join("crates"), root.join("src")];
    for dir in crate_dirs() {
        if dir == root {
            continue;
        }
        let src = dir.join("src");
        if src.is_dir() {
            roots.push(src);
        }
    }
    roots
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Build output and fuzzing artifacts: nothing under either is authored, so
            // nothing under either is evidence.
            let generated = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| GENERATED_DIRS.contains(&n));
            if !generated {
                walk(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

fn files_under(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path in paths {
        if path.is_dir() {
            walk(path, &mut out);
        } else {
            out.push(path.clone());
        }
    }
    out
}

/// `(path, contents)` for every file that is valid UTF-8. One that is not — a binary
/// corpus, say — is skipped rather than guessed at.
fn readable_files(paths: &[PathBuf]) -> Vec<(PathBuf, String)> {
    files_under(paths)
        .into_iter()
        .filter_map(|path| {
            std::fs::read_to_string(&path).ok().map(|t| (path, t))
        })
        .collect()
}

#[test]
fn no_foreign_build_input_on_a_path_cargo_compiles() {
    let paths = built_paths();
    let files = files_under(&paths);
    assert!(
        files.len() > 150,
        "the built-path walk found {} files from {} paths; this workspace has ~235, so \
         the glob is broken and this test would pass vacuously",
        files.len(),
        paths.len()
    );

    let offenders: Vec<_> = files
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| FOREIGN_BUILD_INPUT.contains(&e))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "non-Rust source on a path cargo compiles. These extensions come from the \
         surveyed Go and Python projects, which are read for behaviour and never built \
         here: {offenders:?}"
    );
}

#[test]
fn the_unlicensed_projects_are_not_named_under_a_code_root() {
    let files = readable_files(&code_roots());
    assert!(
        files.len() > 150,
        "the code-root walk read {} files; this workspace has ~215, so the glob is \
         broken and this test would pass vacuously",
        files.len()
    );

    let mut offenders = Vec::new();
    for (path, text) in files {
        let lower = text.to_lowercase();
        for name in unlicensed_names() {
            if lower.contains(&name) {
                offenders.push(format!("{} names {name}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "neither project ships a licence, so neither grants permission to copy anything \
         from it. They are behaviour specifications: describe what they do, never \
         reproduce how they do it. Offenders: {offenders:?}"
    );
}

#[test]
fn the_licensed_donor_is_named_only_inside_an_attribution_header() {
    // Restricted to `.rs`: a crate README explaining what was ported is documentation,
    // and it names the donor in prose, which is correct and must not fail here.
    let sources: Vec<_> = readable_files(&code_roots())
        .into_iter()
        .filter(|(path, _)| path.extension().is_some_and(|e| e == "rs"))
        .collect();
    assert!(
        sources.len() > 150,
        "only {} Rust files found under the code roots; this workspace has ~207, so the \
         walk is broken and this test would pass vacuously",
        sources.len()
    );

    let donor = donor_name();
    let mut offenders = Vec::new();
    for (path, text) in sources {
        for (lineno, line) in text.lines().enumerate() {
            // `//!` is the inner module doc comment, which is where `NOTICE` puts the
            // header: there it survives `rustfmt` and reads as part of the module's own
            // description rather than as a stray remark.
            let in_header = line.trim_start().starts_with("//!");
            if line.to_lowercase().contains(&donor) && !in_header {
                offenders.push(format!(
                    "{}:{} — {line}",
                    path.display(),
                    lineno + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the donor's name belongs in the attribution header `./NOTICE` prescribes, so a \
         file carrying ported logic stays recognisable as a deliberate rewrite. Mentions \
         outside a `//!` line are unattributed ports or stale remarks: {offenders:?}"
    );
}
