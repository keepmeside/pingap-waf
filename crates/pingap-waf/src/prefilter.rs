//! The literal prefilter: decide which rules could possibly match before any
//! regex runs.
//!
//! A ruleset of ~160 patterns spends most of its evaluation scanning fields
//! that cannot match most of them: a request without the bytes `union` needs
//! can still cost a full pass over every SQL-injection pattern. This module
//! extracts, from each pattern, the **literal set every match of that pattern
//! must contain**, collapses it to one ASCII-lowercased needle per distinct
//! literal, and ships the union of all needles as one Aho-Corasick automaton.
//! One pass over the request fields then marks which rules are *present* —
//! some needle of theirs actually occurs — and the engine skips the rest
//! before their regex ever runs, budget included.
//!
//! # Why the needles are sound
//!
//! `regex-syntax`' literal extractor returns one of two kinds for a pattern,
//! each with a containment contract ([`Extractor::kind`]):
//!
//! - **Prefix**: every match of the pattern *starts with* one of the literals.
//! - **Suffix**: every match *ends with* one of the literals.
//!
//! Either way, every match *contains* one of the literals. So if none of the
//! literals occurs anywhere in the bytes a rule can inspect, the rule cannot
//! match, and skipping it changes no verdict. A set the extractor cannot
//! bound (`literals()` returns `None`, "infinite") is simply not usable, and
//! the rule stays ungated — present, always scanned. Ungated is the safe
//! direction everywhere in this module: cap overflow, build failure, and
//! unparsable patterns all degrade to it.
//!
//! `fancy-regex` agreement: the engine's patterns run on `fancy-regex`, this
//! module parses them with `regex-syntax`. A pattern `regex-syntax` accepts
//! has no fancy-only construct (backreference, lookaround); for exactly those,
//! `fancy-regex` delegates to the `regex` crate, which compiles from the same
//! `regex-syntax` HIR with the same semantics. A pattern `regex-syntax`
//! *rejects* leaves [`required_needles`] returning `None` — ungated, never a
//! wrong needle.
//!
//! # Case folding
//!
//! Case-insensitive classes expand to one literal per case variant, so every
//! variant carries its own needle. The needle is the literal lowercased with
//! `to_ascii_lowercase` and the automaton is built ASCII-case-insensitive:
//! an ASCII variant fires on itself and its case partner, and a non-ASCII
//! variant (the Kelvin-sign `K`, the long-s `ſ`) survives `to_ascii_lowercase`
//! untouched and matches its own exact bytes. Every literal in the extracted
//! set therefore has a needle that fires when that literal occurs. The
//! automaton firing *more* often than a literal occurs is fine — that is the
//! superset direction.
//!
//! # What the prescan must see
//!
//! The prescan walks a **superset** of the bytes rules can inspect: every
//! header value (not only those passing `inspect_header`, because a
//! [`Scope::Header`](crate::detectors::Scope) rule reads its header raw), and
//! every encoded form of every field (raw, percent-decoded, `+`-decoded —
//! reusing [`find_both_forms`](crate::engine) so the form logic cannot drift
//! from the matching path). Response-side fields are scanned raw only,
//! mirroring [`find_in_response`](crate::engine), which never decodes.
//!
//! The automaton scan uses **overlapping** iteration: the ordinary iterator
//! resumes at each match's end, so with needles `app` and `append` a haystack
//! `append` would report `app` and never `append` — a present rule marked
//! absent, which is the unsound direction. Overlapping iteration reports
//! every occurrence, which is exactly the superset the gate needs.

use crate::engine::{RequestInput, ResponseInput, each_form, text_prefix};
use aho_corasick::{AhoCorasick, MatchKind};
use regex_syntax::hir::literal::{ExtractKind, Extractor, Literal, Seq};
use std::collections::HashMap;

/// Most needles a single rule may contribute, after case collapsing.
///
/// A pattern whose collapsed set exceeds this is ungated rather than gated on
/// a subset: gating on *some* of a rule's literals is unsound (a match that
/// contains only a dropped literal would be skipped), so the choice is all or
/// nothing.
pub const NEEDLE_CAP: usize = 64;

/// Most needles the whole automaton may carry.
///
/// The point is to bound build time and automaton size for a pathological
/// config (thousands of custom rules) while leaving an ordinary ruleset —
/// roughly two needles per rule — far below it. Rules whose needles do not
/// fit are ungated, in rule order, so the native ruleset keeps its gates.
const TOTAL_NEEDLE_CAP: usize = 4096;

/// The extraction budget. The stock `limit_total` of 250 refuses the
/// case-expansion of any `(?i)` word past 7–8 letters (2^8 = 256), which is
/// most of the keywords the detectors are built from; 4096 admits words to
/// 12 letters, whose 4096 case variants then collapse back to a single
/// needle. Longer `(?i)` words stay ungated.
const EXTRACT_LIMIT_TOTAL: usize = 4096;

/// The literal set every match of `pattern` must contain, or `None` when no
/// usable set exists.
///
/// Lowercased with `to_ascii_lowercase`, deduplicated, in extraction order.
/// `None` means ungated — the caller must treat the rule as always present —
/// and is returned for: an unparsable pattern, both extraction kinds
/// unbounded, any empty literal (a pattern that can match nothing but a
/// position — `\b`, `a?` — has no needle that could gate it), a literal that
/// is not valid UTF-8, or more than [`NEEDLE_CAP`] needles after collapsing.
pub fn required_needles(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::parse(pattern).ok()?;
    for kind in [ExtractKind::Prefix, ExtractKind::Suffix] {
        let mut extractor = Extractor::new();
        extractor.kind(kind).limit_total(EXTRACT_LIMIT_TOTAL);
        let seq: Seq = extractor.extract(&hir);
        // `None` is the extractor's "unbounded" marker: the literal set is
        // not finite, so it cannot serve as a gate. The other kind may still
        // be finite — a pattern anchored by literals at one end only.
        let Some(literals) = seq.literals() else {
            continue;
        };
        let Some(needles) = collapse(literals) else {
            continue;
        };
        if needles.is_empty() || needles.len() > NEEDLE_CAP {
            continue;
        }
        return Some(needles);
    }
    None
}

/// Collapse extracted literals to deduplicated ASCII-lowercase needles.
///
/// `None` — ungated, not an empty set — when any literal is empty or not
/// valid UTF-8. An empty literal means some match path contributes no bytes
/// (a bare look, a `?`/`*`/`{0,}` quantifier), and dropping it from the set
/// would gate out matches that take that path, so the whole rule must stay
/// ungated. Invalid UTF-8 cannot be turned into a `&str` needle; under
/// `regex_syntax::parse`'s UTF-8 mode it should not occur, but this is the
/// safe direction if it ever does.
fn collapse(literals: &[Literal]) -> Option<Vec<String>> {
    let mut needles: Vec<String> = Vec::new();
    for literal in literals {
        if literal.is_empty() {
            return None;
        }
        let text = std::str::from_utf8(literal.as_bytes()).ok()?;
        let needle = text.to_ascii_lowercase();
        if !needles.contains(&needle) {
            needles.push(needle);
        }
    }
    Some(needles)
}

/// One surface's gate: an automaton over every gated rule's needles, and the
/// needle-to-rules mapping that turns a hit into "these rules are present".
pub struct Prefilter {
    /// `None` when no rule is gated, or when the automaton failed to build —
    /// in both cases every rule runs unfiltered, which is sound because
    /// ungated is the safe direction.
    ac: Option<AhoCorasick>,
    /// `by_needle[i]` holds the rule indices gated on needle `i`.
    by_needle: Vec<Vec<u32>>,
    /// One entry per rule on this surface: `true` when the rule has no gate
    /// and must always be treated as present.
    ungated: Vec<bool>,
}

impl Prefilter {
    /// Build the gate for one surface's rules, in rule order.
    pub(crate) fn build<R: crate::rule::Rule + ?Sized>(
        rules: &[Box<R>],
    ) -> Self {
        let mut ungated = vec![false; rules.len()];
        let mut needle_id: HashMap<&str, usize> = HashMap::new();
        let mut needles: Vec<&str> = Vec::new();
        let mut by_needle: Vec<Vec<u32>> = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            let Some(required) = rule.required_literals() else {
                ungated[index] = true;
                continue;
            };
            // An empty set gates on nothing: no scan could ever mark the rule
            // present, so it would be skipped on every input — the unsound
            // direction. `required_needles` never answers empty, but the trait
            // is wider than its native implementors; the answer degrades to
            // ungated like every other the gate cannot use.
            if required.is_empty() {
                ungated[index] = true;
                continue;
            }
            // All or nothing: a rule whose needles cannot all fit is left
            // ungated, never gated on a subset.
            let missing = required
                .iter()
                .filter(|n| !needle_id.contains_key(n.as_str()))
                .count();
            if needles.len() + missing > TOTAL_NEEDLE_CAP {
                ungated[index] = true;
                continue;
            }
            for needle in required {
                let id = match needle_id.get(needle.as_str()) {
                    Some(&id) => id,
                    None => {
                        needle_id.insert(needle.as_str(), needles.len());
                        needles.push(needle.as_str());
                        by_needle.push(Vec::new());
                        needles.len() - 1
                    },
                };
                by_needle[id].push(index as u32);
            }
        }
        let ac = if needles.is_empty() {
            None
        } else {
            build_automaton(&needles)
        };
        if ac.is_none() {
            // No automaton, no gates: every rule must read as present.
            ungated.fill(true);
        }
        Self {
            ac,
            by_needle,
            ungated,
        }
    }

    /// The starting present-mask: `true` for every ungated rule.
    ///
    /// One allocation per evaluation, sized by the rule count and never by
    /// the input — the same bound the plan set for the prescan.
    pub(crate) fn present_mask(&self) -> Vec<bool> {
        self.ungated.clone()
    }

    /// Mark present every gated rule whose needle occurs in the request's
    /// inspectable bytes.
    ///
    /// Walks a superset of what rules can see: all header values in every
    /// encoded form, plus method, URI, query values and the clamped body
    /// prefix in every form. See the module docs for why each choice is the
    /// safe direction.
    pub(crate) fn mark_request(
        &self,
        input: &RequestInput<'_>,
        mask: &mut [bool],
    ) {
        let Some(ac) = self.ac.as_ref() else {
            return;
        };
        let mut remaining = absent(mask);
        if remaining == 0 {
            return;
        }
        mark_field(ac, &self.by_needle, input.method, mask, &mut remaining);
        if remaining == 0 {
            return;
        }
        mark_field(ac, &self.by_needle, input.uri, mask, &mut remaining);
        if remaining == 0 {
            return;
        }
        for (_key, value) in input.query {
            mark_field(ac, &self.by_needle, value, mask, &mut remaining);
            if remaining == 0 {
                return;
            }
        }
        for (_name, value) in input.headers {
            mark_field(ac, &self.by_needle, value, mask, &mut remaining);
            if remaining == 0 {
                return;
            }
        }
        if let Some(body) = input.body {
            mark_field(
                ac,
                &self.by_needle,
                text_prefix(body),
                mask,
                &mut remaining,
            );
        }
    }

    /// The response-side counterpart. Raw bytes only, in both the header
    /// values and the body prefix, mirroring [`find_in_response`], which
    /// never decodes — response offsets must stay valid against the bytes a
    /// redactor rewrites.
    pub(crate) fn mark_response(
        &self,
        input: &ResponseInput<'_>,
        mask: &mut [bool],
    ) {
        let Some(ac) = self.ac.as_ref() else {
            return;
        };
        let mut remaining = absent(mask);
        if remaining == 0 {
            return;
        }
        // Header values first, raw — `find_in_response` matches headers before
        // the body, so the gate must see them too. Every header, not only
        // those `inspect_header` admits, because a header-scoped rule reads
        // its own header raw.
        for (_name, value) in input.headers {
            scan(ac, &self.by_needle, value, mask, &mut remaining);
            if remaining == 0 {
                return;
            }
        }
        if let Some(body) = input.body_chunk {
            scan(ac, &self.by_needle, text_prefix(body), mask, &mut remaining);
        }
    }
}

/// How many gated rules the mask still reports absent.
fn absent(mask: &[bool]) -> usize {
    mask.iter().filter(|present| !**present).count()
}

/// Scan one field value in every form it could reach the origin as.
///
/// [`each_form`](crate::engine) is the same enumerator the matching path
/// uses, so the prescan cannot miss a form a rule matches in. The visitor
/// stops the walk once no gated rule remains absent — the remaining forms
/// cannot change the answer.
fn mark_field(
    ac: &AhoCorasick,
    by_needle: &[Vec<u32>],
    value: &str,
    mask: &mut [bool],
    remaining: &mut usize,
) {
    each_form(value, &mut |form| {
        scan(ac, by_needle, form, mask, remaining);
        *remaining == 0
    });
}

/// One overlapping scan of one form. Overlapping, because the ordinary
/// iterator resumes at each match's end and would hide a longer needle
/// sharing a start with a shorter one (`app` masking `append`) — a present
/// rule reported absent, the unsound direction.
fn scan(
    ac: &AhoCorasick,
    by_needle: &[Vec<u32>],
    form: &str,
    mask: &mut [bool],
    remaining: &mut usize,
) {
    if *remaining == 0 {
        return;
    }
    for found in ac.find_overlapping_iter(form) {
        for &rule in &by_needle[found.pattern().as_usize()] {
            let slot = &mut mask[rule as usize];
            if !*slot {
                *slot = true;
                *remaining -= 1;
                if *remaining == 0 {
                    return;
                }
            }
        }
    }
}

/// Build the shared automaton: ASCII-case-insensitive, standard match
/// semantics (the only kind that supports overlapping search). `None` on a
/// build failure — the caller degrades every rule to ungated, which costs
/// speed and never correctness.
fn build_automaton(needles: &[&str]) -> Option<AhoCorasick> {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(needles)
        .ok()
}

#[cfg(test)]
impl Prefilter {
    /// A gate that reports every rule present and scans nothing — the
    /// unfiltered engine, for equivalence testing.
    pub(crate) fn always(rule_count: usize) -> Self {
        Self {
            ac: None,
            by_needle: Vec::new(),
            ungated: vec![true; rule_count],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_words_collapse_to_one_needle() {
        // `(?i)union` expands to all 32 case variants; every variant lowers
        // to the same needle, so the collapsed set is one entry.
        assert_eq!(
            required_needles(r"(?i)union"),
            Some(vec!["union".to_string()])
        );
        // Twelve letters: 4096 variants, still under the extraction budget,
        // collapsing back to one needle.
        assert_eq!(
            required_needles(r"(?i)twelvecharwd"),
            Some(vec!["twelvecharwd".to_string()])
        );
    }

    #[test]
    fn alternation_yields_every_branch() {
        let needles =
            required_needles(r"(?i)(passthru|shell_exec)").expect("gated");
        assert!(needles.contains(&"passthru".to_string()));
        assert!(needles.contains(&"shell_exec".to_string()));
    }

    #[test]
    fn word_boundaries_do_not_void_the_gate() {
        // `\b` extracts as an empty literal that acts as an identity in the
        // cross product, so the final set is the word's variants — not the
        // degenerate always-present empty set.
        assert_eq!(
            required_needles(r"(?i)\bunion\b[\s(]+"),
            Some(vec!["union".to_string()])
        );
    }

    #[test]
    fn unbounded_shapes_are_ungated() {
        // A class too wide to expand, unanchored by any literal on either
        // side: no prefix, no suffix, no gate.
        assert_eq!(required_needles(r"[a-z]+"), None);
    }

    #[test]
    fn long_case_insensitive_words_degrade_to_a_capped_prefix() {
        // The case expansion of a long `(?i)` word exceeds the extraction
        // budget, and the extractor's own soundness-preserving answer is to
        // keep the accumulated 12-byte prefix as an inexact literal rather
        // than discard the gate. Every match still contains that prefix, so
        // the needle stays sound — the trim is the extractor's, not ours.
        assert_eq!(
            required_needles(r"(?i)twentythreecharacterslong"),
            Some(vec!["twentythreec".to_string()])
        );
    }

    #[test]
    fn case_folding_survives_into_the_needles() {
        // `(?i)shell` folds the long-s `ſ` (U+017F) into the class, so the
        // extracted set carries the `ſ`-variants alongside the ASCII ones.
        // They all lower to two needles, and the ASCII-case-insensitive
        // automaton fires the ASCII needle on every ASCII variant while the
        // `ſ` needle matches its own bytes.
        assert_eq!(
            required_needles(r"(?i)[a-z]+shell"),
            Some(vec!["shell".to_string(), "ſhell".to_string()])
        );
    }

    #[test]
    fn patterns_that_can_match_empty_are_ungated() {
        // An empty literal in the set means a zero-byte match path exists;
        // no needle can gate it, and dropping the empty literal would be
        // unsound, so the whole rule stays ungated.
        assert_eq!(required_needles(r"a*"), None);
        assert_eq!(required_needles(r"\b"), None);
        assert_eq!(required_needles(r"(union)?"), None);
    }

    #[test]
    fn fancy_only_constructs_are_ungated() {
        // Backreferences and lookaround are why the engine uses
        // `fancy-regex`; `regex-syntax` refuses them, which leaves the rule
        // ungated rather than wrongly gated.
        assert_eq!(required_needles(r"(\w+)\s+\1"), None);
        assert_eq!(required_needles(r"(?=.*passwd)"), None);
    }

    #[test]
    fn suffix_extraction_gates_patterns_a_prefix_cannot() {
        // Leading `\w+` makes the prefix set infinite; the trailing literal
        // still bounds the suffix set, so the suffix kind gates it.
        let needles = required_needles(r"\w+passwd").expect("suffix gates it");
        assert_eq!(needles, vec!["passwd".to_string()]);
    }

    #[test]
    fn native_detector_coverage_is_an_explicit_allowlist() {
        // A detector pattern with no usable needle set is ungated: it runs on
        // every request, paying full regex cost, forever. That is sometimes
        // the right answer — a pattern anchored by nothing literal cannot be
        // gated — but it must be a *known* answer. This test fails whenever a
        // pattern joins or leaves the ungated set, so the change is reviewed
        // rather than absorbed.
        use crate::categories::Category;
        let ungated: Vec<(Category, u32, String)> =
            crate::detectors::request_specs()
                .into_iter()
                .chain(crate::detectors::response_specs())
                .flat_map(|(category, specs)| {
                    specs.into_iter().filter_map(move |s| {
                        (required_needles(&s.pattern).is_none())
                            .then_some((category, s.offset, s.pattern))
                    })
                })
                .collect();
        // The reviewed exceptions, each literal-unbounded by construction:
        //
        // - data_leakage 65: a key name followed by a 16-or-more-char
        //   secret body. The key names are literal, but the trailing class
        //   repetition explodes every prefix set past the extraction cap,
        //   and the pattern ends unbounded, so no suffix set exists either.
        //   The secret body is the detection — bounding it would only find
        //   secrets whose characters were already known.
        // - web_shell 61: a passwd-shaped line. The username head and the
        //   path tail are both unbounded classes; the shape between them is
        //   the detection, and neither end can be bounded without losing
        //   real lines.
        let allowed = [(Category::DataLeakage, 65), (Category::WebShell, 61)];
        for (category, offset, pattern) in &ungated {
            eprintln!("ungated: {category} offset {offset} `{pattern}`");
        }
        let unexpected: Vec<_> = ungated
            .iter()
            .filter(|(c, o, _)| !allowed.contains(&(*c, *o)))
            .collect();
        assert!(
            unexpected.is_empty(),
            "{} native patterns are ungated outside the reviewed allowlist: \
             {unexpected:?}",
            unexpected.len()
        );
        // And the other direction: an allowlist entry whose pattern has since
        // gained a gate is stale. A stale entry would silently mask the next
        // pattern to lose its gate — the count would still look reviewed, so
        // the one new ungated pattern would be absorbed unnoticed.
        let stale: Vec<_> = allowed
            .iter()
            .filter(|entry| {
                !ungated.iter().any(|(c, o, _)| (*c, *o) == **entry)
            })
            .collect();
        assert!(
            stale.is_empty(),
            "allowlist entries whose patterns gained a gate: {stale:?}"
        );
        // And the gated majority must be real: a coverage test that passes
        // with everything ungated proves nothing.
        assert!(
            ungated.len()
                < crate::detectors::request_specs()
                    .into_iter()
                    .chain(crate::detectors::response_specs())
                    .map(|(_, s)| s.len())
                    .sum::<usize>()
                    / 2,
            "more than half the native ruleset is ungated"
        );
    }

    /// A [`Rule`](crate::rule::Rule) with a hand-set literal answer, for
    /// driving `Prefilter::build` without a pattern.
    struct FixedLiterals {
        literals: Option<Vec<String>>,
    }

    impl crate::rule::Rule for FixedLiterals {
        fn id(&self) -> crate::rule::RuleId {
            crate::rule::RuleId::native(1_000).expect("inside the native range")
        }
        fn category(&self) -> crate::categories::Category {
            crate::categories::Category::ProtocolEnforcement
        }
        fn severity(&self) -> crate::rule::Severity {
            crate::rule::Severity::Notice
        }
        fn required_literals(&self) -> Option<&[String]> {
            self.literals.as_deref()
        }
    }

    #[test]
    fn an_empty_literal_set_degrades_to_ungated_not_never_present() {
        // `required_needles` never answers an empty set, but the trait is
        // wider than its native implementors. A `Some(&[])` answer declares no
        // usable gate — no scan could ever mark the rule present — and gating
        // on zero needles would skip it on every input, the unsound
        // direction. It must degrade to ungated, like every other answer the
        // gate cannot use.
        let rules: Vec<Box<FixedLiterals>> = vec![
            Box::new(FixedLiterals {
                literals: Some(Vec::new()),
            }),
            Box::new(FixedLiterals { literals: None }),
        ];
        let gate = Prefilter::build(&rules);
        let mask = gate.present_mask();
        assert!(mask[0], "an empty set reads as ungated");
        assert!(mask[1], "None stays ungated");
    }

    #[test]
    fn overlapping_iteration_sees_needles_a_shorter_one_hides() {
        // The exact unsoundness `scan` exists to prevent: `app` and
        // `append` share a start, and a non-overlapping iterator would
        // report `app` and resume past `append`.
        let ac = build_automaton(&["app", "append"]).expect("builds");
        let mut mask = [false, false];
        let mut remaining = 2;
        scan(
            &ac,
            &[vec![0], vec![1]],
            "append",
            &mut mask,
            &mut remaining,
        );
        assert_eq!(mask, [true, true], "both needles must be seen");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn case_variants_fire_through_ascii_insensitivity() {
        // The automaton is ASCII-case-insensitive, so an uppercase haystack
        // fires the lowercased needle — and the Kelvin sign, which
        // `to_ascii_lowercase` leaves untouched, fires its own bytes.
        let ac = build_automaton(&["k", "\u{212a}"]).expect("builds");
        let mut mask = [false, false];
        let mut remaining = 2;
        scan(&ac, &[vec![0], vec![1]], "K", &mut mask, &mut remaining);
        assert!(mask[0], "ASCII K fires the k needle");
        let mut mask = [false, false];
        let mut remaining = 2;
        scan(
            &ac,
            &[vec![0], vec![1]],
            "\u{212a}",
            &mut mask,
            &mut remaining,
        );
        assert!(mask[1], "the Kelvin sign fires its own needle");
    }
}
