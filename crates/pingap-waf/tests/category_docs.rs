//! The published CRS lineage table is part of the contract, so it is checked
//! against the code rather than trusted to stay in sync.
//!
//! Documentation drift here is not cosmetic: the table is what an operator uses to
//! find the upstream CRS rules a category corresponds to. A wrong group number
//! sends them to the wrong file.

use pingap_waf::Category;

const DOC: &str = include_str!("../../../docs/waf-category-mapping.md");

/// The row for one category, as a whole line, so the assertions below can check
/// that the key, group, file, and surface all agree *on the same row* — matching
/// them independently would pass even if two rows had swapped fields.
fn row_for(c: Category) -> &'static str {
    DOC.lines()
        .find(|l| l.starts_with(&format!("| `{}` |", c.key())))
        .unwrap_or_else(|| panic!("no table row for category `{}`", c.key()))
}

#[test]
fn every_category_has_a_row_naming_its_group_file_and_surface() {
    for c in Category::ALL {
        let row = row_for(c);
        assert!(
            row.contains(&c.crs_group().to_string()),
            "row for `{}` does not name group {}: {row}",
            c.key(),
            c.crs_group()
        );
        assert!(
            row.contains(c.crs_file()),
            "row for `{}` does not name {}: {row}",
            c.key(),
            c.crs_file()
        );
        let surface = if c.is_response_side() {
            "response"
        } else {
            "request"
        };
        assert!(
            row.trim_end().ends_with(&format!("| {surface} |")),
            "row for `{}` should end on surface `{surface}`: {row}",
            c.key()
        );
    }
}

#[test]
fn the_table_lists_exactly_the_categories_that_exist() {
    // A row for a category that was removed is as misleading as a missing row for
    // one that was added. The `.conf` filename is what makes a row a lineage row —
    // the file has other tables (rule ID ranges, severities) whose rows also start
    // with a code span.
    let rows = DOC
        .lines()
        .filter(|l| l.starts_with("| `") && l.contains(".conf`"))
        .count();
    assert_eq!(
        rows,
        Category::ALL.len(),
        "the lineage table has {rows} rows for {} categories",
        Category::ALL.len()
    );
}

#[test]
fn the_document_states_that_response_side_cannot_block() {
    // The single most load-bearing sentence in the file: an operator who thinks
    // `redact` denies a response has been misled about their security posture.
    let lowered = DOC.to_lowercase();
    assert!(
        lowered.contains("never `block`") || lowered.contains("never block"),
        "the response-side prohibition must be stated explicitly"
    );
    assert!(
        lowered.contains("rejected at config validation"),
        "the document must say the impossibility is enforced, not just described"
    );
}

#[test]
fn the_document_records_the_id_ranges_the_code_uses() {
    assert!(
        DOC.contains("1_000_000"),
        "the custom-rule floor must be published"
    );
    assert_eq!(
        pingap_waf::CUSTOM_RULE_ID_BASE,
        1_000_000,
        "code and published table disagree on the custom-rule floor"
    );
    // Highest native ID, derived from the highest CRS group.
    let max = Category::ALL
        .iter()
        .map(|c| c.id_range().1)
        .max()
        .expect("non-empty");
    assert!(max < pingap_waf::CUSTOM_RULE_ID_BASE);
}
