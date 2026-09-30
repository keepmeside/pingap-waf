//! The line parser: one feed body in, a validated entry list and an honest set of counts
//! out.
//!
//! Table-driven, one test per line shape, because the failure mode this guards against is a
//! shape that silently stops being understood. A loop over a list of inputs would report
//! "3 of 12 failed"; one test per shape reports "the DShield line stopped contributing".
//!
//! The counts are the point of the module and not a detail of it. A malformed line in a
//! threat feed is a *narrowing of coverage*, and the only way an operator can tell "this
//! feed returned nothing" from "this feed returned 40,000 lines we could not read" is if the
//! parser counts them separately. `dropped` is therefore a first-class output, asserted here
//! as often as `entries` is.

use pingap_intel::parse::Parsed;

/// Parses a body with a cap high enough not to interfere, so a test that does not mention
/// truncation cannot be accidentally testing it.
fn parse(body: &str) -> Parsed {
    Parsed::parse(body, 10_000)
}

fn entries(body: &str) -> Vec<String> {
    parse(body).entries().to_vec()
}

// --- the shapes a feed actually uses

#[test]
fn a_bare_ipv4_address_is_accepted() {
    assert_eq!(entries("93.184.216.34\n"), ["93.184.216.34"]);
    let parsed = parse("93.184.216.34\n");
    assert_eq!(parsed.dropped(), 0);
    assert_eq!(parsed.skipped(), 0);
}

#[test]
fn a_bare_ipv6_address_is_accepted() {
    assert_eq!(entries("2606:4700:4700::1111\n"), ["2606:4700:4700::1111"]);
    assert_eq!(parse("2606:4700:4700::1111\n").dropped(), 0);
}

#[test]
fn a_cidr_network_is_accepted() {
    assert_eq!(entries("185.220.101.0/24\n"), ["185.220.101.0/24"]);
    assert_eq!(entries("2001:db8::/32\n"), ["2001:db8::/32"]);
    assert_eq!(parse("185.220.101.0/24\n").dropped(), 0);
}

#[test]
fn a_host_address_is_accepted_as_written() {
    // `1.2.3.4/32` is a network that contains exactly one address, and it is stored as a
    // network rather than normalised to a bare address. Both forms are legitimate in a feed
    // and both have to survive, which is why deduplication is on the text and not on the
    // value.
    assert_eq!(entries("1.2.3.4\n1.2.3.4/32\n"), ["1.2.3.4", "1.2.3.4/32"]);
    assert_eq!(parse("1.2.3.4\n1.2.3.4/32\n").dropped(), 0);
}

// --- comments and blanks

#[test]
fn a_hash_comment_header_block_is_skipped_and_is_not_a_drop() {
    let body = "\
# Feeds example.com blocklist
# Generated: 2026-09-13T00:00:00Z
# License: CC-BY-4.0
93.184.216.34
";
    let parsed = parse(body);
    assert_eq!(parsed.entries(), ["93.184.216.34"]);
    assert_eq!(parsed.skipped(), 3, "the header is not a fault in the feed");
    assert_eq!(parsed.dropped(), 0);
}

#[test]
fn a_semicolon_comment_header_block_is_skipped_and_is_not_a_drop() {
    let parsed = parse("; version 2\n; contact abuse@example.com\n1.1.1.1\n");
    assert_eq!(parsed.entries(), ["1.1.1.1"]);
    assert_eq!(parsed.skipped(), 2);
    assert_eq!(parsed.dropped(), 0);
}

#[test]
fn a_trailing_hash_comment_is_stripped_from_the_entry() {
    assert_eq!(
        entries("93.184.216.34 # example.com, seen 2026-09-13\n"),
        ["93.184.216.34"]
    );
    assert_eq!(
        parse("93.184.216.34 # example.com\n").dropped(),
        0,
        "a commented entry is not a malformed one"
    );
}

#[test]
fn a_trailing_semicolon_comment_is_stripped_from_the_entry() {
    assert_eq!(
        entries("93.184.216.34;score=87;firstseen=2026-01-01\n"),
        ["93.184.216.34"]
    );
    assert_eq!(parse("93.184.216.34;score=87\n").dropped(), 0);
}

#[test]
fn both_comment_markers_on_one_line_are_stripped() {
    assert_eq!(entries("1.2.3.4 ; note # more\n"), ["1.2.3.4"]);
}

#[test]
fn blank_and_whitespace_only_lines_are_skipped() {
    let parsed = parse("\n93.184.216.34\n\n   \n\t\n1.1.1.1\n\n");
    assert_eq!(parsed.entries(), ["93.184.216.34", "1.1.1.1"]);
    assert_eq!(parsed.skipped(), 5);
    assert_eq!(parsed.dropped(), 0);
}

#[test]
fn an_empty_body_parses_to_nothing_and_is_not_an_error() {
    let parsed = parse("");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 0);
    assert_eq!(parsed.skipped(), 0);
    assert!(!parsed.truncated());
    assert!(parsed.rules().is_empty());
}

#[test]
fn crlf_line_endings_are_handled() {
    // A feed served from Windows, or through a proxy that normalised nothing. The carriage
    // return must not survive into the candidate, or every entry in the feed would fail to
    // parse and the whole body would be counted as dropped.
    let parsed = parse("93.184.216.34\r\n1.1.1.1\r\n# comment\r\n");
    assert_eq!(parsed.entries(), ["93.184.216.34", "1.1.1.1"]);
    assert_eq!(parsed.dropped(), 0);
    assert_eq!(parsed.skipped(), 1);
}

// --- the multi-column formats

#[test]
fn a_tab_separated_dshield_line_contributes_its_start_address() {
    // The DShield format is `start<TAB>end<TAB>count`. Taking the first field is the ported
    // behaviour and it is a real limitation: a range covering 256 addresses contributes one.
    // Under-blocking part of a range from one feed is documented, not silent — which is why
    // this asserts the exact single entry rather than merely "something was accepted".
    let parsed = parse("10.0.0.0\t10.0.0.255\t42\n");
    assert_eq!(parsed.entries(), ["10.0.0.0"]);
    assert_eq!(
        parsed.dropped(),
        0,
        "the line was understood, just not in full"
    );
}

#[test]
fn a_space_separated_csv_style_line_contributes_its_first_field() {
    assert_eq!(entries("93.184.216.34 example.com 87\n"), ["93.184.216.34"]);
}

#[test]
fn leading_whitespace_does_not_displace_the_entry() {
    assert_eq!(entries("   93.184.216.34\n"), ["93.184.216.34"]);
}

// --- what must not be accepted

#[test]
fn a_hostname_is_dropped_and_counted() {
    // Security-relevant: a feed that returns names instead of addresses must be *visibly*
    // not applied. Accepting a name would mean resolving it on the request hot path, and
    // dropping it silently would mean an operator believing a feed is protecting them.
    let parsed = parse("evil.example.com\nblocked.test\n");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 2);
}

#[test]
fn an_address_with_a_port_suffix_is_dropped_and_counted() {
    let parsed = parse("93.184.216.34:8080\n");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 1);
}

#[test]
fn an_out_of_range_octet_is_dropped_and_counted() {
    let parsed = parse("999.1.1.1\n1.2.3.256\n");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 2);
}

#[test]
fn an_out_of_range_prefix_is_dropped_and_counted() {
    let parsed = parse("10.0.0.0/33\n2001:db8::/129\n");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 2);
}

#[test]
fn a_json_body_is_dropped_line_by_line_and_counted() {
    // The realistic shape of a misconfigured feed URL: an API endpoint returning JSON
    // rather than a blocklist. Every line is malformed, nothing is accepted, and the count
    // says so loudly.
    let parsed =
        parse("{\n  \"indicators\": [\n    {\"ip\": \"1.2.3.4\"}\n  ]\n}\n");
    assert!(parsed.entries().is_empty());
    assert_eq!(parsed.dropped(), 5);
}

#[test]
fn a_malformed_line_does_not_disturb_the_valid_ones() {
    let parsed = parse(
        "\
93.184.216.34
not-an-address
185.220.101.0/24
# a comment
,,,
1.1.1.1
",
    );
    assert_eq!(
        parsed.entries(),
        ["93.184.216.34", "185.220.101.0/24", "1.1.1.1"]
    );
    assert_eq!(parsed.dropped(), 2);
    assert_eq!(parsed.skipped(), 1);
}

// --- duplicates

#[test]
fn a_repeated_entry_is_collapsed_and_is_not_counted_as_a_drop() {
    // Feeds repeat themselves constantly. Counting a repeat as a drop would make the
    // dropped count meaningless, because the largest feeds would look the most broken.
    let parsed = parse("1.2.3.4\n1.2.3.4\n1.2.3.4\n5.6.7.8\n");
    assert_eq!(parsed.entries(), ["1.2.3.4", "5.6.7.8"]);
    assert_eq!(parsed.duplicates(), 2);
    assert_eq!(parsed.dropped(), 0, "collapsing a repeat narrows nothing");
}

#[test]
fn a_repeated_network_is_collapsed_and_is_not_counted_as_a_drop() {
    let parsed = parse("10.0.0.0/8\n10.0.0.0/8\n");
    assert_eq!(parsed.entries(), ["10.0.0.0/8"]);
    assert_eq!(parsed.duplicates(), 1);
    assert_eq!(parsed.dropped(), 0);
}

// --- the cap

#[test]
fn the_entry_cap_keeps_the_leading_entries_in_feed_order_and_reports_truncation()
 {
    // Feed order, not an arbitrary end: a cap applied to a hash set's iteration order would
    // make which addresses are enforced depend on a hasher's seed, and two runs of the same
    // feed would block different traffic.
    let body = "1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n5.5.5.5\n";
    let parsed = Parsed::parse(body, 3);
    assert_eq!(parsed.entries(), ["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    assert!(parsed.truncated());
    assert_eq!(
        parsed.dropped(),
        0,
        "truncation is reported, not folded into drops"
    );
}

#[test]
fn a_body_inside_the_cap_is_not_reported_as_truncated() {
    assert!(!Parsed::parse("1.1.1.1\n2.2.2.2\n", 2).truncated());
    assert!(!Parsed::parse("1.1.1.1\n", 100).truncated());
}

#[test]
fn a_cap_of_zero_accepts_nothing_and_says_it_was_truncated() {
    // Degenerate, and config validation refuses it, but the behaviour has to be coherent
    // rather than a divide-by-nothing surprise.
    let parsed = Parsed::parse("1.1.1.1\n2.2.2.2\n", 0);
    assert!(parsed.entries().is_empty());
    assert!(parsed.truncated());
    assert_eq!(parsed.dropped(), 0);
}

#[test]
fn a_dropped_line_before_the_cap_still_consumes_no_cap_room() {
    // Otherwise a feed with a malformed header would silently enforce one address fewer than
    // the operator configured.
    let parsed = Parsed::parse("garbage\n1.1.1.1\n2.2.2.2\n", 2);
    assert_eq!(parsed.entries(), ["1.1.1.1", "2.2.2.2"]);
    assert!(!parsed.truncated());
    assert_eq!(parsed.dropped(), 1);
}

// --- the length check

#[test]
fn every_accepted_entry_is_in_the_compiled_matcher() {
    // `IpRules::new` discards what it cannot parse and reports nothing, so this comparison
    // is the only thing standing between a feed and a silent narrowing of coverage. It is
    // asserted here as a property of the parser rather than left to a caller to remember.
    let body = "\
93.184.216.34
185.220.101.0/24
2606:4700:4700::1111
2001:db8::/32
1.2.3.4/32
# comment

93.184.216.34
nonsense
";
    let parsed = parse(body);
    assert_eq!(parsed.rules().len(), parsed.entries().len());
    assert_eq!(parsed.entries().len(), 5);
    assert_eq!(parsed.dropped(), 1);
    assert_eq!(parsed.skipped(), 2);
    assert_eq!(parsed.duplicates(), 1);
}

#[test]
fn the_compiled_matcher_refuses_what_the_feed_listed() {
    let parsed = parse("93.184.216.34\n185.220.101.0/24\n");
    assert!(
        parsed
            .rules()
            .is_match("93.184.216.34")
            .expect("a valid address")
    );
    assert!(
        parsed
            .rules()
            .is_match("185.220.101.77")
            .expect("a valid address")
    );
    assert!(!parsed.rules().is_match("8.8.8.8").expect("a valid address"));
}

#[test]
fn an_unparsable_address_cannot_reach_the_matcher_through_a_rejected_lookup() {
    // `IpRules::is_match` returns `Err` for a string that is not an address, and the deny
    // decision reads that as "not matched" — fail-closed against the *feed*, consistent with
    // the static filter. Asserted so the reading is recorded rather than inherited.
    let parsed = parse("1.2.3.4\n");
    assert!(parsed.rules().is_match("nonsense").is_err());
    assert!(parsed.rules().is_match("1.2.3.4").expect("a valid address"));
}
