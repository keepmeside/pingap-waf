//! The config surface: what an operator writes, and every way it can be wrong.
//!
//! One test per rejection, each asserting the offending key appears in the message, because
//! a validation error that does not name the key sends the operator looking through the wrong
//! half of a config file. That is the whole reason this module exists separately from
//! `feed.rs`: a feed that is refused at fetch time is refused every cycle forever, silently
//! apart from a log line, whereas a feed refused at load time stops the process from starting
//! and tells the operator which character to change.

use std::time::Duration;

use pingap_intel::config::{ConfigError, IntelConf, plan};
use toml::Table;

/// Deserialises `[intel]` the way the WAF plugin does: from the sub-table of a plugin conf.
fn conf(toml_text: &str) -> IntelConf {
    let wrapper: Table = format!("[intel]\n{toml_text}")
        .parse()
        .expect("test TOML must parse");
    wrapper
        .get("intel")
        .expect("an [intel] table")
        .clone()
        .try_into()
        .expect("valid intel config")
}

fn entry<'a>(name: &'a str, conf: &'a IntelConf) -> (&'a str, &'a IntelConf) {
    (name, conf)
}

// --- the shape an operator writes

#[test]
fn a_declared_feed_becomes_a_definition() {
    let parsed = conf(
        "\
[[intel.feed]]
name = \"firehol\"
url = \"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset\"
category = \"scanner\"
",
    );
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.definitions.len(), 1);
    let definition = &planned.definitions[0];
    assert_eq!(definition.name, "firehol");
    assert_eq!(definition.category, "scanner");
    assert_eq!(definition.url.scheme(), "https");
    assert!(!definition.allow_private_targets);
}

#[test]
fn a_disabled_feed_is_not_planned() {
    let parsed = conf(
        "\
[[intel.feed]]
name = \"firehol\"
url = \"https://example.invalid/list\"
enabled = false
",
    );
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert!(
        planned.definitions.is_empty(),
        "a feed the operator switched off must not be fetched"
    );
}

#[test]
fn a_category_is_an_operator_label_and_is_not_checked_against_the_ruleset() {
    // `category` is surfaced in stats and in a block attribution so an operator can see *why*
    // a request was refused. It is deliberately free-form: validating it against the WAF's
    // rule categories would couple the intel crate to a rule engine it does not otherwise
    // know about, and would break every operator who groups feeds their own way.
    let parsed = conf(
        "\
[[intel.feed]]
name = \"a\"
url = \"https://example.invalid/a\"
category = \"my own grouping\"
",
    );
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.definitions[0].category, "my own grouping");
}

#[test]
fn an_absent_category_is_labelled_rather_than_empty() {
    let parsed = conf(
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\n",
    );
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.definitions[0].category, "unspecified");
}

#[test]
fn a_config_with_no_feed_key_plans_nothing_and_says_nothing() {
    // The criterion behind this: no feed is fetched that the operator did not configure. The
    // strongest form of that is a config which declares none — it must plan an empty set with
    // no error, so "nothing fetched" is the normal path and not a degenerate one.
    let parsed = conf("staleness = \"1h\"\n");
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert!(planned.definitions.is_empty());
    assert!(planned.manual.is_empty());
}

#[test]
fn no_plugin_entries_at_all_plans_nothing() {
    let planned = plan(std::iter::empty()).expect("a valid config");
    assert!(planned.definitions.is_empty());
}

// --- manual entries

#[test]
fn manual_entries_are_carried_into_the_plan_in_order() {
    let parsed = conf("manual = [\"1.2.3.4\", \"10.0.0.0/8\"]\n");
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.manual, ["1.2.3.4", "10.0.0.0/8"]);
}

#[test]
fn a_manual_entry_that_is_not_an_address_names_the_entry() {
    // Manual entries reach the same matcher as feed entries, and the matcher silently discards
    // what it cannot parse. Validating here is the only chance to tell the operator.
    let parsed = conf("manual = [\"evil.example.com\"]\n");
    let error = plan([entry("waf", &parsed)])
        .expect_err("a hostname is not an address");
    assert!(
        error.to_string().contains("evil.example.com"),
        "the offending value must be named: {error}"
    );
    assert!(
        error.to_string().contains("manual"),
        "the offending key must be named: {error}"
    );
}

#[test]
fn manual_entries_from_several_plugin_entries_are_merged_once_each() {
    let a = conf("manual = [\"1.1.1.1\", \"2.2.2.2\"]\n");
    let b = conf("manual = [\"2.2.2.2\", \"3.3.3.3\"]\n");
    let planned =
        plan([entry("a", &a), entry("b", &b)]).expect("a valid config");
    assert_eq!(planned.manual, ["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
}

// --- the node-global knobs

#[test]
fn the_limits_fall_back_to_the_documented_defaults() {
    let parsed = conf("");
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.limits.timeout, Duration::from_secs(30));
    assert_eq!(planned.limits.staleness, Duration::from_secs(24 * 3600));
    assert_eq!(planned.limits.max_body_bytes, 32 * 1024 * 1024);
    assert_eq!(planned.limits.max_entries, 250_000);
    assert_eq!(
        planned.limits.redirect_hops, 0,
        "follows no redirect by default"
    );
}

#[test]
fn durations_are_written_as_humantime() {
    let parsed = conf("timeout = \"5s\"\nstaleness = \"2h\"\n");
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.limits.timeout, Duration::from_secs(5));
    assert_eq!(planned.limits.staleness, Duration::from_secs(7200));
}

#[test]
fn a_number_of_bytes_is_written_as_a_number() {
    let parsed = conf("max_body_bytes = 1048576\nmax_entries = 5000\n");
    let planned = plan([entry("waf", &parsed)]).expect("a valid config");
    assert_eq!(planned.limits.max_body_bytes, 1_048_576);
    assert_eq!(planned.limits.max_entries, 5_000);
}

#[test]
fn the_strictest_of_several_declarations_wins() {
    // Feed content is node-global, so two plugin entries describing the same feed must agree
    // on the limits it is fetched under. Taking the minimum means a single entry that asks for
    // a tighter bound gets it, and one that asks for a looser one does not widen the node.
    let loose = conf(
        "timeout = \"30s\"\nstaleness = \"48h\"\nmax_body_bytes = 8388608\n",
    );
    let tight = conf(
        "timeout = \"5s\"\nstaleness = \"1h\"\nmax_body_bytes = 1048576\n",
    );
    let planned = plan([entry("loose", &loose), entry("tight", &tight)])
        .expect("a valid config");
    assert_eq!(planned.limits.timeout, Duration::from_secs(5));
    assert_eq!(planned.limits.staleness, Duration::from_secs(3600));
    assert_eq!(planned.limits.max_body_bytes, 1_048_576);
}

#[test]
fn one_entry_narrowing_a_limit_narrows_it_for_the_node() {
    let unset = conf("");
    let narrowed = conf("max_entries = 100\n");
    let planned = plan([entry("a", &unset), entry("b", &narrowed)])
        .expect("a valid config");
    assert_eq!(planned.limits.max_entries, 100);
}

// --- the same feed declared twice

#[test]
fn the_same_feed_declared_identically_by_two_entries_is_fetched_once() {
    // Per-policy *selection* means two policies routinely select the same feed. Fetching it
    // twice would double the request rate against the publisher for no gain.
    let text =
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\n";
    let first = conf(text);
    let second = conf(text);
    let planned = plan([entry("one", &first), entry("two", &second)])
        .expect("a valid config");
    assert_eq!(planned.definitions.len(), 1);
    assert_eq!(planned.definitions[0].name, "a");
}

#[test]
fn the_same_name_pointing_at_two_urls_is_refused() {
    // Security-relevant: if this were allowed, which feed a policy enforces would depend on
    // plugin iteration order, and a request could be blocked by a list nobody configured.
    let first =
        conf("[[intel.feed]]\nname = \"a\"\nurl = \"https://one.invalid/a\"\n");
    let second =
        conf("[[intel.feed]]\nname = \"a\"\nurl = \"https://two.invalid/a\"\n");
    let error = plan([entry("one", &first), entry("two", &second)])
        .expect_err("a conflict");
    let message = error.to_string();
    assert!(message.contains("one"), "names the first entry: {message}");
    assert!(message.contains("two"), "names the second entry: {message}");
    assert!(
        message.contains("https://one.invalid/a")
            && message.contains("https://two.invalid/a"),
        "names both URLs so the operator can see the disagreement: {message}"
    );
}

#[test]
fn the_same_name_with_different_categories_is_refused() {
    let first = conf(
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\ncategory = \"scanner\"\n",
    );
    let second = conf(
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\ncategory = \"botnet\"\n",
    );
    let error = plan([entry("one", &first), entry("two", &second)])
        .expect_err("a conflict");
    assert!(error.to_string().contains("category"), "{}", error);
}

#[test]
fn the_same_name_with_different_opt_outs_is_refused() {
    // The opt-out is a widening of what the egress guard will reach. Letting one entry widen
    // it for the whole node would make `allow_private_targets` a global switch that no one
    // chose globally.
    let strict = conf(
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\n",
    );
    let permissive = conf(
        "[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\nallow_private_targets = true\n",
    );
    let error =
        plan([entry("strict", &strict), entry("permissive", &permissive)])
            .expect_err("a conflict");
    assert!(
        error.to_string().contains("allow_private_targets"),
        "{}",
        error
    );
}

// --- what must be refused at load

#[test]
fn a_feed_without_a_name_is_refused() {
    let parsed = conf("[[intel.feed]]\nurl = \"https://example.invalid/a\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a nameless feed");
    let message = error.to_string();
    assert!(message.contains("intel: "), "prefixed: {message}");
    assert!(message.contains("name"), "names the key: {message}");
    assert!(message.contains("waf"), "names the plugin entry: {message}");
}

#[test]
fn a_blank_feed_name_is_refused() {
    let parsed = conf(
        "[[intel.feed]]\nname = \"   \"\nurl = \"https://example.invalid/a\"\n",
    );
    let error = plan([entry("waf", &parsed)]).expect_err("a blank name");
    assert!(error.to_string().contains("name"), "{}", error);
}

#[test]
fn a_feed_without_a_url_is_refused() {
    let parsed = conf("[[intel.feed]]\nname = \"a\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a URL-less feed");
    assert!(error.to_string().contains("url"), "{}", error);
}

#[test]
fn a_url_that_does_not_parse_is_refused() {
    let parsed = conf("[[intel.feed]]\nname = \"a\"\nurl = \"not a url\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("an unparsable URL");
    let message = error.to_string();
    assert!(message.contains("not a url"), "names the value: {message}");
    assert!(message.contains("url"), "names the key: {message}");
}

#[test]
fn a_file_url_is_refused() {
    // A feed path that reads from the local filesystem turns a config key into arbitrary file
    // read, and there is no egress guard that can police it because there is no network
    // boundary to police it at.
    let parsed =
        conf("[[intel.feed]]\nname = \"a\"\nurl = \"file:///etc/passwd\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a file URL");
    assert!(error.to_string().contains("http"), "{}", error);
}

#[test]
fn two_feeds_in_one_entry_sharing_a_name_is_refused() {
    let parsed = conf(
        "\
[[intel.feed]]
name = \"a\"
url = \"https://one.invalid/a\"
[[intel.feed]]
name = \"a\"
url = \"https://two.invalid/a\"
",
    );
    let error = plan([entry("waf", &parsed)])
        .expect_err("a duplicate inside one entry");
    assert!(error.to_string().contains("a"), "{}", error);
}

#[test]
fn a_zero_body_cap_is_refused() {
    // Zero would refuse every feed on every cycle, which looks like a broken publisher rather
    // than a broken config.
    let parsed = conf("max_body_bytes = 0\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a zero cap");
    assert!(error.to_string().contains("max_body_bytes"), "{}", error);
}

#[test]
fn a_zero_entry_cap_is_refused() {
    let parsed = conf("max_entries = 0\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a zero cap");
    assert!(error.to_string().contains("max_entries"), "{}", error);
}

#[test]
fn a_zero_timeout_is_refused() {
    let parsed = conf("timeout = \"0s\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a zero timeout");
    assert!(error.to_string().contains("timeout"), "{}", error);
}

#[test]
fn a_zero_staleness_is_refused() {
    // `staleness = 0` would drop every retained contribution the cycle after a single failed
    // fetch, defeating the retention the window exists for. It is refused rather than accepted
    // as "no retention", because the operator who writes it almost certainly means something
    // else.
    let parsed = conf("staleness = \"0s\"\n");
    let error = plan([entry("waf", &parsed)]).expect_err("a zero window");
    assert!(error.to_string().contains("staleness"), "{}", error);
}

#[test]
fn a_hop_count_beyond_the_ceiling_is_refused() {
    // Each hop is a new connection the egress guard has to police, and each one is an
    // opportunity for a redirect to point at an internal address. The ceiling is generous
    // enough for any real publisher and low enough that a redirect loop cannot be used to
    // hold the refresh cycle.
    let parsed = conf("redirect_hops = 100\n");
    let error = plan([entry("waf", &parsed)]).expect_err("too many hops");
    assert!(error.to_string().contains("redirect_hops"), "{}", error);
}

#[test]
fn an_unknown_key_inside_intel_is_refused() {
    // A typo in a security control must not pass. `enable = false` on a feed whose key is
    // `enabled` would otherwise silently leave the feed running.
    let wrapper = "[intel]\nenable = false\n"
        .parse::<Table>()
        .expect("parses");
    let error = wrapper
        .get("intel")
        .expect("an [intel] table")
        .clone()
        .try_into::<IntelConf>()
        .expect_err("an unknown key");
    assert!(error.to_string().contains("enable"), "{}", error);
}

#[test]
fn an_unknown_key_inside_a_feed_is_refused() {
    let wrapper = "[intel]\n[[intel.feed]]\nname = \"a\"\nurl = \"https://example.invalid/a\"\nenabled = true\nallow_private = true\n"
        .parse::<Table>()
        .expect("parses");
    let error = wrapper
        .get("intel")
        .expect("an [intel] table")
        .clone()
        .try_into::<IntelConf>()
        .expect_err("an unknown key");
    assert!(error.to_string().contains("allow_private"), "{}", error);
}

// --- the error type

#[test]
fn every_rejection_names_the_plugin_entry_it_came_from() {
    let parsed = conf(
        "[[intel.feed]]\nname = \"\"\nurl = \"https://example.invalid/a\"\n",
    );
    match plan([entry("the-profile", &parsed)]) {
        Err(ConfigError::BadFeed { entry, .. }) => {
            assert_eq!(entry, "the-profile");
        },
        other => panic!("expected BadFeed, got {other:?}"),
    }
}

#[test]
fn the_manual_entry_error_carries_the_plugin_entry_too() {
    let parsed = conf("manual = [\"nope\"]\n");
    match plan([entry("the-profile", &parsed)]) {
        Err(ConfigError::BadManual { entry, index, .. }) => {
            assert_eq!(entry, "the-profile");
            assert_eq!(index, 0);
        },
        other => panic!("expected BadManual, got {other:?}"),
    }
}
