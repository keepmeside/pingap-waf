//! JA4H checked against an independent implementation, not against itself.
//!
//! Every vector below is a real request/fingerprint pair from FoxIO's own committed pcap
//! fixtures (`python/test/testdata/http1.pcapng.json` and `http1-with-cookies.pcapng.json`
//! in `FoxIO-LLC/ja4`, fetched 2026-09-03). The `JA4H_ro` field in those fixtures records
//! the header names in the order sent, which is what makes them usable as inputs rather
//! than only as format examples.
//!
//! **That distinction is the reason this file exists.** The phase plan proposed using
//! nginx-love's committed fingerprint values (`ge11nn030000_b51846f30ce9`) as fixtures.
//! Those are log-parser samples with no recorded request, so they validate the *shape* of
//! a fingerprint and nothing about its canonicalisation — the identical defect the Phase
//! 02 JA4 spike recorded for its own vectors. An attempt to reproduce
//! `b51846f30ce9` by searching plausible three-header sets across three casings found no
//! preimage, which is the expected outcome and not a discrepancy: without the originating
//! request there is nothing to check against.

use pingap_bot::ja4h::{RequestHead, Version, ja4h};

/// One fixture: the fingerprint FoxIO computed, and the request that produced it.
struct Vector {
    expected: &'static str,
    method: &'static str,
    version: Version,
    /// In the order sent, original case, including `Cookie` and `Referer` when present.
    headers: &'static [&'static str],
    cookie: Option<&'static str>,
    accept_language: Option<&'static str>,
}

const VECTORS: &[Vector] = &[
    Vector {
        expected: "po11nn050000_530ceba2075f_000000000000_000000000000",
        method: "POST",
        version: Version::Http11,
        headers: &[
            "Host",
            "Accept",
            "User-Agent",
            "Content-Type",
            "Content-Length",
        ],
        cookie: None,
        accept_language: None,
    },
    Vector {
        expected: "he11nn05enus_6f8992deff94_000000000000_000000000000",
        method: "HEAD",
        version: Version::Http11,
        headers: &[
            "Host",
            "Connection",
            "User-Agent",
            "Accept-Encoding",
            "Accept-Language",
        ],
        cookie: None,
        accept_language: Some("en-US"),
    },
    Vector {
        expected: "ge11nn040000_ad0fd3707af2_000000000000_000000000000",
        method: "GET",
        version: Version::Http11,
        headers: &["Host", "User-Agent", "Accept", "Range"],
        cookie: None,
        accept_language: None,
    },
    // The next two differ only in method, so together they prove `a` and `b` are
    // computed independently rather than one being derived from the other.
    Vector {
        expected: "ge11nn040000_4f6f4aad0c1e_000000000000_000000000000",
        method: "GET",
        version: Version::Http11,
        headers: &["User-Agent", "Host", "Connection", "Accept-Encoding"],
        cookie: None,
        accept_language: None,
    },
    Vector {
        expected: "he11nn040000_4f6f4aad0c1e_000000000000_000000000000",
        method: "HEAD",
        version: Version::Http11,
        headers: &["User-Agent", "Host", "Connection", "Accept-Encoding"],
        cookie: None,
        accept_language: None,
    },
    Vector {
        expected: "ge11nn050000_e1365771aae9_000000000000_000000000000",
        method: "GET",
        version: Version::Http11,
        headers: &[
            "Host",
            "Date",
            "User-Agent",
            "X-AV-Physical-Unit-Info",
            "X-AV-Client-Info",
        ],
        cookie: None,
        accept_language: None,
    },
    // Same four header names as the `4f6f4aad0c1e` pair, in a different order, and a
    // different hash. This is the vector that would catch a sorted-names mistake.
    Vector {
        expected: "ge11nn040000_532a1ee47909_000000000000_000000000000",
        method: "GET",
        version: Version::Http11,
        headers: &["Host", "User-Agent", "Connection", "Accept-Encoding"],
        cookie: None,
        accept_language: None,
    },
    Vector {
        expected: "ge11nn030000_f8649f6808db_000000000000_000000000000",
        method: "GET",
        version: Version::Http11,
        headers: &["Host", "Connection", "User-Agent"],
        cookie: None,
        accept_language: None,
    },
    Vector {
        expected: "po11nn080000_6977d1188c03_000000000000_000000000000",
        method: "POST",
        version: Version::Http11,
        headers: &[
            "Host",
            "User-Agent",
            "Content-Length",
            "Content-Type",
            "SOAPAction",
            "Connection",
            "Cache-Control",
            "Pragma",
        ],
        cookie: None,
        accept_language: None,
    },
    // Cookies and a referer. `Cookie` and `Referer` appear in the header list and must
    // be excluded from both the count (`04`) and the header hash, while still setting
    // the `c` and `r` flags.
    Vector {
        expected: "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442",
        method: "GET",
        version: Version::Http11,
        headers: &[
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Cookie",
            "Referer",
        ],
        cookie: Some("yummy_cookie=choco; tasty_cookie=strawberry"),
        accept_language: Some("da, en-gb;q=0.8, en;q=0.7"),
    },
];

fn compute(v: &Vector) -> String {
    let mut head = RequestHead::new(v.method, v.version, v.headers);
    head.cookie = v.cookie;
    head.accept_language = v.accept_language;
    ja4h(&head)
}

#[test]
fn every_reference_vector_is_reproduced_exactly() {
    for v in VECTORS {
        assert_eq!(
            compute(v),
            v.expected,
            "canonicalisation diverges from the reference for {} {:?}",
            v.method,
            v.headers
        );
    }
}

#[test]
fn the_same_client_fingerprints_identically_every_time() {
    let v = &VECTORS[0];
    let first = compute(v);
    for _ in 0..50 {
        assert_eq!(compute(v), first);
    }
}

#[test]
fn header_order_changes_the_fingerprint() {
    // Vectors 3 and 6 carry the same four header names in different orders and FoxIO
    // gives them different hashes. A sorted or `HeaderMap`-derived order would collapse
    // them, which is precisely the silent failure the HTTP/2 guard exists to prevent.
    let reordered = compute(&VECTORS[3]);
    let as_sent = compute(&VECTORS[6]);
    assert_ne!(
        reordered, as_sent,
        "two orders of the same header set produced one fingerprint"
    );
}

#[test]
fn materially_different_clients_differ() {
    let mut seen = std::collections::BTreeSet::new();
    for v in VECTORS {
        seen.insert(compute(v));
    }
    // All ten are distinct, including the `4f6f4aad0c1e` pair: they share the header
    // hash but differ in method, and the method is part of the fingerprint. Asserting
    // the exact count rather than "more than one" is what would catch a component
    // silently dropping out of the format.
    assert_eq!(
        seen.len(),
        VECTORS.len(),
        "two different clients collapsed onto one fingerprint: {seen:?}"
    );
}
