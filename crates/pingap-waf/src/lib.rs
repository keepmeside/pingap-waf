//! WAF rule engine and detectors.
//!
//! Native Rust rule matching with CRS-category parity. No libmodsecurity, no
//! SecLang, and no C++ in the request path, so the musl static build survives.
//!
//! Filled in by phases 03 (engine) and 04 (detectors ported from pingora-waf).
