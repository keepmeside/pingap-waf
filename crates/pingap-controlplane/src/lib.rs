//! Control-plane store, RBAC, and notification delivery.
//!
//! Storage sits behind a repository trait so the driver stays swappable: Turso
//! is the choice, `rusqlite` on the same file format is the fallback the phase
//! 02 probe keeps open. Phase 12's email and Telegram notifiers land here as
//! `impl Notification` types rather than as edits to `pingap-webhook`.
//!
//! Filled in by phase 07, extended by phases 12 and 13.
