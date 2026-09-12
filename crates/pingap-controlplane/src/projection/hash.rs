//! Canonical serialisation and content hashing.
//!
//! The hash is over the *canonical* form, not the file bytes, so reformatting cannot
//! produce a false drift signal — and it is assembled in sorted order because
//! `PingapConfig` holds `HashMap`s, whose iteration order would otherwise reach the
//! output and make two generations of one intent hash differently.
//!
//! Deliberately not `PingapConfig::hash`. That one is crc32 over a description list with
//! certificate and storage secrets folded to their own crc32 — right for its purpose
//! (change detection between two in-process configs) and wrong for this one, where the
//! hash is a durable record in `config_versions` that a later drift check compares
//! against. A 32-bit checksum with a documented collision rate is not what to write into
//! an audit trail.

use super::{Projected, ProjectionError, Result};
use pingap_config::PingapConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

fn to_value<T: Serialize>(value: &T) -> Result<toml::Value> {
    toml::Value::try_from(value).map_err(|e| ProjectionError::Serialise {
        reason: e.to_string(),
    })
}

/// One category's entries, in name order.
fn sorted_table<T: Serialize>(
    items: &HashMap<String, T>,
) -> Result<toml::Table> {
    let mut out = toml::Table::new();
    // Collected into a `BTreeSet` rather than sorted in place: the point is that no code
    // path here can observe the source map's order.
    for name in items.keys().collect::<BTreeSet<_>>() {
        let value =
            items.get(name).ok_or_else(|| ProjectionError::Serialise {
                reason: format!(
                    "`{name}` vanished between key listing and lookup"
                ),
            })?;
        out.insert(name.clone(), to_value(value)?);
    }
    Ok(out)
}

/// The config as one deterministic TOML document.
///
/// Empty categories are omitted rather than emitted as empty tables, so adding the first
/// entry to a category is a content change and not also a structural one.
pub fn canonical_toml(config: &PingapConfig) -> Result<String> {
    let mut root = toml::Table::new();
    root.insert("basic".to_string(), to_value(&config.basic)?);
    for (name, table) in [
        ("upstreams", sorted_table(&config.upstreams)?),
        ("locations", sorted_table(&config.locations)?),
        ("servers", sorted_table(&config.servers)?),
        ("plugins", sorted_table(&config.plugins)?),
        ("certificates", sorted_table(&config.certificates)?),
        ("storages", sorted_table(&config.storages)?),
    ] {
        if !table.is_empty() {
            root.insert(name.to_string(), toml::Value::Table(table));
        }
    }
    toml::to_string_pretty(&root).map_err(|e| ProjectionError::Serialise {
        reason: e.to_string(),
    })
}

/// The content hash of a projection: SHA-256 of its canonical form, hex-encoded.
pub fn hash(projected: &Projected) -> String {
    let digest = Sha256::digest(projected.toml.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}
