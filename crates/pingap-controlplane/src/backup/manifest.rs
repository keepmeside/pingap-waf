use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BUNDLE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub format_version: u32,
    pub product_version: String,
    pub intent_schema_version: u32,
    pub config_version: Option<String>,
    pub created_at: i64,
    pub encrypted: bool,
    pub files: BTreeMap<String, String>,
}
