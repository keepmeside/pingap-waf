//! Symmetric etcd peer inventory primitives using the existing config storage abstraction.

use pingap_config::Storage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const HEARTBEAT_PREFIX: &str = "_cluster/nodes/";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceUsage { pub cpu_millis: Option<u64>, pub memory_bytes: Option<u64> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeHeartbeat {
    pub node_id: String, pub version: String, pub config_version: Option<String>, pub config_hash: Option<String>, pub resource_usage: ResourceUsage, pub last_seen: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus { Healthy, Offline, Stale, Drifted }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInventory { pub heartbeat: NodeHeartbeat, pub status: NodeStatus }
#[derive(Debug, Clone, Copy)]
pub struct LivenessPolicy { pub offline_after_secs: i64, pub reap_after_secs: i64 }
impl Default for LivenessPolicy { fn default() -> Self { Self { offline_after_secs: 30, reap_after_secs: 86_400 } } }
#[derive(Clone)]
pub struct ClusterInventory { storage: Arc<dyn Storage>, policy: LivenessPolicy }

impl ClusterInventory {
    pub fn new(storage: Arc<dyn Storage>, policy: LivenessPolicy) -> Result<Self, String> {
        if policy.offline_after_secs <= 0 || policy.reap_after_secs <= policy.offline_after_secs { return Err("cluster liveness policy requires positive thresholds and reap_after_secs greater than offline_after_secs".into()); }
        Ok(Self { storage, policy })
    }
    pub async fn publish(&self, heartbeat: &NodeHeartbeat) -> Result<(), String> {
        validate_heartbeat(heartbeat)?;
        let value = serde_json::to_string(heartbeat).map_err(|e| format!("encode heartbeat: {e}"))?;
        self.storage.save(&heartbeat_key(&heartbeat.node_id), &value).await.map_err(|e| format!("save heartbeat: {e}"))
    }
    pub async fn read(&self, now: i64, expected_version: Option<&str>, expected_hash: Option<&str>) -> Result<Vec<NodeInventory>, String> {
        if now < 0 { return Err("inventory time cannot be negative".into()); }
        let keys = self.storage.list_keys(HEARTBEAT_PREFIX).await.map_err(|e| format!("list cluster nodes: {e}"))?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let value = match self.storage.fetch(&key).await { Ok(value) => value, Err(_) => continue };
            let heartbeat: NodeHeartbeat = match serde_json::from_str(&value) { Ok(value) => value, Err(_) => continue };
            if validate_heartbeat(&heartbeat).is_err() { continue; }
            let status = status(&heartbeat, now, self.policy, expected_version, expected_hash);
            out.push(NodeInventory { heartbeat, status });
        }
        out.sort_by(|a, b| a.heartbeat.node_id.cmp(&b.heartbeat.node_id));
        Ok(out)
    }
    pub async fn reap(&self, now: i64) -> Result<usize, String> {
        let cutoff = now.checked_sub(self.policy.reap_after_secs).ok_or_else(|| "reaper time underflow".to_string())?;
        let inventory = self.read(now, None, None).await?;
        let mut removed = 0;
        for item in inventory {
            if item.heartbeat.last_seen < cutoff {
                self.storage.delete(&heartbeat_key(&item.heartbeat.node_id)).await.map_err(|e| format!("reap node {}: {e}", item.heartbeat.node_id))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

pub fn stable_node_id(seed: &str) -> Result<String, String> {
    if seed.trim().is_empty() { return Err("node identity seed cannot be empty".into()); }
    let digest = Sha256::digest(seed.as_bytes());
    let encoded: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("node-{encoded}"))
}
pub fn heartbeat_key(node_id: &str) -> String { format!("{HEARTBEAT_PREFIX}{node_id}.json") }
fn validate_heartbeat(value: &NodeHeartbeat) -> Result<(), String> {
    if value.node_id.is_empty() || value.node_id.len() > 128 || value.node_id.contains('/') || value.last_seen < 0 { return Err("invalid heartbeat identity or timestamp".into()); }
    if value.version.len() > 256 { return Err("heartbeat version is too long".into()); }
    Ok(())
}
fn status(value: &NodeHeartbeat, now: i64, policy: LivenessPolicy, expected_version: Option<&str>, expected_hash: Option<&str>) -> NodeStatus {
    if now.saturating_sub(value.last_seen) > policy.offline_after_secs { return NodeStatus::Offline; }
    if expected_version.is_some_and(|v| value.config_version.as_deref() != Some(v)) { return NodeStatus::Stale; }
    if expected_hash.is_some_and(|h| value.config_hash.as_deref() != Some(h)) { return NodeStatus::Drifted; }
    NodeStatus::Healthy
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_stable() { assert_eq!(stable_node_id("cluster-secret").unwrap(), stable_node_id("cluster-secret").unwrap()); assert_ne!(stable_node_id("a").unwrap(), stable_node_id("b").unwrap()); }
    #[test]
    fn status_distinguishes_states() {
        let p = LivenessPolicy { offline_after_secs: 30, reap_after_secs: 60 };
        let base = NodeHeartbeat { node_id: "n".into(), version: "v".into(), config_version: Some("1".into()), config_hash: Some("a".into()), resource_usage: ResourceUsage { cpu_millis: None, memory_bytes: None }, last_seen: 100 };
        assert_eq!(status(&base, 100, p, Some("1"), Some("a")), NodeStatus::Healthy);
        assert_eq!(status(&base, 100, p, Some("2"), Some("a")), NodeStatus::Stale);
        assert_eq!(status(&base, 100, p, Some("1"), Some("b")), NodeStatus::Drifted);
        assert_eq!(status(&base, 131, p, Some("1"), Some("a")), NodeStatus::Offline);
    }
}
