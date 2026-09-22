use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub struct BackupRetention { pub keep: usize, pub max_bytes: u64 }

pub fn retain_backups(mut backups: Vec<(PathBuf, u64, i64)>, policy: BackupRetention) -> Vec<PathBuf> {
    backups.sort_by_key(|(_, _, created)| std::cmp::Reverse(*created));
    let mut total: u64 = 0;
    backups.into_iter().enumerate().filter_map(|(index, (path, size, _))| {
        if index < policy.keep && total.saturating_add(size) <= policy.max_bytes { total += size; None } else { Some(path) }
    }).collect()
}
