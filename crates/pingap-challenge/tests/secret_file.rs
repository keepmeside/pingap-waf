use pingap_challenge::{Challenge, ChallengeConfig};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct KeyFile {
    name: String,
    path: PathBuf,
}
impl KeyFile {
    fn new(bytes: &[u8]) -> Self {
        let root = PathBuf::from("/run/secrets/pingap/challenge");
        std::fs::create_dir_all(&root).expect("test fixture succeeds");
        let name = format!(
            "test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = root.join(&name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("test fixture succeeds");
        std::fs::write(&path, bytes).expect("test fixture succeeds");
        Self { name, path }
    }
    fn config(&self) -> ChallengeConfig {
        ChallengeConfig {
            enabled: true,
            secret_file: Some(self.name.clone()),
            client_ip_from_peer: true,
            ..Default::default()
        }
    }
}
impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[test]
fn file_source_is_resolved_without_trimming_or_serializing_key_bytes() {
    let key = KeyFile::new(b" distinct-test-material \n");
    let cfg = key.config();
    assert_eq!(
        cfg.resolve_secret().expect("test fixture succeeds"),
        b" distinct-test-material \n"
    );
    assert!(
        !toml::to_string(&cfg)
            .expect("test fixture succeeds")
            .contains("distinct-test-material")
    );
    Challenge::new(cfg.clone()).expect("file-backed constructor");
    let mut both = cfg;
    both.secret = "legacy".into();
    assert!(Challenge::new(both).is_err());
    assert!(
        !format!(
            "{:?}",
            ChallengeConfig {
                secret: "legacy-sensitive-marker".into(),
                ..Default::default()
            }
        )
        .contains("legacy-sensitive-marker")
    );
}
#[test]
fn invalid_references_and_non_regular_sources_fail_without_disclosing_material()
{
    for name in ["", "..", "../key", "/etc/passwd", "a/b", "a\\b", "key..v1"] {
        let cfg = ChallengeConfig {
            secret_file: Some(name.into()),
            ..Default::default()
        };
        assert!(Challenge::new(cfg).is_err(), "accepted {name}");
    }
    for bytes in [b"".as_slice(), b" \n\t".as_slice()] {
        assert!(Challenge::new(KeyFile::new(bytes).config()).is_err());
    }
    let missing = KeyFile::new(b"sensitive-marker");
    std::fs::remove_file(&missing.path).expect("test fixture succeeds");
    let error = Challenge::new(missing.config())
        .err()
        .expect("missing file")
        .to_string();
    assert!(!error.contains("sensitive-marker"));
    let target = KeyFile::new(b"sensitive-marker");
    let link = KeyFile::new(b"unused");
    std::fs::remove_file(&link.path).expect("test fixture succeeds");
    std::os::unix::fs::symlink(&target.path, &link.path)
        .expect("test fixture succeeds");
    assert!(Challenge::new(link.config()).is_err());
    let fifo = KeyFile::new(b"unused");
    std::fs::remove_file(&fifo.path).expect("test fixture succeeds");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo.path)
            .status()
            .expect("test fixture succeeds")
            .success()
    );
    assert!(Challenge::new(fifo.config()).is_err());
    let dir = KeyFile::new(b"unused");
    std::fs::remove_file(&dir.path).expect("test fixture succeeds");
    std::fs::create_dir(&dir.path).expect("test fixture succeeds");
    assert!(Challenge::new(dir.config()).is_err());
    std::fs::remove_dir(&dir.path).expect("test fixture succeeds");
}
#[test]
fn immutable_file_versions_keep_ordinary_config_hash_and_legacy_compatibility()
{
    use pingap_config::PluginConf;
    use pingap_core::Plugin;
    let first = KeyFile::new(b"test-key-first");
    let second = KeyFile::new(b"test-key-second");
    let make = |cfg: &ChallengeConfig| -> PluginConf {
        toml::Value::try_from(cfg)
            .expect("test fixture succeeds")
            .as_table()
            .expect("test fixture succeeds")
            .clone()
    };
    let first_conf = make(&first.config());
    let one = Challenge::try_from(&first_conf).expect("test fixture succeeds");
    assert_eq!(one.config_key(), pingap_plugin::get_hash_key(&first_conf));
    assert_eq!(
        one.config_key(),
        Challenge::try_from(&first_conf)
            .expect("test fixture succeeds")
            .config_key()
    );
    assert_ne!(
        one.config_key(),
        Challenge::new(second.config())
            .expect("test fixture succeeds")
            .config_key()
    );
    Challenge::new(ChallengeConfig {
        enabled: true,
        secret: "legacy".into(),
        client_ip_from_peer: true,
        ..Default::default()
    })
    .expect("test fixture succeeds");
    Challenge::new(ChallengeConfig::default()).expect("test fixture succeeds");
}
