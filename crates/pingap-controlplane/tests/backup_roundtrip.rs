use pingap_controlplane::backup::{
    export_bundle, restore_bundle, validate_bundle,
};
use tempfile::tempdir;
use tokio::fs;

#[tokio::test]
async fn export_validate_restore_verifies_payloads_before_staging() {
    let dir = tempdir().expect("tempdir");
    let source_store = dir.path().join("source.sqlite");
    fs::write(&source_store, b"snapshot").await.expect("store");
    let bundle = dir.path().join("bundle");
    let result = export_bundle(
        &bundle,
        "[basic]\n",
        &source_store,
        "test",
        3,
        Some("v1".into()),
        10,
    )
    .await
    .expect("export");
    assert_eq!(result.manifest.intent_schema_version, 3);
    validate_bundle(&bundle).await.expect("valid bundle");
    let staging = dir.path().join("staging");
    let restored = restore_bundle(&bundle, &staging).await.expect("restore");
    assert_eq!(
        fs::read(restored.staged_config).await.expect("config"),
        b"[basic]\n"
    );
    assert_eq!(
        fs::read(restored.staged_store).await.expect("store"),
        b"snapshot"
    );
}

#[tokio::test]
async fn corrupted_payload_is_rejected() {
    let dir = tempdir().expect("tempdir");
    let source_store = dir.path().join("source.sqlite");
    fs::write(&source_store, b"snapshot").await.expect("store");
    let bundle = dir.path().join("bundle");
    export_bundle(&bundle, "config", &source_store, "test", 1, None, 10)
        .await
        .expect("export");
    fs::write(bundle.join("config.toml"), b"tampered")
        .await
        .expect("tamper");
    assert!(validate_bundle(&bundle).await.is_err());
}
