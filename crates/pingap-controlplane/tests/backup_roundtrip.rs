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

#[tokio::test]
async fn encrypted_bundle_roundtrip_requires_correct_key() {
    use pingap_controlplane::backup::{
        export_encrypted_bundle, restore_bundle_with_key,
    };

    let dir = tempdir().expect("tempdir");
    let source_store = dir.path().join("source.sqlite");
    let original_store = b"binary-store-snapshot-content-1234";
    fs::write(&source_store, original_store)
        .await
        .expect("store");
    let bundle = dir.path().join("encrypted_bundle");

    let key = "test-encryption-key-for-backup";
    let original_config = "[basic]\nname = \"secure-pingap\"\n";

    let result = export_encrypted_bundle(
        &bundle,
        original_config,
        &source_store,
        "test",
        2,
        Some("v2".into()),
        20,
        key,
    )
    .await
    .expect("export encrypted");

    assert!(result.manifest.encrypted);

    // Unkeyed/public validate must refuse encrypted bundle to prevent uninspected partial restores
    assert!(validate_bundle(&bundle).await.is_err());

    // Wrong key must fail decryption
    let wrong_staging = dir.path().join("wrong_staging");
    assert!(
        restore_bundle_with_key(&bundle, &wrong_staging, "wrong-key")
            .await
            .is_err()
    );

    // Correct key restores byte-identical config and store
    let staging = dir.path().join("staging");
    let restored = restore_bundle_with_key(&bundle, &staging, key)
        .await
        .expect("restore with key");

    assert_eq!(
        fs::read_to_string(restored.staged_config)
            .await
            .expect("read staged config"),
        original_config
    );
    assert_eq!(
        fs::read(restored.staged_store)
            .await
            .expect("read staged store"),
        original_store
    );
}
