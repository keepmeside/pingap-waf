# Backup and restore

The control-plane backup modules support verifiable directory bundles containing:

- `config.toml`, the canonical projected configuration;
- `store.sqlite`, a point-in-time store snapshot; and
- `manifest.json`, containing format and intent-schema versions, ConfigVersion, timestamp,
  encryption marker, and SHA-256 checksums for each payload file.

### Bundle Encryption and Keyed Staging

- `export_bundle` creates standard verifiable bundles with plain payload files.
- `export_encrypted_bundle` encrypts `config.toml` and `store.sqlite` (base64-encoded binary payload)
  using authenticated AES encryption with an operator-supplied key. The key is never stored in the bundle.
- `validate_bundle` checks format versions, validates checksums, and refuses encrypted bundles when called
  without a decryption key to prevent accidental partial staging.
- `restore_bundle_with_key` verifies the manifest, decrypts both payloads, and stages the plaintext files
  into a staging directory without touching live configuration or database paths.
- `restore_bundle` validates unencrypted bundles and copies them into the staging directory.

### Operational Boundaries

Live atomic swap, live store `VACUUM INTO` through the private writer connection, and automated scheduled
retention require runtime coordination and are executed outside the data-plane hot path. Callers must provide
a consistent point-in-time snapshot and maintain key custody.
