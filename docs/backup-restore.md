# Backup and restore

The control-plane backup scaffold writes a directory bundle containing:

- `config.toml`, the canonical projected configuration supplied by the caller;
- `store.sqlite`, a caller-provided consistent store snapshot; and
- `manifest.json`, containing format and intent-schema versions, ConfigVersion, timestamp,
  encryption marker, and SHA-256 checksums for each payload file.

Validation checks the format version, rejects bundles marked encrypted when no decryptor is
configured, and verifies every checksum before staging. `restore_bundle` only validates and
copies into a staging directory; it never replaces a live configuration or database.

This implementation intentionally does not claim unsupported runtime guarantees. It does not yet
invoke `VACUUM INTO` through the private serialised writer, perform application-level foreign-key
validation, encrypt secrets, package an archive, run `pingap-waf -t`, atomically swap live stores,
record activity rows, schedule retention, or expose an admin route. Callers must protect bundle
directories and provide their own consistent snapshot until those interfaces are implemented.

The `encrypted` field is therefore always `false`; marking a bundle encrypted causes restore to
reject it rather than treating plaintext as protected.
