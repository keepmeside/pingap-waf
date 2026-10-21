//! Backend-only immutable secret reference resolution. No paths or contents in errors.
use crate::config::ConfigError;

pub(crate) fn load(reference: &str) -> Result<Vec<u8>, ConfigError> {
    if reference.is_empty()
        || reference.contains("..")
        || reference.contains(['/', '\\'])
        || reference.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConfigError::BadSecretReference);
    }
    load_regular(reference)
}

#[cfg(unix)]
fn load_regular(reference: &str) -> Result<Vec<u8>, ConfigError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path =
        std::path::Path::new("/run/secrets/pingap/challenge").join(reference);
    // O_NOFOLLOW closes the symlink/open race. O_NONBLOCK ensures a FIFO can
    // never hang candidate validation before its descriptor type is checked.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ConfigError::UnusableSecretFile)?;
    if !file
        .metadata()
        .map_err(|_| ConfigError::UnusableSecretFile)?
        .is_file()
    {
        return Err(ConfigError::UnusableSecretFile);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| ConfigError::UnusableSecretFile)?;
    if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ConfigError::UnusableSecretFile);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn load_regular(_: &str) -> Result<Vec<u8>, ConfigError> {
    Err(ConfigError::UnusableSecretFile)
}
