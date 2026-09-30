/// Validate a return path before it is placed in a redirect or HTML attribute.
pub fn validate_return_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.starts_with("/\\")
    {
        return Err(
            "return path must be a relative path beginning with one `/`",
        );
    }
    if path
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte.is_ascii_control())
    {
        return Err("return path contains a control character");
    }
    if path.contains("://") {
        return Err("return path cannot be an absolute URL");
    }
    Ok(())
}

pub fn safe_return_path(path: &str) -> &str {
    validate_return_path(path).ok().map(|_| path).unwrap_or("/")
}
