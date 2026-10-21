//! Public policy inspection is separate from canonical secret-bearing intent.
use pingap_config::PluginConf;

pub fn is_challenge(config: &PluginConf) -> bool {
    config.get("category").and_then(|v| v.as_str()) == Some("challenge")
}

/// Redact a copy only. The canonical source remains available to validation and rollback.
pub fn redact(config: &mut PluginConf) {
    if !is_challenge(config) {
        return;
    }
    let literal = config
        .remove("secret")
        .and_then(|v| v.as_str().map(|s| !s.is_empty()))
        .unwrap_or(false);
    let reference = config
        .get("secret_file")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    config.insert(
        "secret_configured".into(),
        toml::Value::Boolean(literal || reference.is_some()),
    );
    let mut source = toml::Table::new();
    source.insert(
        "kind".into(),
        toml::Value::String(
            if reference.is_some() {
                "file"
            } else if literal {
                "literal"
            } else {
                "none"
            }
            .into(),
        ),
    );
    if let Some(reference) = reference {
        source.insert("reference".into(), toml::Value::String(reference));
    }
    config.insert("secret_source".into(), toml::Value::Table(source));
}

/// Strip read-only inspection metadata, preserving an omitted source from the
/// same canonical base used by the caller's mutation. Explicit replacements are
/// never merged with an old source; validation decides whether they are usable.
pub fn preserve_source(candidate: &mut PluginConf, base: Option<&PluginConf>) {
    if !is_challenge(candidate) {
        return;
    }
    candidate.remove("secret_configured");
    candidate.remove("secret_source");
    if !candidate.contains_key("secret")
        && !candidate.contains_key("secret_file")
        && let Some(base) = base.filter(|base| is_challenge(base))
    {
        for key in ["secret", "secret_file"] {
            if let Some(value) = base.get(key) {
                candidate.insert(key.into(), value.clone());
            }
        }
    }
}

/// New clients use an envelope, while the existing direct-table API remains
/// compatible. Deserialization failures cannot echo untrusted secret values.
pub fn mutation(
    body: serde_json::Value,
    base: Option<&PluginConf>,
) -> Result<PluginConf, &'static str> {
    let body = if body.get("category").is_none() {
        body.get("config").cloned().unwrap_or(body)
    } else {
        body
    };
    let mut candidate: PluginConf = serde_json::from_value(body)
        .map_err(|_| "policy config must be a valid table")?;
    preserve_source(&mut candidate, base);
    Ok(candidate)
}

pub fn redact_config(config: &mut pingap_config::PingapConfig) {
    for plugin in config.plugins.values_mut() {
        redact(plugin);
    }
}
