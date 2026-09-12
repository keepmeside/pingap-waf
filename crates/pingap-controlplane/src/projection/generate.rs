//! Intent to config, totally and deterministically.
//!
//! Every reference is resolved here rather than left for `pingap -t` or for runtime,
//! because the failure modes downstream are silent: pingap drops a plugin name it cannot
//! resolve with no error and no log, and an empty plugin list means "continue to
//! upstream". A dangling policy binding must therefore be a message from this function,
//! not a Location that proxies unfiltered while the control plane reports it protected.

use super::hash::canonical_toml;
use super::{
    Domain, Intent, Listener, Projected, ProjectionError, Result, Upstream,
};
use bytesize::ByteSize;
use pingap_config::{LocationConf, PingapConfig, ServerConf, UpstreamConf};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Compile `intent` into a complete pingap config.
///
/// Total: every projected category is emitted from `intent` alone, so the result is a pure
/// function of stored intent and the hash over it is meaningful.
pub fn generate(intent: &Intent) -> Result<Projected> {
    let mut config = PingapConfig::default();

    config.basic.trusted_proxies = intent.trusted_proxies.clone();

    for (name, upstream) in &intent.upstreams {
        config
            .upstreams
            .insert(name.clone(), upstream_conf(upstream));
    }

    // Which domains sit on each listener, and whether any of them wants gRPC-web. Both
    // are properties of the listener that only the domains know, so they are collected
    // while walking the domains rather than asked for twice.
    let mut on_listener: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut wants_grpc_web: BTreeMap<&str, bool> = BTreeMap::new();

    for (name, domain) in &intent.domains {
        if !intent.upstreams.contains_key(&domain.upstream) {
            return Err(ProjectionError::Dangling {
                kind: "upstream".to_string(),
                name: domain.upstream.clone(),
                domain: name.clone(),
            });
        }
        let listener = intent
            .listeners
            .get_key_value(domain.listener.as_str())
            .ok_or_else(|| ProjectionError::Dangling {
                kind: "listener".to_string(),
                name: domain.listener.clone(),
                domain: name.clone(),
            })?;
        for binding in &domain.policies {
            let entry = binding.entry_name();
            if !intent.policies.contains_key(&entry) {
                return Err(ProjectionError::Dangling {
                    kind: "policy".to_string(),
                    name: entry,
                    domain: name.clone(),
                });
            }
        }
        config
            .locations
            .insert(name.clone(), location_conf(name, domain)?);
        on_listener
            .entry(listener.0)
            .or_default()
            .push(name.clone());
        let entry = wants_grpc_web.entry(listener.0).or_default();
        *entry = *entry || domain.grpc_web;
    }

    for (name, listener) in &intent.listeners {
        config.servers.insert(
            name.clone(),
            server_conf(
                listener,
                on_listener.get(name.as_str()).cloned().unwrap_or_default(),
                wants_grpc_web.get(name.as_str()).copied().unwrap_or(false),
            ),
        );
    }

    for (name, plugin) in &intent.policies {
        config.plugins.insert(name.clone(), plugin.clone());
    }

    let toml = canonical_toml(&config)?;
    Ok(Projected { config, toml })
}

fn upstream_conf(upstream: &Upstream) -> UpstreamConf {
    UpstreamConf {
        // `addr weight`, space separated, which is how `pingap-discovery::format_addrs`
        // reads it. Weight omitted rather than written as 1, so a default does not show up
        // as a content change.
        addrs: upstream
            .backends
            .iter()
            .map(|b| match b.weight {
                Some(w) => format!("{} {w}", b.addr),
                None => b.addr.clone(),
            })
            .collect(),
        algo: upstream.lb_algorithm.clone(),
        health_check: upstream.health_check.clone(),
        discovery: upstream.discovery.clone(),
        sni: upstream.tls_sni.clone(),
        verify_cert: upstream.verify_cert,
        ..Default::default()
    }
}

fn location_conf(name: &str, domain: &Domain) -> Result<LocationConf> {
    let client_max_body_size = match &domain.client_max_body_size {
        Some(value) => Some(ByteSize::from_str(value).map_err(|e| {
            ProjectionError::BadValue {
                field: format!("domain `{name}`.client_max_body_size"),
                value: value.clone(),
                reason: e.to_string(),
            }
        })?),
        None => None,
    };
    Ok(LocationConf {
        upstream: Some(domain.upstream.clone()),
        path: domain.path.clone(),
        // Comma-joined: one Location can serve several names.
        host: if domain.hostnames.is_empty() {
            None
        } else {
            Some(domain.hostnames.join(","))
        },
        weight: domain.priority,
        remark: domain.notes.clone(),
        client_max_body_size,
        max_processing: domain.max_processing,
        max_retries: domain.max_retries,
        enable_reverse_proxy_headers: domain.reverse_proxy_headers,
        // `false` is written as absent rather than `false`: the two mean the same thing to
        // pingap, and emitting the default would make every domain's config differ from
        // the minimal form for no behavioural reason.
        grpc_web: domain.grpc_web.then_some(true),
        // Order preserved. The first plugin to answer terminates the request, so the
        // order is policy, not presentation.
        plugins: if domain.policies.is_empty() {
            None
        } else {
            Some(
                domain
                    .policies
                    .iter()
                    .map(|b| b.entry_name())
                    .collect::<Vec<_>>(),
            )
        },
        ..Default::default()
    })
}

fn server_conf(
    listener: &Listener,
    mut locations: Vec<String>,
    grpc_web: bool,
) -> ServerConf {
    locations.sort_unstable();
    let tls = listener.tls.clone().unwrap_or_default();
    ServerConf {
        addr: listener.addr.clone(),
        access_log: listener.access_log.clone(),
        locations: (!locations.is_empty()).then_some(locations),
        enabled_h2: listener.http2,
        enable_server_timing: listener.server_timing,
        tls_min_version: tls.min_version,
        tls_max_version: tls.max_version,
        tls_cipher_list: tls.cipher_list,
        tls_ciphersuites: tls.ciphersuites,
        // gRPC-web needs two keys at two levels: the Location opts in and the Server must
        // load the module. Setting only one is a silent no-op, so the module is derived
        // from the domains rather than configured separately.
        modules: grpc_web.then(|| vec!["grpc-web".to_string()]),
        ..Default::default()
    }
}
