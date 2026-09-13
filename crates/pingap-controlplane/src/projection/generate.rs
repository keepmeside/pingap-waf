//! Intent to config, totally and deterministically.
//!
//! Every reference is resolved here rather than left for `pingap-waf -t` or for runtime,
//! because the failure modes downstream are silent: pingap drops a plugin name it cannot
//! resolve with no error and no log, and an empty plugin list means "continue to
//! upstream". A dangling policy binding must therefore be a message from this function,
//! not a Location that proxies unfiltered while the control plane reports it protected.

use super::hash::canonical_toml;
use super::{
    Certificate, Domain, Intent, Listener, Projected, ProjectionError, Result,
    Upstream,
};
use bytesize::ByteSize;
use pingap_config::{
    CertificateConf, LocationConf, PingapConfig, ServerConf, UpstreamConf,
};
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
        // `global_certificates` is the only key that makes a pingap server terminate TLS,
        // so a listener that asks for TLS settings and has nothing to serve is refused
        // here rather than left to fall back to a self-signed certificate at handshake.
        if listener.tls.is_some() && intent.certificates.is_empty() {
            return Err(ProjectionError::BadValue {
                field: format!("listener `{name}`.tls"),
                value: "tls settings".to_string(),
                reason: "no certificate is defined, so there is nothing to \
                         terminate TLS with"
                    .to_string(),
            });
        }
        config.servers.insert(
            name.clone(),
            server_conf(
                listener,
                on_listener.get(name.as_str()).cloned().unwrap_or_default(),
                wants_grpc_web.get(name.as_str()).copied().unwrap_or(false),
            ),
        );
    }

    for (name, certificate) in &intent.certificates {
        config
            .certificates
            .insert(name.clone(), certificate_conf(name, certificate)?);
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

/// One certificate, refusing the shapes that load nothing.
///
/// `CertificateConf::validate` parses `tls_cert` and `tls_key` only when they are present,
/// so "a chain and no key" is not an error it can catch — and the server then serves a
/// self-signed certificate instead, which reaches the operator as a browser warning with no
/// trail back to the write that caused it. The invariant is checked here, where the reason
/// can name the entry.
fn certificate_conf(
    name: &str,
    certificate: &Certificate,
) -> Result<CertificateConf> {
    let present =
        |value: &Option<String>| value.as_ref().is_some_and(|v| !v.is_empty());
    let has_chain = present(&certificate.tls_cert);
    let has_key = present(&certificate.tls_key);
    let has_acme = present(&certificate.acme);

    if has_chain != has_key {
        return Err(ProjectionError::BadValue {
            field: format!("certificate `{name}`"),
            value: if has_chain {
                "tls_cert with no tls_key".to_string()
            } else {
                "tls_key with no tls_cert".to_string()
            },
            reason: "a manual certificate needs both PEM halves, and an ACME \
                     one needs neither"
                .to_string(),
        });
    }
    if !has_chain && !has_acme {
        return Err(ProjectionError::BadValue {
            field: format!("certificate `{name}`"),
            value: "no PEM pair and no ACME issuer".to_string(),
            reason:
                "there is nothing to serve and nothing that will obtain one"
                    .to_string(),
        });
    }

    Ok(CertificateConf {
        // Comma-joined, which is how SNI matching reads it. Empty means "no host
        // restriction", so an empty list is emitted as absent rather than as "".
        domains: (!certificate.domains.is_empty())
            .then(|| certificate.domains.join(",")),
        tls_cert: certificate.tls_cert.clone(),
        tls_key: certificate.tls_key.clone(),
        is_default: certificate.is_default,
        is_ca: certificate.is_ca,
        acme: certificate.acme.clone(),
        dns_challenge: certificate.dns_challenge,
        dns_provider: certificate.dns_provider.clone(),
        dns_service_url: certificate.dns_service_url.clone(),
        buffer_days: certificate.buffer_days,
        remark: certificate.remark.clone(),
    })
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
        // Derived, not configured, and the reason a `tls` block is not inert. `pingap-proxy`
        // sets `is_tls` from this flag alone, so version and cipher settings on a server
        // without it apply to a plaintext listener. Written as absent rather than `false`
        // for the same reason `grpc_web` is: the two mean the same thing to pingap and
        // emitting the default would show up as a content change for no behaviour.
        global_certificates: listener.tls.is_some().then_some(true),
        // gRPC-web needs two keys at two levels: the Location opts in and the Server must
        // load the module. Setting only one is a silent no-op, so the module is derived
        // from the domains rather than configured separately.
        modules: grpc_web.then(|| vec!["grpc-web".to_string()]),
        ..Default::default()
    }
}
