// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `openapi.yaml` and the route table, checked against each other.
//!
//! A specification nobody enforces is worse than none, because a client trusts it. Both
//! directions are checked: a route added to the table without a spec entry leaves a
//! client unable to call it, and a spec entry whose route was renamed or removed sends a
//! client to a 404. The second is the one that ships silently, because nothing in the build
//! reads the YAML.
//!
//! The capability is compared too, not just the path and method, and the expected spelling
//! comes from the same `serde` attribute that names a capability on the wire. A route whose
//! guard is tightened or loosened without the spec following is therefore a failure here
//! rather than a documentation drift nobody reads.
//!
//! Parsed by indentation rather than by a YAML library. The document's structure is fixed
//! by this check — two spaces per level, operations keyed by method, one extension line per
//! operation — and the only YAML crate in the lockfile is a deprecated one, so reading
//! three fields from a file this test already constrains is the smaller commitment.

use pingap_admin_api::{Access, table};
use pingap_controlplane::Capability;

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

/// One operation the spec declares, and the capability it says is needed to reach it.
///
/// The capability is optional at this stage rather than defaulted, so "the spec forgot to
/// say" is distinguishable from "the spec said something wrong" — the first is a gap in the
/// document, the second is a disagreement with the code, and they are fixed differently.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Operation {
    method: String,
    path: String,
    capability: Option<String>,
}

/// Every operation under `paths:`, in document order.
fn spec() -> Vec<Operation> {
    let mut out: Vec<Operation> = Vec::new();
    let mut in_paths = false;
    let mut path = String::new();

    for line in include_str!("../../../openapi.yaml").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            // `paths:` opens the section and the next top-level key closes it. Everything
            // under `components:` has the same shape and must not be read as routes.
            in_paths = trimmed == "paths:";
            continue;
        }
        if !in_paths {
            continue;
        }
        match indent {
            // A path item, or a path-level `parameters:` — which is not one, and must not
            // be mistaken for it.
            2 => {
                if let Some(key) = trimmed.strip_suffix(':')
                    && key.starts_with('/')
                {
                    path = key.to_string();
                }
            },
            // An operation. Anything else at this level (`parameters:`) is ignored, and so
            // is the list item under it.
            4 => {
                if let Some(method) = trimmed
                    .strip_suffix(':')
                    .filter(|key| METHODS.contains(key))
                {
                    out.push(Operation {
                        method: method.to_string(),
                        path: path.clone(),
                        capability: None,
                    });
                }
            },
            // The extension belongs to the operation most recently opened.
            6 => {
                if let Some(capability) =
                    trimmed.strip_prefix("x-required-capability:")
                    && let Some(operation) = out.last_mut()
                {
                    operation.capability = Some(capability.trim().to_string());
                }
            },
            _ => {},
        }
    }
    out
}

/// The capability a route declares, spelled the way it reaches a client.
fn capability_name(access: Access) -> String {
    match access {
        Access::Public => "public".to_string(),
        Access::Authenticated => "authenticated".to_string(),
        Access::Needs(capability) => match serde_json::to_value(capability) {
            Ok(serde_json::Value::String(name)) => name,
            other => panic!(
                "{capability:?} is not a string on the wire: {other:?}",
                capability = capability
            ),
        },
    }
}

/// The table, in the spec's spelling: `:name` becomes `{name}`.
fn routes() -> Vec<Operation> {
    table()
        .iter()
        .map(|route| Operation {
            method: route.method.as_str().to_ascii_lowercase(),
            path: route
                .path
                .split('/')
                .map(|segment| match segment.strip_prefix(':') {
                    Some(name) => format!("{{{name}}}"),
                    None => segment.to_string(),
                })
                .collect::<Vec<_>>()
                .join("/"),
            capability: Some(capability_name(route.access)),
        })
        .collect()
}

/// The paths answered by `src/plugin/admin.rs` before the router is consulted.
///
/// Pinned rather than derived, because they are not in the table — which is the reason this
/// list exists, and the reason `docs/api-parity.md` enumerates them as the retained surface.
/// A retained path removed from the binary leaves its entry here, and that mismatch is found
/// by reading that document against the plugin rather than by this test.
const RETAINED: [(&str, &str, &str); 12] = [
    ("post", "/auth/login", "public"),
    ("post", "/auth/totp", "authenticated"),
    ("post", "/auth/logout", "authenticated"),
    ("get", "/auth/me", "authenticated"),
    ("get", "/basic", "authenticated"),
    ("get", "/certificates", "view_raw_config"),
    ("get", "/configs/{category}", "view_raw_config"),
    ("post", "/configs/{category}/{name}", "write_raw_config"),
    ("delete", "/configs/{category}/{name}", "write_raw_config"),
    ("post", "/configs/import", "write_raw_config"),
    (
        "get",
        "/config-history/{category}/{name}",
        "view_raw_config",
    ),
    ("post", "/restart", "restart_process"),
];

fn retained() -> Vec<Operation> {
    RETAINED
        .into_iter()
        .map(|(method, path, capability)| Operation {
            method: method.to_string(),
            path: path.to_string(),
            capability: Some(capability.to_string()),
        })
        .collect()
}

fn describe(operations: &[Operation]) -> String {
    operations
        .iter()
        .map(|operation| {
            format!(
                "  {} {} ({})",
                operation.method.to_ascii_uppercase(),
                operation.path,
                operation
                    .capability
                    .as_deref()
                    .unwrap_or("<no x-required-capability>")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every registered route appears in the spec, with the capability the table gives it.
#[test]
fn every_registered_route_appears_in_the_spec() {
    let spec = spec();
    let mut missing = Vec::new();
    let mut disagreeing = Vec::new();

    for route in routes() {
        match spec.iter().find(|operation| {
            operation.method == route.method && operation.path == route.path
        }) {
            None => missing.push(route),
            Some(operation) if operation.capability != route.capability => {
                disagreeing.push(format!(
                    "  {} {} is {:?} in the spec and {:?} in the table",
                    route.method.to_ascii_uppercase(),
                    route.path,
                    operation.capability,
                    route.capability
                ));
            },
            Some(_) => {},
        }
    }

    assert!(
        missing.is_empty(),
        "routes absent from openapi.yaml — a client generated from the spec cannot call \
         them:\n{}",
        describe(&missing)
    );
    assert!(
        disagreeing.is_empty(),
        "routes whose documented capability differs from the guard the table gives \
         them:\n{}",
        disagreeing.join("\n")
    );
}

/// Every operation in the spec is either a registered route or a pinned retained path.
///
/// The direction that fails silently: nothing in the build reads the YAML, so an operation
/// left behind by a renamed or removed route keeps being published to clients until someone
/// tries to call it.
#[test]
fn every_operation_in_the_spec_is_a_route_or_a_retained_path() {
    let routes = routes();
    let retained = retained();
    let mut orphaned = Vec::new();
    let mut disagreeing = Vec::new();

    for operation in spec() {
        let same_route = |candidate: &Operation| {
            candidate.method == operation.method
                && candidate.path == operation.path
        };
        // Compared on all three fields first, then on path and method, so a capability
        // mismatch is reported as a disagreement rather than as an orphaned route.
        if routes.contains(&operation) || retained.contains(&operation) {
            continue;
        }
        match routes
            .iter()
            .find(|candidate| same_route(candidate))
            .or(retained.iter().find(|candidate| same_route(candidate)))
        {
            Some(known) => disagreeing.push(format!(
                "  {} {} is {:?} in the spec and {:?} in the code",
                operation.method.to_ascii_uppercase(),
                operation.path,
                operation.capability,
                known.capability
            )),
            None => orphaned.push(operation),
        }
    }

    assert!(
        disagreeing.is_empty(),
        "documented capabilities that disagree with the code:\n{}",
        disagreeing.join("\n")
    );
    assert!(
        orphaned.is_empty(),
        "operations in openapi.yaml that no route answers — a client generated from the \
         spec would be sent to a 404:\n{}",
        describe(&orphaned)
    );
}

/// The extension is present on every operation.
///
/// Both tests above compare capabilities, so an operation with none would report as a
/// disagreement and send whoever fixes it looking for a wrong value rather than a missing
/// line.
#[test]
fn every_operation_declares_a_capability() {
    let undocumented: Vec<Operation> = spec()
        .into_iter()
        .filter(|operation| operation.capability.is_none())
        .collect();
    assert!(
        undocumented.is_empty(),
        "operations with no `x-required-capability`, so this file cannot say who may call \
         them:\n{}",
        describe(&undocumented)
    );
}

/// The extension names something the matrix defines.
///
/// A renamed capability variant would otherwise read to a client as a permission nobody
/// holds, which is indistinguishable from being denied one that does.
#[test]
fn every_documented_capability_exists() {
    let mut known: Vec<String> = Capability::ALL
        .into_iter()
        .map(|capability| capability_name(Access::Needs(capability)))
        .collect();
    known.push(capability_name(Access::Public));
    known.push(capability_name(Access::Authenticated));

    let unknown: Vec<String> = spec()
        .into_iter()
        .filter_map(|operation| {
            let capability = operation.capability?;
            (!known.contains(&capability)).then(|| {
                format!(
                    "  {} {} declares `{capability}`",
                    operation.method.to_ascii_uppercase(),
                    operation.path
                )
            })
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "capabilities in the spec that the matrix does not define:\n{}",
        unknown.join("\n")
    );
}

/// The retained surface is documented, so the escape hatch is published rather than
/// discovered by reading the plugin.
#[test]
fn the_retained_surface_is_documented() {
    let spec = spec();
    let missing: Vec<String> = RETAINED
        .into_iter()
        .filter(|(method, path, _)| {
            !spec.iter().any(|operation| {
                operation.method == *method && operation.path == *path
            })
        })
        .map(|(method, path, _)| format!("  {method} {path}"))
        .collect();
    assert!(
        missing.is_empty(),
        "retained paths missing from openapi.yaml:\n{}",
        missing.join("\n")
    );
}
