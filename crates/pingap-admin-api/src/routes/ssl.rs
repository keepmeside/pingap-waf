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

//! Certificates: what to serve, and the one resource with a secret in it.
//!
//! Mounted at `/ssl`, which is the reference API's mount path for this resource.
//! `/certificates` is taken, and deliberately not reclaimed: that is the retained route
//! answering from the *running* certificate provider — what is loaded and when it expires.
//! This one is the definition the provider is built from. Both are certificates and neither
//! is the other, so they keep separate paths rather than one pretending to be a view of the
//! other.
//!
//! Two things here are not true of any other config-shaped resource, and both follow from
//! `tls_key` being key material:
//!
//! - **Reads return a view, not the entry.** The private key is stored and projected but is
//!   never serialised back out. [`CertificateView`] is destructured rather than built with
//!   `..` so that a field added to `Certificate` is a compile error here until someone
//!   decides whether it is public — the fail-closed direction, because the alternative
//!   leaks on a rename nobody thinks about.
//! - **A write may omit the key.** `PUT` replaces the whole entry everywhere else, which
//!   would mean re-uploading a private key to change a remark, on a value the read route
//!   just refused to hand back. Omitting `tls_key` therefore means "keep the stored one",
//!   and that is unambiguous rather than a special case: the projection already refuses a
//!   chain with no key, so there is no valid certificate in the "clear the key" state for
//!   it to be confused with. Switching to an issued certificate clears both halves at once.

use super::{intent_resource, name};
use crate::{ApiError, ApiRequest, ApiResponse, AppState, Result};
use pingap_controlplane::projection::Certificate;
use serde::Serialize;
use std::collections::BTreeMap;

/// A certificate as a read route may show it: every field but the private key.
#[derive(Debug, Serialize)]
struct CertificateView {
    domains: Vec<String>,
    /// The chain is public — it is served in every handshake — so it is not redacted.
    tls_cert: Option<String>,
    /// The fact of a key rather than the key. Named for what it is so a UI cannot bind to a
    /// `tls_key` field and quietly receive an empty string it mistook for a redaction.
    has_tls_key: bool,
    is_default: Option<bool>,
    is_ca: Option<bool>,
    acme: Option<String>,
    dns_challenge: Option<bool>,
    dns_provider: Option<String>,
    dns_service_url: Option<String>,
    buffer_days: Option<u16>,
    remark: Option<String>,
}

impl CertificateView {
    fn of(certificate: &Certificate) -> Self {
        // Destructured in full. A new field on `Certificate` breaks this match, which is the
        // point: the decision "is this public?" is forced on whoever adds it.
        let Certificate {
            domains,
            tls_cert,
            tls_key,
            is_default,
            is_ca,
            acme,
            dns_challenge,
            dns_provider,
            dns_service_url,
            buffer_days,
            remark,
        } = certificate;
        Self {
            domains: domains.clone(),
            tls_cert: tls_cert.clone(),
            has_tls_key: tls_key.is_some(),
            is_default: *is_default,
            is_ca: *is_ca,
            acme: acme.clone(),
            dns_challenge: *dns_challenge,
            dns_provider: dns_provider.clone(),
            dns_service_url: dns_service_url.clone(),
            buffer_days: *buffer_days,
            remark: remark.clone(),
        }
    }
}

pub async fn list(
    state: &AppState,
    _request: &ApiRequest,
    _params: &[String],
) -> Result<ApiResponse> {
    let intent = intent_resource::base_intent(state).await?;
    let view: BTreeMap<&str, CertificateView> = intent
        .certificates
        .iter()
        .map(|(name, certificate)| {
            (name.as_str(), CertificateView::of(certificate))
        })
        .collect();
    ApiResponse::json(&view)
}

pub async fn get(
    state: &AppState,
    _request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let name = name(params)?;
    let intent = intent_resource::base_intent(state).await?;
    let certificate =
        intent
            .certificates
            .get(name)
            .ok_or_else(|| ApiError::NotFound {
                kind: "certificate".to_string(),
                id: name.to_string(),
            })?;
    ApiResponse::json(&CertificateView::of(certificate))
}

pub async fn put(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    let name = name(params)?;
    let mut certificate: Certificate = request.json()?;
    // One read of the base, used for both the carried-forward key and the write, so a
    // concurrent edit cannot land between them and have this one built on the older intent.
    let intent = intent_resource::base_intent(state).await?;
    if certificate.tls_key.is_none() {
        certificate.tls_key = intent
            .certificates
            .get(name)
            .and_then(|stored| stored.tls_key.clone());
    }
    intent_resource::insert(
        state,
        request,
        "certificate",
        name,
        certificate,
        intent,
        |intent| &mut intent.certificates,
    )
    .await
}

pub async fn delete(
    state: &AppState,
    request: &ApiRequest,
    params: &[String],
) -> Result<ApiResponse> {
    intent_resource::remove(
        state,
        request,
        "certificate",
        name(params)?,
        |intent| &mut intent.certificates,
    )
    .await
}
