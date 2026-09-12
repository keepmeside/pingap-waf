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

use super::admin_auth::{
    LazyAdminAuth, LoginRequest, Principal, Refusal, TotpRequest,
};
use super::{get_hash_key, get_int_conf, get_str_conf};
use crate::certificates::new_certificate_provider;
use crate::config_manager::get_config_manager;
use crate::process::{get_start_time, restart_now};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use ctor::ctor;
use flate2::Compression;
use flate2::write::GzEncoder;
use hex::encode;
use http::Method;
use http::{HeaderValue, StatusCode, header};
use pingap_admin_api::{ApiRequest, ApiResponse, AppState, Caller};
use pingap_config::hcl::convert_toml_to_hcl;
use pingap_config::kdl::convert_toml_to_kdl;
use pingap_config::{
    BasicConf, CATEGORY_CERTIFICATE, CATEGORY_STORAGE, Category,
    CertificateConf, ConfigManager, LocationConf, PluginConf, ServerConf,
    StorageConf, UpstreamConf, Validate, format_category,
};
use pingap_config::{
    CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    PingapConfig,
};
use pingap_controlplane::AuthLevel;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_performance::get_process_system_info;
use pingap_performance::get_processing_accepted;
use pingap_plugin::{Error, get_plugin_factory};
use pingap_upstream::UpstreamHealthyStatus;
use pingap_util::base64_decode;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

static LOG_TARGET: &str = "main::admin";

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration);

impl From<EmbeddedStaticFile> for HttpResponse {
    fn from(value: EmbeddedStaticFile) -> Self {
        let Some(file) = value.0 else {
            return HttpResponse::not_found("Not Found");
        };
        // generate content hash
        let str = &encode(file.metadata.sha256_hash())[0..8];
        let mime_type = file.metadata.mimetype();
        // cut hash and file length as etag
        let entity_tag = format!(r#""{:x}-{str}""#, file.data.len());
        // html set no-cache
        let max_age = if mime_type.contains("text/html") {
            0
        } else {
            value.1.as_secs()
        };

        let mut headers = vec![];
        if let Ok(value) = HeaderValue::from_str(mime_type) {
            headers.push((header::CONTENT_TYPE, value));
        }
        if let Ok(value) = HeaderValue::from_str(&entity_tag) {
            headers.push((header::ETAG, value));
        }

        let mut gzip_body = None;
        if file.data.len() > 1024 {
            let mut d = GzEncoder::new(vec![], Compression::best());
            let _ = d.write_all(&file.data);
            if let Ok(w) = d.finish() {
                gzip_body = Some(Bytes::copy_from_slice(w.as_ref()));
                if let Ok(value) = HeaderValue::from_str("gzip") {
                    headers.push((header::CONTENT_ENCODING, value));
                }
            }
        }
        let body = if let Some(data) = gzip_body {
            data
        } else {
            Bytes::copy_from_slice(&file.data)
        };

        HttpResponse {
            status: StatusCode::OK,
            body,
            max_age: Some(max_age as u32),
            headers: Some(headers),
            ..Default::default()
        }
    }
}

pub struct AdminServe {
    pub path: String,
    pub plugin_step: PluginStep,
    manager: Arc<ConfigManager>,
    hash_value: String,
    ip_fail_limit: TtlLruLimit,
    /// Per-user sessions from the control-plane store. Replaces the shared
    /// `authorizations` list, which could not say who did anything.
    auth: LazyAdminAuth,
    /// The route table's state, built on first API request.
    ///
    /// Deferred for the same reason `auth` is: pingora forks for daemon mode after
    /// `bootstrap()` and before the service runtimes start, so a store connection
    /// opened while the plugin was constructed would be handed to a process that
    /// never opened it. Built from `auth`'s store rather than a second handle, so
    /// the API and the session lookup are the one writer `TursoStore::shared`
    /// requires.
    api: tokio::sync::OnceCell<AppState>,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

const GIT_HASH: &str = env!("VERGEN_GIT_SHA");

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    rustc_version: String,
    kernel: String,
    config_hash: String,
    pid: String,
    user: String,
    group: String,
    threads: i64,
    processing: i32,
    accepted: u64,
    memory_mb: usize,
    memory: String,
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    total_memory: String,
    used_memory: String,
    features: Vec<String>,
    fd_count: usize,
    tcp_count: usize,
    tcp6_count: usize,
    supported_plugins: Vec<String>,
    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>,
    support_history: bool,
    git_hash: String,
    now: u64,
    /// `None` when reachable; otherwise why not. Reported here rather than as
    /// a failed request, so a missing store reads as a state and not a crash.
    control_plane_store_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FullConfigJson {
    pub hcl: String,
    pub kdl: String,
    pub full: String,
    pub original: String,
}

/// The `authorizations` key, on an admin plugin, is the shared-credential scheme
/// this fork replaces. Refused rather than ignored: an operator who still has it
/// in their config believes admin auth is configured, and silently dropping it
/// would leave them believed-secure. The `--admin user:pass@addr` path does not
/// hit this — it arrives as `bootstrap`, a different key, because that
/// credential still has one job: creating the first account.
///
/// Scoped to this plugin. `basic_auth` and `combined_auth` also read
/// `authorizations`, legitimately, and never come through here.
const LEGACY_AUTHORIZATIONS_MESSAGE: &str = "`authorizations` no longer \
    configures the admin plugin: admin access is per-user, with accounts in the \
    control-plane store. Remove the key. To create the first admin, pass \
    `--admin user:password@addr` (or PINGAP_ADMIN_USER + PINGAP_ADMIN_PASSWORD) \
    and log in once; that credential bootstraps the account and is not consulted \
    again.";

impl TryFrom<&PluginConf> for AdminServe {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        Self::build(value, LazyAdminAuth::new)
    }
}

/// How `AdminServe::build` makes its auth handle: store path, bootstrap
/// credential, TOTP key. Production passes `LazyAdminAuth::new`; tests pass
/// `LazyAdminAuth::private` so each plugin gets its own store.
type MakeAuth =
    fn(String, Option<(String, String)>, Option<String>) -> LazyAdminAuth;

impl AdminServe {
    /// Construction proper, parameterised on how the auth handle is made so
    /// tests can hand each plugin its own store instead of the process-global
    /// one.
    fn build(value: &PluginConf, make_auth: MakeAuth) -> Result<Self> {
        let hash_value = get_hash_key(value);
        if value.contains_key("authorizations") {
            return Err(Error::Invalid {
                category: "admin".to_string(),
                message: LEGACY_AUTHORIZATIONS_MESSAGE.to_string(),
            });
        }
        // The one credential an operator has when the store is empty. Base64
        // `user:pass`, exactly as `--admin` encodes it.
        let mut bootstrap = None;
        let encoded = get_str_conf(value, "bootstrap");
        if !encoded.is_empty() {
            let data =
                base64_decode(&encoded).map_err(|e| Error::Base64Decode {
                    category: "admin".to_string(),
                    source: e,
                })?;
            match std::string::String::from_utf8_lossy(&data).split_once(':') {
                Some((user, pass)) if !user.is_empty() && !pass.is_empty() => {
                    bootstrap = Some((user.to_string(), pass.to_string()));
                },
                _ => {
                    return Err(Error::Invalid {
                        category: "admin".to_string(),
                        message: "bootstrap must decode to `user:password` \
                                  with both parts non-empty"
                            .to_string(),
                    });
                },
            }
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let mut path = get_str_conf(value, "path");
        if path.len() > 1 && path.ends_with("/") {
            path = path.substring(0, path.len() - 1).to_string();
        }
        let store_path = get_str_conf(value, "store");
        if store_path.is_empty() {
            return Err(Error::Invalid {
                category: "admin".to_string(),
                message: "store is required: the path of the control-plane \
                          database that holds admin accounts and sessions"
                    .to_string(),
            });
        }
        let totp_key = get_str_conf(value, "totp_key");

        let params = AdminServe {
            hash_value,
            plugin_step: PluginStep::Request,
            path,
            ip_fail_limit: TtlLruLimit::new_compact(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            manager: get_config_manager().map_err(|e| Error::Invalid {
                category: "config_manager".to_string(),
                message: e.to_string(),
            })?,
            auth: make_auth(
                store_path,
                bootstrap,
                Some(totp_key).filter(|k| !k.is_empty()),
            ),
            api: tokio::sync::OnceCell::new(),
        };

        Ok(params)
    }

    /// Like `try_from`, over a store private to this instance.
    #[cfg(test)]
    fn try_from_private(value: &PluginConf) -> Result<Self> {
        Self::build(value, LazyAdminAuth::private)
    }

    /// The route table's state, built on first use.
    ///
    /// The store is `auth`'s, not a second handle: `TursoStore::shared` is one writer per
    /// process and refuses a second path, and splitting the API's writes from the session
    /// lookup's would split the audit trail even if it did not.
    ///
    /// A failure here is a broken installation — `new_applier` only fails when this
    /// executable's own path cannot be resolved, which is what validation needs to spawn
    /// `pingap -t`. Reported as a state the operator can read rather than a panic, on the
    /// same reasoning as an unavailable store: the data plane keeps serving either way.
    async fn api(&self) -> std::result::Result<&AppState, String> {
        self.api
            .get_or_try_init(|| async {
                let store = self.auth.get().await.store().clone();
                let applier = crate::projection::new_applier(
                    store.clone(),
                    self.manager.clone(),
                    crate::projection::DEFAULT_RELOAD_WINDOW,
                )?;
                Ok(AppState::new(store, Arc::new(applier)))
            })
            .await
    }
}

/// The router's caller, from the session that authenticated.
///
/// A conversion rather than a shared type: `Principal` is the binary's, produced by reading
/// a bearer token against the store, and `Caller` is what the router decides authorisation
/// from. Keeping them separate is what keeps `pingap-admin-api` free of the auth path — and
/// therefore testable without one.
fn caller_of(principal: &Principal) -> Caller {
    Caller {
        session_id: principal.session_id.clone(),
        user_id: principal.user_id.clone(),
        username: principal.username.clone(),
        role: principal.role,
        auth_level: principal.auth_level,
    }
}

/// The router's response, in the gateway's own type.
fn http_response_of(response: ApiResponse) -> HttpResponse {
    HttpResponse {
        status: response.status,
        body: response.body,
        headers: response.content_type.and_then(|value| {
            Some(vec![(
                header::CONTENT_TYPE,
                HeaderValue::from_str(value).ok()?,
            )])
        }),
        ..Default::default()
    }
}

async fn get_request_body(session: &mut Session) -> pingora::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(4096);
    while let Some(value) = session.read_request_body().await? {
        buf.put(value.as_ref());
    }
    Ok(buf)
}

impl AdminServe {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(target: LOG_TARGET, params = params.to_string(), "new admin server plugin");
        AdminServe::try_from(params)
    }

    /// Whether `path` is one the login UI needs before anyone is logged in.
    ///
    /// The index page and its static assets (js/css/png) load unauthenticated;
    /// everything under `/api` never does, even with a static-looking suffix —
    /// otherwise `GET /api/configs/x.js` would bypass auth. The skip and the
    /// `/api` router use different criteria, so they are kept mutually exclusive
    /// here.
    ///
    /// One exception, matched exactly rather than by prefix: `/api/health`. A load
    /// balancer has no session, and the route is built for that — it answers a fixed
    /// two-field shape with no version, no build, no path and no error text, so there is
    /// nothing in it an unauthenticated scanner can use. Exact match because
    /// `starts_with("/api/health")` would also open `/api/health-detail` to anyone who
    /// later adds it.
    fn auth_skipped(path: &str) -> bool {
        if path == "/api/health" {
            return true;
        }
        let is_api = path.starts_with("/api") || path.starts_with("api/");
        !is_api
            && (path.len() <= 1
                || path.ends_with(".js")
                || path.ends_with(".css")
                || path.ends_with(".png"))
    }

    /// Resolve the request's bearer token to a user, or say why not.
    ///
    /// Asks the store on every call; nothing is cached, so revoking a session
    /// or deactivating a user takes effect on the next request. No
    /// credentials-present check exists here any more because there is no
    /// credential list: a store with no users and no bootstrap simply has
    /// nobody who can log in, which is deny by construction.
    async fn auth_validate(
        &self,
        req_header: &RequestHeader,
    ) -> std::result::Result<Principal, Refusal> {
        let auth = self.auth.get().await;
        auth.authenticate(req_header).await.inspect_err(|refusal| {
            error!(
                target: LOG_TARGET,
                path = req_header.uri.path(),
                refusal = ?refusal,
                "auth validate fail"
            );
        })
    }
    async fn load_config(
        &self,
        replace_include: bool,
    ) -> pingora::Result<PingapConfig> {
        let config = self.manager.load_all().await.map_err(|e| {
            error!(target: LOG_TARGET, "failed to load config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        let config = config.to_pingap_config(replace_include).map_err(|e| {
            error!(target: LOG_TARGET, "failed to convert config: {e}");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(config)
    }
    async fn get_config(
        &self,
        category: &str,
    ) -> pingora::Result<HttpResponse> {
        let conf = self.load_config(false).await?;
        if category == "full" {
            let full_conf = self.load_config(true).await?;
            let mut full_toml = toml::to_string_pretty(&full_conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let hcl = convert_toml_to_hcl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let kdl = convert_toml_to_kdl(&full_toml)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let mut original_toml = toml::to_string_pretty(&conf)
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            if let Ok(value) =
                pingap_util::toml_omit_empty_value(&original_toml)
            {
                original_toml = value;
            };
            return HttpResponse::try_from_json(&FullConfigJson {
                hcl,
                kdl,
                full: full_toml,
                original: original_toml,
            });
        }
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PLUGIN => HttpResponse::try_from_json(&conf.plugins)?,
            CATEGORY_CERTIFICATE => {
                HttpResponse::try_from_json(&conf.certificates)?
            },
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(
        &self,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        let category = Category::from_str(category)
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        self.manager.delete(category, name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "delete config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        Ok(HttpResponse::no_content())
    }
    async fn handle_update_config<T>(
        &self,
        name: &str,
        buf: &[u8],
        category: Category,
    ) -> pingora::Result<()>
    where
        T: DeserializeOwned + Serialize + Send + Sync + Validate,
    {
        let conf: T = serde_json::from_slice(buf).map_err(|e| {
            error!(
                target: LOG_TARGET,
                error = e.to_string(),
                "parse {} config fail",
                category.to_string()
            );
            pingap_core::new_internal_error(400, e)
        })?;
        conf.validate().map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "validate config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        self.manager
            .update(category, name, &conf)
            .await
            .map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "update config fail");
                pingap_core::new_internal_error(400, e)
            })?;

        Ok(())
    }

    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> pingora::Result<HttpResponse> {
        if name.is_empty() {
            return Err(pingap_core::new_internal_error(
                400,
                "name is empty".to_string(),
            ));
        }
        let buf = get_request_body(session).await?;

        match category {
            CATEGORY_UPSTREAM => {
                self.handle_update_config::<UpstreamConf>(
                    name,
                    &buf,
                    Category::Upstream,
                )
                .await?;
            },
            CATEGORY_LOCATION => {
                self.handle_update_config::<LocationConf>(
                    name,
                    &buf,
                    Category::Location,
                )
                .await?;
            },
            CATEGORY_SERVER => {
                self.handle_update_config::<ServerConf>(
                    name,
                    &buf,
                    Category::Server,
                )
                .await?;
            },
            CATEGORY_PLUGIN => {
                self.handle_update_config::<PluginConf>(
                    name,
                    &buf,
                    Category::Plugin,
                )
                .await?;
            },
            CATEGORY_CERTIFICATE => {
                self.handle_update_config::<CertificateConf>(
                    name,
                    &buf,
                    Category::Certificate,
                )
                .await?;
            },
            CATEGORY_STORAGE => {
                self.handle_update_config::<StorageConf>(
                    name,
                    &buf,
                    Category::Storage,
                )
                .await?;
            },
            _ => {
                self.handle_update_config::<BasicConf>(
                    "",
                    &buf,
                    Category::Basic,
                )
                .await?;
            },
        };

        Ok(HttpResponse::no_content())
    }
    async fn import_config(
        &self,
        session: &mut Session,
    ) -> pingora::Result<HttpResponse> {
        let buf = get_request_body(session).await?;
        let config = toml::from_slice(&buf).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;
        self.manager.save_all(&config).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "import config fail");
            pingap_core::new_internal_error(400, e)
        })?;

        Ok(HttpResponse::no_content())
    }
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

async fn handle_request_admin(
    plugin: &AdminServe,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<Option<HttpResponse>> {
    let ip = pingap_core::ensure_client_ip(session, ctx);
    if !plugin.ip_fail_limit.validate(ip) {
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(b"Forbidden, too many failures"),
            ..Default::default()
        }));
    }

    let header = session.req_header_mut();
    let path = header.uri.path();
    let mut new_path =
        path.substring(plugin.path.len(), path.len()).to_string();
    if plugin.path.len() > 1 && new_path.is_empty() {
        new_path = format!("{path}/");
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        let resp = HttpResponse::redirect(&new_path)?;
        return Ok(Some(resp));
    }
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // ignore parse error
    if let Ok(uri) = new_path.parse::<http::Uri>() {
        header.set_uri(uri);
    }
    let (method, mut path) = get_method_path(session);

    // Login is the one API route with no session to check, so it precedes the
    // gate. It is still behind the IP failure limiter above, and a refused
    // login counts against that limiter exactly as a bad token does.
    if path == "/api/auth/login" && method == Method::POST {
        let ip = ip.to_string();
        let user_agent = pingap_core::get_req_header_value(
            session.req_header(),
            "User-Agent",
        )
        .map(str::to_string);
        let buf = get_request_body(session).await?;
        let req: LoginRequest = serde_json::from_slice(buf.as_ref())
            .map_err(|e| pingap_core::new_internal_error(400, e))?;
        let auth = plugin.auth.get().await;
        return Ok(Some(
            match auth.login(req, Some(&ip), user_agent.as_deref()).await {
                Ok(Some(resp)) => HttpResponse::try_from_json(&resp)
                    .unwrap_or(HttpResponse::unknown_error("Json serde fail")),
                Ok(None) => {
                    plugin.ip_fail_limit.inc(&ip);
                    HttpResponse {
                        status: StatusCode::UNAUTHORIZED,
                        ..Default::default()
                    }
                },
                Err(refusal) => refusal.into_response(),
            },
        ));
    }

    let principal = if AdminServe::auth_skipped(&path) {
        None
    } else {
        match plugin.auth_validate(session.req_header()).await {
            Ok(principal) => Some(principal),
            Err(Refusal::Unauthenticated) => {
                plugin.ip_fail_limit.inc(ip);
                return Ok(Some(HttpResponse {
                    status: StatusCode::UNAUTHORIZED,
                    ..Default::default()
                }));
            },
            // Not counted against the limiter: the caller did nothing wrong.
            Err(refusal) => return Ok(Some(refusal.into_response())),
        }
    };

    // The remaining auth routes act on the session that just authenticated.
    if let Some(principal) = &principal {
        if path == "/api/auth/totp" && method == Method::POST {
            let buf = get_request_body(session).await?;
            let req: TotpRequest = serde_json::from_slice(buf.as_ref())
                .map_err(|e| pingap_core::new_internal_error(400, e))?;
            let auth = plugin.auth.get().await;
            return Ok(Some(match auth.complete_totp(principal, req).await {
                Ok(true) => HttpResponse::no_content(),
                Ok(false) => {
                    plugin.ip_fail_limit.inc(ip);
                    HttpResponse {
                        status: StatusCode::UNAUTHORIZED,
                        ..Default::default()
                    }
                },
                Err(refusal) => refusal.into_response(),
            }));
        }
        if path == "/api/auth/logout" && method == Method::POST {
            let auth = plugin.auth.get().await;
            return Ok(Some(match auth.logout(principal).await {
                Ok(()) => HttpResponse::no_content(),
                Err(refusal) => refusal.into_response(),
            }));
        }
        if path == "/api/auth/me" {
            return Ok(Some(
                HttpResponse::try_from_json(&json!({
                    "username": principal.username,
                    "role": principal.role,
                    "auth_level": principal.auth_level,
                }))
                .unwrap_or(HttpResponse::unknown_error("Json serde fail")),
            ));
        }
        // A password-only session may look but not touch. Decided here, before
        // any route, from the same predicate the role matrix uses.
        if principal.auth_level == AuthLevel::PasswordOnly
            && method != Method::GET
        {
            return Ok(Some(HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from_static(
                    b"Forbidden, complete the second factor first",
                ),
                ..Default::default()
            }));
        }
    }
    let api_prefix = "/api";
    // Recorded before the prefix is stripped, because afterwards `/api/users` and a static
    // asset at `/users` are the same string — and only the first may reach the router. The
    // auth path above skips authentication for short non-`/api` paths and for
    // `.js`/`.css`/`.png`, so a route answerable outside the prefix would inherit that skip.
    let is_api_request = path.starts_with(api_prefix);
    if is_api_request {
        path = path.substring(api_prefix.len(), path.len()).to_string();
    }
    let params: Vec<String> = path
        .split('/')
        .map(|item| decode(item).unwrap_or_default().to_string())
        .collect();
    let mut category = "";
    if params.len() >= 3 {
        category = &params[2];
    }
    let resp = if path.starts_with("/configs") {
        match method {
            Method::POST => {
                if category == "import" {
                    plugin.import_config(session).await
                } else if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.update_config(session, category, &params[3]).await
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    Err(pingora::Error::new_str("Url is invalid(no name)"))
                } else {
                    plugin.remove_config(category, &params[3]).await
                }
            },
            _ => plugin.get_config(category).await,
        }
        .unwrap_or_else(|err| {
            HttpResponse::try_from_json_status(
                &ErrorResponse {
                    message: err.to_string(),
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
        })
    } else if path.starts_with("/config-history") {
        let category = Category::from_str(category).map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config category fail");
            pingap_core::new_internal_error(400, e)
        })?;
        // The name segment is optional in the url but not in the code below,
        // so reject a short url instead of indexing past the end of `params`.
        let Some(name) = params.get(3).cloned() else {
            return Err(pingap_core::new_internal_error(
                400,
                "Url is invalid(no name)",
            ));
        };
        let arr = plugin.manager.history(category.clone(), &name).await.map_err(|e| {
            error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
            pingap_core::new_internal_error(400, e)
        })?.unwrap_or_default();

        let mut history = vec![];
        for item in arr {
            let data:toml::Table = toml::from_str(&item.data).map_err(|e| {
                error!(target: LOG_TARGET, error = e.to_string(), "get config history fail");
                pingap_core::new_internal_error(400, e)
            })?;
            let key = format_category(&category);
            let Some(data) = data.get(key).cloned() else {
                continue;
            };
            let data = if name.is_empty() {
                data
            } else {
                let Some(data) = data.get(&name).cloned() else {
                    continue;
                };
                data
            };
            history.push(json!({
                "created_at": item.created_at,
                "data": data,
            }));
        }
        HttpResponse::try_from_json(&json!({
            "history": history,
        }))
        .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/basic" {
        let current_config = plugin.load_config(true).await?;
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let mut basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version(),
            config_hash: plugin
                .manager
                .get_current_config()
                .hash()
                .unwrap_or_default(),
            user: current_config.basic.user.clone().unwrap_or_default(),
            group: current_config.basic.group.clone().unwrap_or_default(),
            pid: info.pid.to_string(),
            threads: info.threads,
            accepted,
            processing,
            kernel: info.kernel,
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            features: vec![],
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: new_upstream_provider().healthy_status(),
            support_history: plugin.manager.support_history(),
            git_hash: GIT_HASH.to_string(),
            now: pingap_core::now_sec(),
            control_plane_store_error: plugin
                .auth
                .get()
                .await
                .store_available()
                .await
                .err()
                .map(|e| e.into_response().body)
                .map(|b| String::from_utf8_lossy(&b).to_string()),
        };
        basic_info.features.push("default".to_string());

        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                basic_info.features.push("tracing".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
                basic_info.features.push("full".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "pyro")] {
                basic_info.features.push("pyroscope".to_string());
            }
        }

        HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/restart" && method == Method::POST {
        if let Err(e) = restart_now().await {
            error!(target: LOG_TARGET, error = e.to_string(), "Restart fail");
            HttpResponse::bad_request(e.to_string())
        } else {
            HttpResponse::no_content()
        }
    } else if path == "/certificates" {
        let mut infos = HashMap::new();
        for (name, cert) in new_certificate_provider().list().iter() {
            if let Some(info) = &cert.info {
                let key = if let Some(value) = &cert.name {
                    value.clone()
                } else {
                    name.clone()
                };
                infos.insert(key, info.clone());
            }
        }
        HttpResponse::try_from_json(&infos)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if is_api_request {
        // Everything else under `/api` belongs to the route table. Placed after the
        // retained raw-config routes so those keep their behaviour unchanged — they are
        // documented drift sources, not part of this surface — and before the static-asset
        // fallback, so an unknown API path answers a JSON 404 rather than "no such asset".
        match plugin.api().await {
            Ok(state) => {
                let query = session
                    .req_header()
                    .uri
                    .query()
                    .unwrap_or_default()
                    .to_string();
                let body = get_request_body(session).await?.freeze();
                let request = ApiRequest {
                    method,
                    path,
                    query,
                    body,
                    caller: principal.as_ref().map(caller_of),
                };
                http_response_of(
                    pingap_admin_api::dispatch(state, &request).await,
                )
            },
            Err(reason) => {
                error!(target: LOG_TARGET, reason, "admin api is unavailable");
                HttpResponse::try_from_json_status(
                    &ErrorResponse { message: reason },
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
            },
        }
    } else {
        let mut file = path.substring(1, path.len());
        if file.is_empty() {
            file = "index.html";
        }
        EmbeddedStaticFile(
            AdminAsset::get(file),
            Duration::from_secs(365 * 24 * 3600),
        )
        .into()
    };
    Ok(Some(resp))
}

#[async_trait]
impl Plugin for AdminServe {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if self.plugin_step != step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(RequestPluginResult::Skipped);
        }
        let resp = handle_request_admin(self, session, _ctx).await?;
        if let Some(resp) = resp {
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register("admin", |params| Ok(Arc::new(AdminServe::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::{
        AdminAsset, AdminServe, EmbeddedStaticFile, handle_request_admin,
    };
    use crate::config_manager::try_init_config_manager;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, HttpResponse};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tokio_test::io::Builder;

    /// An admin plugin over a fresh store in `dir`, bootstrapped with
    /// `admin:123123` (the base64 the tests below share).
    fn admin_over(dir: &tempfile::TempDir) -> AdminServe {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let store = dir.path().join("cp.db");
        // spellchecker:off
        AdminServe::try_from_private(
            &toml::from_str::<PluginConf>(&format!(
                r#"
    category = "admin"
    bootstrap = "YWRtaW46MTIzMTIz"
    store = "{}"
    "#,
                store.to_string_lossy()
            ))
            .unwrap(),
        )
        .unwrap()
        // spellchecker:on
    }

    /// Drive one raw HTTP/1.1 request through the plugin.
    async fn send(admin: &AdminServe, raw: &str) -> HttpResponse {
        let mock_io = Builder::new().read(raw.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        handle_request_admin(admin, &mut session, &mut Ctx::default())
            .await
            .unwrap()
            .expect("the admin plugin always answers")
    }

    /// Log in and return the bearer token.
    async fn login(admin: &AdminServe, user: &str, pass: &str) -> String {
        let body = format!(r#"{{"username":"{user}","password":"{pass}"}}"#);
        let resp = send(
            admin,
            &format!(
                "POST /api/auth/login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert_eq!(200, resp.status.as_u16(), "login refused");
        let json: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap();
        json["token"].as_str().unwrap().to_string()
    }

    #[test]
    fn test_admin_params() {
        let dir = tempfile::tempdir().unwrap();
        let params = admin_over(&dir);
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("", params.path);

        // The bootstrap credential must be a decodable `user:pass`.
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    bootstrap = "123"
    store = "/tmp/x.db"
    "#,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin admin, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );
    }

    /// The legacy shared-credential key is refused with the replacement
    /// named. Refused rather than ignored: silently dropping it would leave an
    /// operator who configured it believing admin auth is in place.
    #[test]
    fn test_legacy_authorizations_key_is_rejected_on_the_admin_plugin() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let err = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    authorizations = ["YWRtaW46MTIzMTIz"]
    store = "/tmp/x.db"
    "#,
            )
            .unwrap(),
        )
        .err()
        .expect("the legacy key must not be accepted");
        // spellchecker:on
        let msg = err.to_string();
        assert!(msg.contains("`authorizations`"), "{msg}");
        assert!(msg.contains("--admin user:password@addr"), "{msg}");
        // An empty list is the same key and the same refusal — the hole
        // Phase 01 closed must not reopen by way of "the list was empty".
        let err = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    authorizations = []
    store = "/tmp/x.db"
    "#,
            )
            .unwrap(),
        )
        .err()
        .expect("an empty legacy list is still the legacy key");
        assert!(err.to_string().contains("`authorizations`"));
    }

    /// The same key is required by `basic_auth` and `combined_auth`, and the
    /// rejection above must not reach them. Asserted through the factory,
    /// which is the path `pingap -t` takes.
    #[test]
    fn test_basic_auth_and_combined_auth_still_accept_authorizations() {
        let factory = pingap_plugin::get_plugin_factory();
        // spellchecker:off
        for conf in [
            r#"
    category = "basic_auth"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            r#"
    category = "combined_auth"
    authorizations = [{ app_id = "a", secret = "s", deviation = 60 }]
    "#,
        ] {
            let conf = toml::from_str::<PluginConf>(conf).unwrap();
            factory
                .create(&conf)
                .unwrap_or_else(|e| panic!("{conf:?} refused: {e}"));
        }
        // spellchecker:on
    }

    #[test]
    fn test_embedded_static_file() {
        let file = AdminAsset::get("index.html").unwrap();
        let resp: HttpResponse =
            EmbeddedStaticFile(Some(file), Duration::from_secs(60)).into();
        assert_eq!(true, !resp.body.is_empty());
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(0, resp.max_age.unwrap_or_default());
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", resp.headers.unwrap_or_default()[0])
        );

        let resp: HttpResponse =
            EmbeddedStaticFile(None, Duration::from_secs(60)).into();
        assert_eq!(404, resp.status.as_u16())
    }

    #[test]
    fn test_auth_skipped_only_for_static_assets() {
        // Genuine static assets of the login UI load without auth.
        assert_eq!(true, AdminServe::auth_skipped("/"));
        assert_eq!(true, AdminServe::auth_skipped("/assets/index.js"));
        assert_eq!(true, AdminServe::auth_skipped("/assets/index.css"));
        assert_eq!(true, AdminServe::auth_skipped("/pingap.png"));

        // Regression: API routes must never be auth-skipped, even when suffixed
        // with a static-looking extension.
        assert_eq!(false, AdminServe::auth_skipped("/api/configs/anything.js"));
        assert_eq!(
            false,
            AdminServe::auth_skipped("/api/configs/upstream/evil.css")
        );
        assert_eq!(false, AdminServe::auth_skipped("/api/certificates.png"));
        assert_eq!(false, AdminServe::auth_skipped("/api/basic"));
        assert_eq!(false, AdminServe::auth_skipped("/api/auth/me"));

        // The one API path a load balancer reaches without a session, matched exactly so a
        // longer path that merely starts the same way is not also opened.
        assert_eq!(true, AdminServe::auth_skipped("/api/health"));
        assert_eq!(false, AdminServe::auth_skipped("/api/health-detail"));
        assert_eq!(false, AdminServe::auth_skipped("/api/health/nodes"));
    }

    /// The acceptance criterion asserted by request rather than by reading
    /// config: no `Authorization` header sent, a config write must come back
    /// 401.
    #[tokio::test]
    async fn test_unauthenticated_config_write_returns_401() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        let resp = send(
            &admin,
            "POST /api/configs/upstream/evil HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert_eq!(401, resp.status.as_u16());
    }

    /// The route table is reachable through the mount, and the role gate is the router's.
    ///
    /// Asserted by request because mounting is the half the router's own enumeration test
    /// cannot see: that test drives `dispatch` directly, so a table that was never wired to
    /// the admin listener would pass every assertion in it.
    #[tokio::test]
    async fn test_the_mounted_route_table_answers_under_api() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        let token = login(&admin, "admin", "123123").await;

        let users = send(
            &admin,
            &format!(
                "GET /api/users HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(
            200,
            users.status.as_u16(),
            "the route table is not mounted: {}",
            String::from_utf8_lossy(&users.body)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&users.body).unwrap();
        assert_eq!("admin", json[0]["username"]);
        // The password hash is not a field of the view, and this is the assertion that
        // keeps it that way through a serialisation change.
        assert_eq!(
            false,
            String::from_utf8_lossy(&users.body).contains("argon2"),
            "a user listing carried the stored password hash"
        );

        // A path the table does not have answers the router's JSON 404 rather than falling
        // through to the static-asset handler.
        let missing = send(
            &admin,
            &format!(
                "GET /api/nothing-here HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(404, missing.status.as_u16());
        assert_eq!(
            true,
            String::from_utf8_lossy(&missing.body).contains("route"),
            "an unknown API path was answered by something other than the router"
        );
    }

    /// `/api/health` is the one API route with no session, and a non-API path never reaches
    /// the router at all.
    #[tokio::test]
    async fn test_health_is_the_only_unauthenticated_api_route() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);

        let health = send(&admin, "GET /api/health HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, health.status.as_u16());
        let body = String::from_utf8_lossy(&health.body).to_string();
        // Two fields, and nothing an unauthenticated scanner can use: no version, no build,
        // no store path, no error text.
        assert_eq!(
            true,
            body.contains("\"status\":\"ok\""),
            "unexpected health body: {body}"
        );
        for leak in ["version", "git", "path", "pid", "rustc"] {
            assert_eq!(
                false,
                body.contains(leak),
                "the unauthenticated health route leaked `{leak}`: {body}"
            );
        }

        // Every other route still needs a session, health included once it is not the
        // exact path.
        for path in ["/api/users", "/api/activity", "/api/health/nodes"] {
            let resp =
                send(&admin, &format!("GET {path} HTTP/1.1\r\n\r\n")).await;
            assert_eq!(
                401,
                resp.status.as_u16(),
                "{path} was reachable without a session"
            );
        }

        // And a path outside `/api` is a static asset, not a route: it must not be answered
        // by the router, or it would inherit the static-asset auth skip.
        let asset = send(&admin, "GET /users HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            false,
            String::from_utf8_lossy(&asset.body).contains("\"error\""),
            "a non-API path was answered by the router"
        );
    }

    /// End to end: the bootstrap credential logs in, the token opens the API,
    /// logout closes it on the very next request.
    #[tokio::test]
    async fn test_login_then_logout_revokes_on_the_next_request() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        let token = login(&admin, "admin", "123123").await;

        let me = send(
            &admin,
            &format!(
                "GET /api/auth/me HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(200, me.status.as_u16());
        let json: serde_json::Value = serde_json::from_slice(&me.body).unwrap();
        assert_eq!("admin", json["username"]);
        assert_eq!("admin", json["role"]);

        let out = send(
            &admin,
            &format!(
                "POST /api/auth/logout HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(204, out.status.as_u16());

        let after = send(
            &admin,
            &format!(
                "GET /api/auth/me HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(401, after.status.as_u16(), "a revoked token still worked");
    }

    /// A wrong password is a 401 and counts against the IP limiter, so
    /// password guessing hits the same wall that token guessing does.
    #[tokio::test]
    async fn test_a_failed_login_counts_against_the_ip_limiter() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        // Bootstrap first so there is an account to guess at.
        login(&admin, "admin", "123123").await;
        let body = r#"{"username":"admin","password":"wrong"}"#;
        let raw = format!(
            "POST /api/auth/login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut last = 0;
        // The default limit is 10 failures per five minutes.
        for _ in 0..12 {
            last = send(&admin, &raw).await.status.as_u16();
        }
        assert_eq!(403, last, "the limiter never engaged");
    }

    /// `/aes` encrypted and decrypted caller-supplied data with a
    /// caller-supplied key: an oracle behind admin auth with no further gate,
    /// and nothing in the gateway needs it. Authenticated, so the request gets
    /// past auth and the assertion is about the route, not the guard.
    #[tokio::test]
    async fn test_aes_endpoint_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        let token = login(&admin, "admin", "123123").await;
        let body = r#"{"category":"encrypt","key":"k","data":"d"}"#;
        let resp = send(
            &admin,
            &format!(
                "POST /api/aes HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert_eq!(
            404,
            resp.status.as_u16(),
            "the encryption oracle is reachable again"
        );
    }

    /// Regression: `/config-history/{category}` without the trailing name used
    /// to index past the end of the split url and panic the request task.
    #[tokio::test]
    async fn test_config_history_without_name() {
        let dir = tempfile::tempdir().unwrap();
        let admin = admin_over(&dir);
        let token = login(&admin, "admin", "123123").await;
        let mock_io = Builder::new()
            .read(
                format!(
                    "GET /api/config-history/upstream HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let err =
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .err()
                .unwrap();
        assert_eq!(
            true,
            err.to_string().contains("Url is invalid(no name)"),
            "unexpected error: {err}"
        );
    }

    /// The load-bearing boundary, at the request layer: with the store on a
    /// path that cannot exist, the plugin still constructs, static assets
    /// still serve, and the API says 503 rather than 401 or 500.
    #[tokio::test]
    async fn test_store_unavailable_is_503_and_the_ui_still_loads() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from_private(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    bootstrap = "YWRtaW46MTIzMTIz"
    store = "/nonexistent-directory-for-a-test/cp.db"
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        let index = send(&admin, "GET / HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, index.status.as_u16(), "the login page must load");

        let body = r#"{"username":"admin","password":"123123"}"#;
        let login = send(
            &admin,
            &format!(
                "POST /api/auth/login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert_eq!(503, login.status.as_u16());
        assert!(
            String::from_utf8_lossy(&login.body).contains("unavailable"),
            "the body should say why"
        );

        let api = send(
            &admin,
            "GET /api/basic HTTP/1.1\r\nAuthorization: Bearer whatever\r\n\r\n",
        )
        .await;
        assert_eq!(503, api.status.as_u16());
    }
}
