//! Control-plane store and RBAC.
//!
//! Users, second factors, sessions and the audit trail — the state pingap's config
//! cannot hold, because config is a document and this is an append-heavy log queried by
//! range and filtered by role.
//!
//! The boundary is the load-bearing decision: **the gateway must start and serve with
//! this store unavailable.** Config (file or etcd) owns domains, upstreams, certificates
//! and policy, and already has validation, history, an etcd watch and `pingap-waf -t`. This
//! store owns identity and history. Nothing here is on the request path.

pub mod auth;
pub mod projection;
pub mod rbac;
pub mod repository;
pub mod schema;
pub mod store;

pub use auth::{
    AuthError, TotpGuard, decrypt_totp_secret, encrypt_totp_secret, enrol_totp,
    hash_password, hash_token, new_token, tokens_match, verify_password,
};
pub use rbac::{AuthLevel, Capability, Denial, Role, authorize};
pub use repository::{
    Activity, ConfigStatus, ConfigVersion, ControlPlaneStore, NewActivity,
    NewConfigVersion, NewSession, NewUser, Session, StoreError, TimeRange,
    User,
};
pub use store::TursoStore;
