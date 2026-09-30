//! Bounded, domain-keyed, expiring state.
//!
//! One primitive, and deliberately nothing else: a container keyed by `(domain,
//! client identity)` whose every map has a bound, whose entries expire, and which
//! knows nothing about what it holds. The payload parameter is unconstrained and no
//! policy vocabulary appears in the API, so four subsystems can share the bounding,
//! eviction and expiry logic without sharing a decision.
//!
//! # Ownership and lifetime
//!
//! One instance per subsystem, process-global, instantiated once and held by nothing on
//! any plugin instance. Plugin instances are rebuilt rather than reused whenever the
//! config hash changes, so state held on an instance dies routinely — not exceptionally.
//! What that costs if missed: an issued-but-unverified token vanishes on each apply, so a
//! client that spent CPU solving a proof-of-work posts back a nonce for a token that no
//! longer exists, is re-issued, and solves again.
//!
//! Global ownership and domain keying are **orthogonal**, and reading "process-global" as
//! cross-domain sharing is the mistake to avoid. The first gives durability across
//! rebuilds; the second gives isolation. Satisfying the isolation invariant does not
//! require state to die with the instance, and surviving the rebuild does not require
//! state to be shared between domains. `tests/isolation.rs` asserts isolation against a
//! process-global store for exactly that reason.
//!
//! State is not persisted across a process restart. A graceful restart re-challenges every
//! client, which is accepted deliberately rather than papered over: persisting tokens means
//! writing bearer credentials to disk, a larger security surface than the inconvenience it
//! buys.
//!
//! # Two saturations, two directions
//!
//! [`Full`] splits what a single error cannot express, because the two conditions have
//! different causes and need different responses:
//!
//! - [`Full::Domains`] is a **configuration fault**. Once unregistered hosts collapse it is
//!   not reachable by traffic, so a consumer should fail toward its configured policy. There
//!   is no availability argument for failing open on a condition an attacker cannot cause.
//! - [`Full::Entries`] is reachable by traffic, so **the caller decides**. It must be a
//!   returned error rather than a silent displacement, because a consumer with a cheaper
//!   fallback can only use it if it learns the bound was hit.
//!
//! # Reclaim
//!
//! Lazy, on access, always. No eager sweep is promised: a sweep needs a trigger and an
//! owner, and the only periodic mechanism in the tree holds one interval shared by every
//! task, which is already spoken for. What is guaranteed instead is that an expired entry
//! is unreachable through every accessor, that a domain reclaims its entries the next time
//! it receives any request, and that its bound cannot be held by stale entries in the
//! meantime.
//!
//! The honest residual: a domain that receives *no* traffic keeps its expired entries until
//! its own cap forces reclaim. That is bounded by the cap, which is what makes it survivable.

pub mod identity;
pub mod store;

pub use identity::{ClientIdentity, IdentityError, IdentitySource};
pub use store::{
    Clock, Counters, Domain, Full, HostPolicy, Limits, ManualClock, Millis,
    ScopedStore, SystemClock,
};
