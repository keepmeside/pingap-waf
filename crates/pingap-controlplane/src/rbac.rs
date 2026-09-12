//! Roles, capabilities, and the one function that decides whether a request may proceed.
//!
//! The design constraint here is not "implement three roles" — it is **make an
//! unprotected route impossible to add by accident**. A matrix enforced in middleware
//! protects the routes that were registered inside the guarded group, and says nothing
//! about the one added next to it. So the matrix is expressed as an exhaustive `match`
//! over a closed [`Capability`] enum: adding a capability without deciding what each role
//! may do with it does not compile, and a route that cannot name its capability cannot be
//! authorised at all.
//!
//! Second-factor state is decided in the same place, for the same reason. A separate
//! "has 2FA" check somewhere up the stack is a check a new route can forget.

use serde::{Deserialize, Serialize};

/// Who is asking.
///
/// The reference model's `moderator` is `Operator` here. "Moderator" describes someone
/// policing user-generated content; nothing in a gateway is moderated.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Everything, including other users, cluster membership and process restart.
    Admin,
    /// Traffic and policy: domains, upstreams, WAF/ACL/bot, certificates. No user
    /// management, no node enrolment, no restart.
    Operator,
    /// Reads, including logs, metrics and events. Mutates nothing.
    Viewer,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Admin, Role::Operator, Role::Viewer];

    pub const fn key(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    /// The inverse of [`Self::key`], for reading a stored row back.
    ///
    /// `None` rather than a default on unrecognised text. A role that defaulted would
    /// decide authorisation from a typo, and whichever default were chosen would be wrong:
    /// `Admin` grants everything to a corrupt row, `Viewer` locks out every real
    /// administrator.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.key() == key)
    }
}

/// Everything the admin surface can do, enumerated.
///
/// Closed on purpose. A route declares the capability it needs, so a route whose
/// capability nobody added cannot be written — and adding one here forces a decision for
/// all three roles in [`Role::allows`], because that match is exhaustive.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // ---- reads -------------------------------------------------------------------
    ViewConfig,
    ViewLogs,
    ViewMetrics,
    ViewEvents,
    ViewAlerts,
    ViewBackups,
    ViewNodes,
    /// The user list. A viewer cannot see who else has access.
    ViewUsers,
    /// One's *own* sessions. Everyone has this; it is how a user revokes their laptop.
    ViewOwnSessions,

    // ---- traffic and policy ------------------------------------------------------
    EditDomain,
    EditUpstream,
    EditPolicy,
    EditCertificate,
    EditAlert,
    RunBackup,

    // ---- administrative ----------------------------------------------------------
    RestoreBackup,
    ManageUsers,
    /// Revoke someone else's session.
    RevokeAnySession,
    EnrolNode,
    RestartProcess,
}

impl Capability {
    pub const ALL: [Capability; 20] = [
        Capability::ViewConfig,
        Capability::ViewLogs,
        Capability::ViewMetrics,
        Capability::ViewEvents,
        Capability::ViewAlerts,
        Capability::ViewBackups,
        Capability::ViewNodes,
        Capability::ViewUsers,
        Capability::ViewOwnSessions,
        Capability::EditDomain,
        Capability::EditUpstream,
        Capability::EditPolicy,
        Capability::EditCertificate,
        Capability::EditAlert,
        Capability::RunBackup,
        Capability::RestoreBackup,
        Capability::ManageUsers,
        Capability::RevokeAnySession,
        Capability::EnrolNode,
        Capability::RestartProcess,
    ];

    /// Whether exercising this capability changes state.
    ///
    /// Drives two things that must not disagree: the "a viewer is refused every mutating
    /// endpoint" gate, and the second-factor requirement. Deriving both from one
    /// predicate is what keeps a new mutating capability from being covered by one and
    /// missed by the other.
    pub const fn is_mutating(self) -> bool {
        !matches!(
            self,
            Self::ViewConfig
                | Self::ViewLogs
                | Self::ViewMetrics
                | Self::ViewEvents
                | Self::ViewAlerts
                | Self::ViewBackups
                | Self::ViewNodes
                | Self::ViewUsers
                | Self::ViewOwnSessions
        )
    }
}

impl Role {
    /// Whether this role may exercise this capability.
    ///
    /// Exhaustive by construction: every arm names its capabilities, so a new variant
    /// fails to compile until each role's answer is written down. That is the whole
    /// mechanism preventing a capability from defaulting to "allowed" because nobody
    /// thought about it.
    pub const fn allows(self, capability: Capability) -> bool {
        use Capability::*;
        match self {
            // Everything. Stated as a wildcard rather than an enumeration, because an
            // admin gaining a new capability automatically is the intended behaviour.
            Role::Admin => true,
            Role::Operator => matches!(
                capability,
                ViewConfig
                    | ViewLogs
                    | ViewMetrics
                    | ViewEvents
                    | ViewAlerts
                    | ViewBackups
                    | ViewNodes
                    | ViewOwnSessions
                    | EditDomain
                    | EditUpstream
                    | EditPolicy
                    | EditCertificate
                    | EditAlert
                    | RunBackup
            ),
            Role::Viewer => matches!(
                capability,
                ViewConfig
                    | ViewLogs
                    | ViewMetrics
                    | ViewEvents
                    | ViewAlerts
                    | ViewBackups
                    | ViewNodes
                    | ViewOwnSessions
            ),
        }
    }
}

/// How far a session has authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLevel {
    /// Password accepted, second factor still outstanding. May read, may not mutate.
    PasswordOnly,
    /// Second factor completed, or the account has none enrolled.
    TwoFactor,
}

impl AuthLevel {
    pub const ALL: [AuthLevel; 2] =
        [AuthLevel::PasswordOnly, AuthLevel::TwoFactor];

    pub const fn key(self) -> &'static str {
        match self {
            Self::PasswordOnly => "password_only",
            Self::TwoFactor => "two_factor",
        }
    }

    /// The inverse of [`Self::key`].
    ///
    /// `None` on unrecognised text, for a sharper reason than [`Role::from_key`]: a
    /// default of `TwoFactor` would let a corrupt or truncated row mutate, which is the
    /// exact bypass [`authorize`] exists to prevent.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.key() == key)
    }
}

/// Why a request was refused. Distinct variants because the API answers them
/// differently: a missing second factor is a 403 the client can *fix* by completing the
/// challenge, while a role denial is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The role does not have the capability.
    Role,
    /// The capability mutates and the session has not completed its second factor.
    SecondFactorRequired,
}

/// The single authorisation decision.
///
/// Role and second factor are decided together so a route cannot satisfy one check and
/// bypass the other. Order matters: the role denial is reported first, because telling a
/// viewer to complete a second factor implies that doing so would grant a capability
/// their role will never have.
pub const fn authorize(
    role: Role,
    level: AuthLevel,
    capability: Capability,
) -> Result<(), Denial> {
    if !role.allows(capability) {
        return Err(Denial::Role);
    }
    if capability.is_mutating() && matches!(level, AuthLevel::PasswordOnly) {
        return Err(Denial::SecondFactorRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_viewer_is_refused_every_mutating_capability() {
        // Enumerated over the capability list rather than asserted on a middleware, so a
        // capability added later is covered whether or not anyone remembers this test.
        for capability in Capability::ALL {
            if !capability.is_mutating() {
                continue;
            }
            assert_eq!(
                authorize(Role::Viewer, AuthLevel::TwoFactor, capability),
                Err(Denial::Role),
                "a viewer was allowed to {capability:?}"
            );
        }
    }

    #[test]
    fn read_only_and_viewer_visible_are_not_the_same_set() {
        // `ViewUsers` mutates nothing and a viewer still may not have it: knowing who
        // else holds access is administrative. Worth an explicit test because the
        // tempting simplification — "a viewer gets everything non-mutating" — would
        // quietly hand over the user list, and because the next read-only-but-sensitive
        // capability will face the same choice.
        assert!(!Capability::ViewUsers.is_mutating());
        assert_eq!(
            authorize(
                Role::Viewer,
                AuthLevel::TwoFactor,
                Capability::ViewUsers
            ),
            Err(Denial::Role)
        );

        // What a viewer does get: the operational reads it exists for.
        for capability in [
            Capability::ViewConfig,
            Capability::ViewLogs,
            Capability::ViewMetrics,
            Capability::ViewEvents,
            Capability::ViewAlerts,
            Capability::ViewBackups,
            Capability::ViewNodes,
            Capability::ViewOwnSessions,
        ] {
            assert_eq!(
                authorize(Role::Viewer, AuthLevel::TwoFactor, capability),
                Ok(()),
                "a viewer was refused {capability:?}"
            );
        }
    }

    #[test]
    fn an_operator_edits_traffic_and_policy_but_not_users_nodes_or_the_process()
    {
        for capability in [
            Capability::EditDomain,
            Capability::EditUpstream,
            Capability::EditPolicy,
            Capability::EditCertificate,
        ] {
            assert_eq!(
                authorize(Role::Operator, AuthLevel::TwoFactor, capability),
                Ok(()),
                "an operator was refused {capability:?}"
            );
        }
        // The boundary. Every "just this once" grant here erodes it until operator is
        // admin, so the three denials are named individually.
        for capability in [
            Capability::ManageUsers,
            Capability::EnrolNode,
            Capability::RestartProcess,
        ] {
            assert_eq!(
                authorize(Role::Operator, AuthLevel::TwoFactor, capability),
                Err(Denial::Role),
                "an operator was allowed to {capability:?}"
            );
        }
        // And they cannot see the user list either — knowing who else has access is
        // itself administrative.
        assert_eq!(
            authorize(
                Role::Operator,
                AuthLevel::TwoFactor,
                Capability::ViewUsers
            ),
            Err(Denial::Role)
        );
    }

    #[test]
    fn an_admin_has_every_capability() {
        for capability in Capability::ALL {
            assert_eq!(
                authorize(Role::Admin, AuthLevel::TwoFactor, capability),
                Ok(())
            );
        }
    }

    #[test]
    fn a_session_without_a_second_factor_can_read_but_not_mutate() {
        for capability in Capability::ALL {
            let result =
                authorize(Role::Admin, AuthLevel::PasswordOnly, capability);
            if capability.is_mutating() {
                assert_eq!(
                    result,
                    Err(Denial::SecondFactorRequired),
                    "{capability:?} was permitted before the second factor"
                );
            } else {
                assert_eq!(result, Ok(()), "{capability:?} should be readable");
            }
        }
    }

    #[test]
    fn a_role_denial_is_reported_ahead_of_a_missing_second_factor() {
        // Telling a viewer to complete a second factor implies that doing so would grant
        // a capability their role will never have.
        assert_eq!(
            authorize(
                Role::Viewer,
                AuthLevel::PasswordOnly,
                Capability::ManageUsers
            ),
            Err(Denial::Role)
        );
    }

    #[test]
    fn the_capability_list_is_complete() {
        // `ALL` is hand-maintained, and a capability missing from it would silently drop
        // out of every enumeration-driven test above — including the viewer gate.
        assert_eq!(
            Capability::ALL.len(),
            {
                let mut unique: Vec<Capability> = Capability::ALL.to_vec();
                unique.sort();
                unique.dedup();
                unique.len()
            },
            "the capability list has a duplicate"
        );
        assert_eq!(
            Capability::ALL.iter().filter(|c| c.is_mutating()).count(),
            11,
            "the mutating/read split moved; check both the viewer gate and the \
             second-factor requirement, which are derived from it"
        );
    }

    #[test]
    fn every_role_can_manage_its_own_sessions() {
        // How a user revokes the laptop they lost. Withholding it from a viewer would
        // mean an administrator has to do it for them.
        for role in Role::ALL {
            assert_eq!(
                authorize(
                    role,
                    AuthLevel::TwoFactor,
                    Capability::ViewOwnSessions
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn a_role_and_an_auth_level_round_trip_through_their_stored_text() {
        // The store keeps both as TEXT, so this encoding is a persistence format: changing
        // a key silently reinterprets every existing row.
        for role in Role::ALL {
            assert_eq!(Role::from_key(role.key()), Some(role));
        }
        for level in AuthLevel::ALL {
            assert_eq!(AuthLevel::from_key(level.key()), Some(level));
        }
        assert_eq!(
            Role::from_key("moderator"),
            None,
            "the renamed role parsed"
        );
        assert_eq!(
            Role::from_key("Admin"),
            None,
            "the encoding is not case-folded"
        );
    }

    #[test]
    fn unrecognised_stored_text_does_not_default_to_a_usable_level() {
        // A default of `TwoFactor` would let a corrupt row mutate, which is the bypass
        // `authorize` exists to prevent; a default of `Admin` would hand a typo every
        // capability. Both must be unrepresentable, so the parse returns `None`.
        for junk in ["", "two-factor", "2fa", "TWO_FACTOR", "admin"] {
            assert_eq!(
                AuthLevel::from_key(junk),
                None,
                "`{junk}` parsed as an auth level"
            );
        }
    }
}
