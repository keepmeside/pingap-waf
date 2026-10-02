use pingap_challenge::plugin::Challenge;
use pingap_challenge::{ChallengeConfig, ChallengeKind};

#[test]
fn enabled_challenge_rejects_an_unusable_reserved_prefix() {
    for prefix in ["/", "", "//challenge/", "/challenge"] {
        let config = ChallengeConfig {
            enabled: true,
            secret: "secret".into(),
            prefix: prefix.into(),
            client_ip_from_peer: true,
            ..Default::default()
        };
        assert!(config.validate().is_err(), "accepted prefix {prefix:?}");
    }
    let config = ChallengeConfig {
        enabled: true,
        secret: "secret".into(),
        kind: ChallengeKind::Pow,
        client_ip_from_peer: true,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn enabled_challenge_requires_a_secret_and_a_trust_anchor() {
    let missing_secret = ChallengeConfig {
        enabled: true,
        client_ip_from_peer: true,
        ..Default::default()
    };
    assert!(missing_secret.validate().is_err());
    let missing_anchor = ChallengeConfig {
        enabled: true,
        secret: "secret".into(),
        ..Default::default()
    };
    assert!(missing_anchor.validate().is_err());
}

/// The missing secret fails construction, not just validation: an enabled
/// challenge with no secret would sign its pass cookies with an empty key,
/// which is a key anyone can forge, so there is no default to fall back to —
/// the plugin refuses to exist and the location fails toward its configured
/// refusal rather than serving a challenge tier no secret protects.
#[test]
fn an_enabled_challenge_with_no_secret_fails_construction() {
    let err = match Challenge::new(ChallengeConfig {
        enabled: true,
        client_ip_from_peer: true,
        ..Default::default()
    }) {
        Ok(_) => {
            panic!("an enabled challenge with no secret must not construct")
        },
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(message.contains("secret"), "names the key: {message}");
    // A disabled challenge constructs without one: the tier is off, so no
    // cookie is ever signed and there is no key to require.
    Challenge::new(ChallengeConfig {
        client_ip_from_peer: true,
        ..Default::default()
    })
    .expect("a disabled challenge constructs without a secret");
}

#[test]
fn a_descending_escalation_ladder_is_refused_at_config_load() {
    // `[8,2]` would make more failures earn a *lower* challenge level: the
    // ladder maps thresholds onto tiers, so it must be non-decreasing.
    let inverted = ChallengeConfig {
        enabled: true,
        secret: "secret".into(),
        client_ip_from_peer: true,
        ladder: vec![8, 2],
        ..Default::default()
    };
    let err = inverted.validate().expect_err("descending ladder");
    assert!(err.to_string().contains("ladder"), "names the key: {err}");
    // The default and a strictly-increasing ladder both validate.
    for ladder in [vec![2, 4, 8], vec![1, 1, 3]] {
        let config = ChallengeConfig {
            enabled: true,
            secret: "secret".into(),
            client_ip_from_peer: true,
            ladder,
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "rejected a valid ladder");
    }
}
