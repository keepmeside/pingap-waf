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
