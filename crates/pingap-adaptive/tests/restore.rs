//! The startup restore path: what happens to a stored baseline offered back
//! to the registry, in one sequential sweep — the outcome matrix depends on
//! the process-global registry existing or not, so the cases run in order
//! inside one test rather than as parallel tests.

use pingap_adaptive::{
    Adaptive, Baseline, HourlyProfile, RestoreOutcome, baselines,
    domain_state_snapshot, restore_baseline,
};
use pingap_config::PluginConf;
use std::time::{SystemTime, UNIX_EPOCH};

fn plugin_conf() -> PluginConf {
    toml::from_str(
        r#"category = "adaptive"
           enabled = true
           client_ip_from_peer = true
           max_baseline_age_days = 30
        "#,
    )
    .expect("config parses")
}

fn baseline(learned_at_secs: u64) -> Baseline {
    Baseline {
        profiles: (0..24).map(|_| HourlyProfile::new(64)).collect(),
        learned_at_secs,
    }
}

#[test]
fn the_restore_outcome_matrix_in_one_startup_sweep() {
    let now = SystemTime::now();
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // Before any adaptive plugin exists there is no registry to restore into,
    // and the published state is honestly empty.
    assert_eq!(
        restore_baseline("a.test", baseline(now_secs), now),
        RestoreOutcome::Disabled
    );
    assert!(domain_state_snapshot().is_empty());

    // The first enabled plugin creates the process registry.
    Adaptive::try_from(&plugin_conf()).expect("builds");

    // A fresh baseline is accepted: the learner resumes from it uncalibrated,
    // re-earning calibration from live samples rather than trusting the
    // restored aggregate.
    assert_eq!(
        restore_baseline("a.test", baseline(now_secs), now),
        RestoreOutcome::Restored
    );
    let state = domain_state_snapshot()
        .get("a.test")
        .expect("the restored domain has a learner")
        .clone();
    assert!(!state.calibrated, "restored learners start uncalibrated");
    assert_eq!(state.samples, 0);
    assert_eq!(state.discarded_baselines, 0);

    // A baseline past max_baseline_age_days is discarded, visibly: the learner
    // stays in place with the discard counted on it, so a stale store row is
    // published state, not a silent drop.
    let stale_secs = now_secs.saturating_sub(31 * 86_400);
    assert_eq!(
        restore_baseline("stale.test", baseline(stale_secs), now),
        RestoreOutcome::Discarded
    );
    let rows = domain_state_snapshot();
    assert_eq!(
        rows.get("stale.test")
            .expect("the learner stays after a discard")
            .discarded_baselines,
        1
    );

    // A malformed baseline — the wrong profile count — is discarded the same
    // way rather than panicking on a corrupted row.
    let mut malformed = baseline(now_secs);
    malformed.profiles.pop();
    assert_eq!(
        restore_baseline("malformed.test", malformed, now),
        RestoreOutcome::Discarded
    );

    // Domain capacity caps the sweep: filling the registry, then one more.
    let mut saw_capacity = false;
    for i in 0..300 {
        let outcome =
            restore_baseline(&format!("fill-{i:03}"), baseline(now_secs), now);
        if outcome == RestoreOutcome::Capacity {
            saw_capacity = true;
            break;
        }
        assert_eq!(
            outcome,
            RestoreOutcome::Restored,
            "fill domains restore until capacity, not {outcome:?}"
        );
    }
    assert!(
        saw_capacity,
        "the registry must reach domain capacity within 300 extra domains"
    );

    // The write-back source sees every learner the sweep created, keyed by
    // the label it was restored under.
    let learned = baselines();
    assert!(learned.contains_key("a.test"));
    assert!(learned.contains_key("fill-000"));
    assert_eq!(
        learned.len(),
        domain_state_snapshot().len(),
        "baselines and the published state describe the same learners"
    );
}
