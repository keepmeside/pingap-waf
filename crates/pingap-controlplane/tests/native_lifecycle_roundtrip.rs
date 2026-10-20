use pingap_controlplane::events::{
    EventQueue, EventWriter, NativeActor, NativeKind, NativeLifecycle, Verdict,
    WafEvent,
};
use pingap_controlplane::metrics::{Retention, sweep};
use pingap_controlplane::repository::{TimeRange, WafEventFilter};
use pingap_controlplane::{ControlPlaneStore, TursoStore};
use std::sync::Arc;

fn event(kind: NativeKind, at: u64) -> NativeLifecycle {
    NativeLifecycle {
        version: 1,
        kind,
        id: format!("epoch-{}", kind.action()),
        epoch: "epoch".into(),
        profile: "behaviour:auth".into(),
        domain: "a.test".into(),
        client_ip: "::1".into(),
        scenario: "login".into(),
        mode: if kind == NativeKind::Detected {
            "detect"
        } else {
            "block"
        }
        .into(),
        created_at_ms: 1000000,
        expires_at_ms: Some(1001000),
        observed_at_ms: at,
        actor: NativeActor::default(),
        reason: if kind == NativeKind::Released {
            "operator_release"
        } else {
            "threshold"
        }
        .into(),
    }
}
#[tokio::test]
async fn all_four_lifecycle_types_preserve_transition_time_and_outlive_telemetry()
 {
    let dir = tempfile::tempdir().expect("test fixture succeeds");
    let store = Arc::new(
        TursoStore::open(
            dir.path()
                .join("history.db")
                .to_str()
                .expect("test fixture succeeds"),
        )
        .await
        .expect("test fixture succeeds"),
    );
    store.migrate().await.expect("test fixture succeeds");
    let queue = Arc::new(EventQueue::new(16).expect("test fixture succeeds"));
    for (i, kind) in [
        NativeKind::Detected,
        NativeKind::Created,
        NativeKind::Released,
        NativeKind::Expired,
    ]
    .into_iter()
    .enumerate()
    {
        queue.offer_native(event(kind, 1000000 + i as u64 * 1000));
    }
    queue.offer(WafEvent {
        node: "test".into(),
        domain: "a.test".into(),
        profile: "behaviour:auth".into(),
        rule_id: None,
        category: Some("native.abuse.login".into()),
        severity: None,
        score: 0,
        verdict: Verdict::Detect,
        client_ip: Some("::1".into()),
        method: None,
        uri: None,
        created_at: 1000,
    });
    let writer = EventWriter::new(queue.clone(), store.clone());
    assert_eq!(writer.flush().await.expect("test fixture succeeds"), 5);
    assert_eq!(writer.flush().await.expect("test fixture succeeds"), 0);
    let rows = store
        .read_activity(TimeRange::default())
        .await
        .expect("test fixture succeeds");
    assert_eq!(rows.len(), 4);
    for row in &rows {
        let detail: serde_json::Value = serde_json::from_str(
            row.detail.as_deref().expect("test fixture succeeds"),
        )
        .expect("test fixture succeeds");
        assert_eq!(detail["version"], 1);
        assert_eq!(detail["profile"], "behaviour:auth");
        assert_eq!(
            row.created_at,
            detail["observed_at_ms"]
                .as_u64()
                .expect("test fixture succeeds") as i64
                / 1000
        );
        assert_eq!(row.actor_username, "system");
        assert_eq!(row.target, detail["id"]);
    }
    let telemetry = store
        .read_waf_events(WafEventFilter::default())
        .await
        .expect("test fixture succeeds");
    assert_eq!(telemetry.len(), 1);
    assert!(!telemetry[0].blocked);
    for days in [8, 365] {
        sweep(
            store.as_ref(),
            &Retention {
                waf_events: 7 * 86400,
                performance_metrics: 7 * 86400,
            },
            1000 + days * 86400,
        )
        .await
        .expect("test fixture succeeds");
        assert_eq!(
            store
                .read_activity(TimeRange::default())
                .await
                .expect("test fixture succeeds")
                .len(),
            4
        );
        assert!(
            store
                .read_waf_events(WafEventFilter::default())
                .await
                .expect("test fixture succeeds")
                .is_empty()
        );
    }
}
#[tokio::test]
async fn failed_storage_retains_bounded_unacknowledged_lifecycle_and_recovers()
{
    let dir = tempfile::tempdir().expect("test fixture succeeds");
    let store = Arc::new(
        TursoStore::open(
            dir.path()
                .join("history.db")
                .to_str()
                .expect("test fixture succeeds"),
        )
        .await
        .expect("test fixture succeeds"),
    );
    let queue = Arc::new(EventQueue::new(2).expect("test fixture succeeds"));
    queue.offer_native(event(NativeKind::Created, 1000000));
    queue.offer_native(event(NativeKind::Expired, 1002000));
    let writer = EventWriter::new(queue.clone(), store.clone());
    assert!(writer.flush().await.is_err());
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.dropped_lifecycle(), 0);
    queue.offer_native(event(NativeKind::Detected, 1003000));
    assert_eq!(queue.dropped_lifecycle(), 1);
    assert_eq!(queue.dropped_native_detection(), 1);
    store.migrate().await.expect("test fixture succeeds");
    assert_eq!(writer.flush().await.expect("test fixture succeeds"), 2);
    assert_eq!(
        store
            .read_activity(TimeRange::default())
            .await
            .expect("test fixture succeeds")
            .len(),
        2
    );
    assert_eq!(writer.flush().await.expect("test fixture succeeds"), 0);
}

#[tokio::test]
async fn removed_actor_is_preserved_as_text_without_a_dangling_foreign_key() {
    let dir = tempfile::tempdir().expect("test fixture succeeds");
    let store = Arc::new(
        TursoStore::open(
            dir.path()
                .join("history.db")
                .to_str()
                .expect("test fixture succeeds"),
        )
        .await
        .expect("test fixture succeeds"),
    );
    store.migrate().await.expect("test fixture succeeds");
    let queue = Arc::new(EventQueue::new(4).expect("test fixture succeeds"));
    let mut released = event(NativeKind::Released, 1001000);
    released.actor = NativeActor {
        id: Some("removed-user".into()),
        username: "remembered-name".into(),
    };
    queue.offer_native(released);
    let writer = EventWriter::new(queue.clone(), store.clone());
    assert_eq!(writer.flush().await.expect("test fixture succeeds"), 1);
    let rows = store
        .read_activity(TimeRange::default())
        .await
        .expect("test fixture succeeds");
    assert_eq!(rows[0].actor_username, "remembered-name");
    assert_eq!(rows[0].actor_id, None);
    assert!(
        rows[0]
            .detail
            .as_ref()
            .expect("test fixture succeeds")
            .contains("removed-user")
    );
}
#[tokio::test]
async fn partial_flush_retries_only_unacknowledged_rows() {
    let dir = tempfile::tempdir().expect("test fixture succeeds");
    let path = dir.path().join("history.db");
    let store = Arc::new(
        TursoStore::open(path.to_str().expect("test fixture succeeds"))
            .await
            .expect("test fixture succeeds"),
    );
    store.migrate().await.expect("test fixture succeeds");
    // The schema fault is confined to this disposable fixture. The first native
    // write succeeds, while the subsequent WAF batch cannot reach its table.
    let db = turso::Builder::new_local(
        path.to_str().expect("test fixture succeeds"),
    )
    .build()
    .await
    .expect("test fixture succeeds");
    db.connect()
        .expect("test fixture succeeds")
        .execute("DROP TABLE waf_events", ())
        .await
        .expect("test fixture succeeds");
    let queue = Arc::new(EventQueue::new(4).expect("test fixture succeeds"));
    queue.offer_native(event(NativeKind::Created, 1000000));
    queue.offer(WafEvent {
        node: "test".into(),
        domain: "a.test".into(),
        profile: "waf:test".into(),
        rule_id: None,
        category: None,
        severity: None,
        score: 0,
        verdict: Verdict::Block,
        client_ip: None,
        method: None,
        uri: None,
        created_at: 1000,
    });
    let writer = EventWriter::new(queue.clone(), store.clone());
    for _ in 0..2 {
        assert!(writer.flush().await.is_err());
        assert_eq!(queue.len(), 1);
        let rows = store
            .read_activity(TimeRange::default())
            .await
            .expect("test fixture succeeds");
        assert_eq!(rows.len(), 1, "acknowledged creation was duplicated");
    }
}
