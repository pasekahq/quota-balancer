//! Journal records: the live state as records, and restoring them into a fresh core.

mod common;

use common::{DAY, HOUR, NOW, cand, core, on, outcome, pick_for, release, role, spec, step};
use qb_core::{
    Auth, Core, LeaseRecord, Marks, OutcomeClass, Reason, Record, RestoreError, Verdict,
};

fn worker() -> Core {
    core(spec(vec![role(
        "worker",
        vec![step(
            1,
            vec![cand("vendor-a", "a", 1), cand("vendor-b", "b", 2)],
        )],
        vec![],
    )]))
}

fn lease_of(v: &Verdict) -> u64 {
    match v {
        Verdict::Run(g, _) => g.lease,
        other => panic!("expected run, got {other:?}"),
    }
}

fn lease(id: u64, login: &str, cost: Vec<f64>, expires_at: u64) -> Record {
    Record::Lease(LeaseRecord {
        id,
        login: login.into(),
        model: "a".into(),
        client: "test".into(),
        run_id: None,
        cost,
        expires_at,
        reason: None,
    })
}

#[test]
fn records_rebuild_leases_marks_and_the_lease_counter() {
    let mut live = worker();
    let first = lease_of(&pick_for(&mut live, "worker", 1, 30, NOW));
    let kept = lease_of(&pick_for(&mut live, "worker", 1, 20, NOW));
    release(&mut live, first, NOW);
    for (login, class, model) in [
        ("login-1", OutcomeClass::UsageLimit, None),
        ("login-2", OutcomeClass::ModelUnavailable, Some("a")),
        ("login-2", OutcomeClass::Http429, None),
        ("login-3", OutcomeClass::Http401, None),
        ("login-3", OutcomeClass::Http401, None),
    ] {
        outcome(&mut live, on(login), class, model, NOW).expect("known login");
    }

    let mut restored = worker();
    for _ in 0..2 {
        for r in live.records() {
            restored.restore(&r, NOW).expect("fits the config");
        }
        assert_eq!(restored.snapshot(NOW), live.snapshot(NOW));
        assert_eq!(restored.marks("login-2"), live.marks("login-2"));
    }
    assert_eq!(restored.marks("login-3").map(|m| m.auth), Some(Auth::Dead));
    assert_eq!(restored.lease(kept), live.lease(kept));
    assert_eq!(
        restored.lease(kept).and_then(|l| l.reason),
        Some(Reason::SpendBeforeReset)
    );

    assert_eq!(restored.records(), live.records());
    assert_eq!(live.records()[0], Record::Issued(2));
}

#[test]
fn releases_and_expiries_apply_in_record_order() {
    let mut c = worker();
    c.restore(&lease(257, "login-1", vec![0.1, 0.01], NOW + HOUR), NOW)
        .expect("fits");
    c.restore(&lease(514, "login-2", vec![0.1, 0.01], NOW + 60), NOW)
        .expect("fits");
    c.restore(&Record::Release(257), NOW + 10).expect("fits");
    assert_eq!(c.snapshot(NOW + 10).leases.len(), 1);
    c.tick(NOW + 60);
    assert_eq!(c.snapshot(NOW + 60).leases, []);
    assert_eq!(c.records(), [Record::Issued(2)]);
}

#[test]
fn a_lease_replaces_the_lease_in_its_slot() {
    let mut c = worker();
    c.restore(&lease(257, "login-1", vec![0.1, 0.01], NOW + HOUR), NOW)
        .expect("fits");
    c.restore(&lease(513, "login-2", vec![0.2, 0.02], NOW + HOUR), NOW)
        .expect("fits");
    let snap = c.snapshot(NOW);
    let ids: Vec<u64> = snap.leases.iter().map(|l| l.id).collect();
    assert_eq!(ids, [513]);
    assert_eq!(snap.logins[0].windows[0].reserved, 0.0);
    assert_eq!(snap.logins[1].windows[0].reserved, 0.2);
}

#[test]
fn records_that_do_not_fit_the_config_are_refused() {
    let mut c = worker();
    assert_eq!(
        c.restore(&lease(257, "login-9", vec![0.1, 0.01], NOW + HOUR), NOW),
        Err(RestoreError::UnknownLogin("login-9".into()))
    );
    assert_eq!(
        c.restore(&lease(257, "login-3", vec![0.1, 0.01], NOW + HOUR), NOW),
        Err(RestoreError::CostWindows {
            login: "login-3".into(),
            expected: 1,
            got: 2,
        })
    );
    assert_eq!(c.records(), [Record::Issued(0)]);

    let marks = Marks {
        model_dead: vec![("gone".into(), NOW + DAY), ("b".into(), NOW + DAY)],
        ..Marks::default()
    };
    c.restore(
        &Record::Marks {
            login: "login-3".into(),
            marks,
        },
        NOW,
    )
    .expect("unknown models are ignored");
    assert_eq!(
        c.marks("login-3").map(|m| m.model_dead),
        Some(vec![("b".to_owned(), NOW + DAY)])
    );
}
