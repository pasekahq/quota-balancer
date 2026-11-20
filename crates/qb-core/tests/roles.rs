//! Replacing the roles of a running core: new ladders steer the next pick, the live state stays.

mod common;

use common::{
    DAY, HOUR, NOW, cand, core, observe, on, outcome, pick, pick_for, ran, release, role, spec,
    step,
};
use qb_core::{Core, OutcomeClass, ReportSubject, SpecError, Verdict};

/// `old` on model `x`, `worker` on `y` at difficulty 1 and `a` at difficulty 2, all on vendor-a.
fn running() -> Core {
    core(spec(vec![
        role("old", vec![step(1, vec![cand("vendor-a", "x", 1)])], vec![]),
        role(
            "worker",
            vec![
                step(1, vec![cand("vendor-a", "y", 1)]),
                step(2, vec![cand("vendor-a", "a", 1)]),
            ],
            vec![],
        ),
    ]))
}

fn lease_of(v: &Verdict) -> u64 {
    match v {
        Verdict::Run(g, _) => g.lease,
        other => panic!("expected run, got {other:?}"),
    }
}

#[test]
fn new_roles_steer_the_next_pick_and_keep_leases_marks_and_windows() {
    let mut c = running();
    observe(
        &mut c,
        "login-1",
        &[("five_hour", 0.3, Some(NOW + HOUR))],
        NOW,
    );
    let lease = lease_of(&pick_for(&mut c, "old", 1, 30, NOW));
    outcome(
        &mut c,
        on("login-2"),
        OutcomeClass::ModelUnavailable,
        Some("a"),
        NOW,
    )
    .expect("declared model");
    let before = c.snapshot(NOW);
    let marks = c.marks("login-2");

    let worker = role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "b", 1)])],
        vec![],
    );
    c.set_roles(vec![worker]).expect("valid roles");

    assert_eq!(c.snapshot(NOW), before, "leases, windows and statuses stay");
    assert_eq!(c.marks("login-2"), marks, "a dead model keeps its mark");
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)), ("login-3", "b"));
    assert!(
        matches!(pick(&mut c, "old", 1, None), Verdict::Dead(_)),
        "a removed role serves no pick"
    );
    let status = outcome(
        &mut c,
        ReportSubject::Lease(lease),
        OutcomeClass::ModelUnavailable,
        None,
        NOW,
    );
    assert!(
        status.is_ok(),
        "the lease of a removed role keeps its model"
    );
    release(&mut c, lease, NOW);
    assert_eq!(c.lease(lease), None);

    c.tick(NOW + DAY);
    let marks = c.marks("login-2").expect("declared login");
    assert_eq!(marks.model_dead, [], "the moved mark still ends on time");
}

#[test]
fn refused_roles_change_nothing() {
    let mut c = running();
    let stray = role(
        "worker",
        vec![step(1, vec![cand("vendor-z", "b", 1)])],
        vec![],
    );
    assert_eq!(
        c.set_roles(vec![stray]),
        Err(SpecError::UnknownVendor("vendor-z".into()))
    );
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).1, "y");
    assert_eq!(ran(&pick(&mut c, "old", 1, None)).1, "x");
}

#[test]
fn the_running_roles_read_back_as_last_given() {
    let mut c = running();
    let names: Vec<&str> = c.roles().iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["old", "worker"]);
    let worker = role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "b", 1)])],
        vec![],
    );
    c.set_roles(vec![worker.clone()]).expect("valid roles");
    assert_eq!(c.roles(), std::slice::from_ref(&worker));
    let stray = role(
        "worker",
        vec![step(1, vec![cand("vendor-z", "b", 1)])],
        vec![],
    );
    assert!(c.set_roles(vec![stray]).is_err());
    assert_eq!(c.roles(), [worker], "a refused replacement keeps the roles");
}
