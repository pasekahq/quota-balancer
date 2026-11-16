//! Leases, reserved accounting, `retry_after` and the deadline heap.

mod common;

use common::{
    DAY, HOUR, NOW, cand, core, input, login_view, observe, on, outcome, pick, pick_for, ran,
    release, reserve, role, spec, step,
};
use qb_core::{Core, LeaseView, MAX_LEASES, OutcomeClass, Reason, Source, Target, Verdict};

/// `worker` step 1 on `vendor-b` (`login-3`, `five_hour` only).
fn vendor_b() -> Core {
    core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "b", 1)])],
        vec![],
    )]))
}

fn lease_of(v: &Verdict) -> u64 {
    match v {
        Verdict::Run(g, _) => g.lease,
        other => panic!("expected run, got {other:?}"),
    }
}

fn reserved(c: &Core, login: &str) -> Vec<f64> {
    login_view(c, login, NOW)
        .windows
        .iter()
        .map(|w| w.reserved)
        .collect()
}

#[test]
fn a_run_holds_a_lease_with_its_cost_until_release() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "a", 1)])],
        vec![],
    )]));
    let mut req = input("worker", Target::Difficulty(1), None);
    req.expected_minutes = Some(30);
    req.run_id = Some("run-1".into());
    let verdict = c.pick(&req, NOW);
    let Verdict::Run(g, _) = &verdict else {
        panic!("expected run, got {verdict:?}")
    };
    assert_eq!(g.expires_at, NOW + HOUR + 30 * 60);
    assert_eq!(
        c.snapshot(NOW).leases,
        [LeaseView {
            id: g.lease,
            login: "login-1".into(),
            model: "a".into(),
            client: "test".into(),
            run_id: Some("run-1".into()),
            expires_at: NOW + HOUR + 30 * 60,
        }]
    );
    // 0.01 of the 5 h window per minute; the 7 d window is 33.6 times longer.
    let r = reserved(&c, "login-1");
    assert!((r[0] - 0.3).abs() < 1e-12, "{r:?}");
    assert!((r[1] - 0.3 / 33.6).abs() < 1e-12, "{r:?}");
    assert_eq!(reserved(&c, "login-2"), [0.0, 0.0]);

    release(&mut c, g.lease, NOW);
    assert_eq!(c.snapshot(NOW).leases, []);
    assert_eq!(reserved(&c, "login-1"), [0.0, 0.0]);
    assert_eq!(
        outcome(
            &mut c,
            qb_core::ReportSubject::Lease(g.lease),
            OutcomeClass::Ok,
            None,
            NOW
        ),
        Err(qb_core::ReportError::UnknownLease),
        "a released lease is gone"
    );
}

#[test]
fn reserved_and_the_tasks_cost_count_against_admissibility() {
    let mut c = vendor_b();
    observe(
        &mut c,
        "login-3",
        &[("five_hour", 0.3, Some(NOW + 4 * HOUR))],
        NOW,
    );
    let first = lease_of(&pick_for(&mut c, "worker", 1, 30, NOW));
    let second = lease_of(&pick_for(&mut c, "worker", 1, 30, NOW + 10));
    assert_eq!(
        pick_for(&mut c, "worker", 1, 30, NOW + 20),
        Verdict::Wait {
            retry_after: NOW + HOUR + 30 * 60,
            reason: Reason::AllExhausted,
            stale: false,
        },
        "1 - 0.3 used - 0.6 reserved - 0.3 cost; the first lease expiry frees room"
    );
    assert_eq!(
        ran(&pick_for(&mut c, "worker", 1, 0, NOW + 20)).0,
        "login-3",
        "a task without cost still fits"
    );
    release(&mut c, first, NOW + 30);
    assert_eq!(
        ran(&pick_for(&mut c, "worker", 1, 30, NOW + 30)).0,
        "login-3"
    );
    release(&mut c, second, NOW + 40);
    let r = reserved(&c, "login-3");
    assert!((r[0] - 0.3).abs() < 1e-12, "{r:?}");
}

#[test]
fn a_reserve_only_block_waits_for_t_burn() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "a", 1)])],
        vec![reserve(1, "seven_day", 0.2)],
    )]));
    let resets = NOW + 3 * DAY;
    observe(&mut c, "login-1", &[("seven_day", 0.9, Some(resets))], NOW);
    observe(
        &mut c,
        "login-2",
        &[("seven_day", 1.0, Some(NOW + 4 * DAY))],
        NOW,
    );
    let t_burn = 12 * HOUR;
    let admissible_at = resets - t_burn + 1;
    let v = pick(&mut c, "worker", 1, None);
    assert!(
        matches!(v, Verdict::Wait { retry_after, .. } if retry_after == admissible_at),
        "{v:?}"
    );
    let at = |c: &mut Core, now| c.pick(&input("worker", Target::Difficulty(1), None), now);
    assert!(matches!(
        at(&mut c, admissible_at - 1),
        Verdict::Wait { .. }
    ));
    assert_eq!(ran(&at(&mut c, admissible_at)).0, "login-1");
}

#[test]
fn a_full_lease_table_waits_for_the_first_expiry() {
    let mut c = vendor_b();
    let mut first = None;
    for k in 0..MAX_LEASES as u64 {
        let id = lease_of(&pick_for(&mut c, "worker", 1, 0, NOW + k));
        first.get_or_insert(id);
    }
    assert_eq!(c.snapshot(NOW).leases.len(), MAX_LEASES);
    let full = pick_for(&mut c, "worker", 1, 0, NOW + 1000);
    assert_eq!(
        full,
        Verdict::Wait {
            retry_after: NOW + HOUR,
            reason: Reason::LeasesFull,
            stale: true,
        }
    );
    release(&mut c, first.expect("leases issued"), NOW + 1000);
    let again = lease_of(&pick_for(&mut c, "worker", 1, 0, NOW + 1000));
    assert_ne!(Some(again), first, "a reused slot gets a new id");
    assert_eq!(c.snapshot(NOW).leases.len(), MAX_LEASES);
    assert!(matches!(
        pick_for(&mut c, "worker", 1, 0, NOW + HOUR + 1),
        Verdict::Run(..)
    ));
}

#[test]
fn next_deadline_is_the_earliest_and_tick_applies_it() {
    let mut c = vendor_b();
    assert_eq!(c.next_deadline(), None);
    let lease = lease_of(&pick_for(&mut c, "worker", 1, 10, NOW));
    let expiry = NOW + HOUR + 600;
    assert_eq!(c.next_deadline(), Some(expiry));

    outcome(&mut c, on("login-3"), OutcomeClass::Http429, None, NOW).expect("known");
    assert_eq!(c.next_deadline(), Some(NOW + 60));
    c.tick(NOW + 59);
    assert_eq!(login_view(&c, "login-3", NOW).dead_until, Some(NOW + 60));
    c.tick(NOW + 60);
    assert_eq!(login_view(&c, "login-3", NOW).dead_until, None);
    assert_eq!(c.next_deadline(), Some(expiry));

    c.tick(expiry - 1);
    assert_eq!(c.snapshot(expiry).leases.len(), 1);
    c.tick(expiry);
    assert_eq!(c.snapshot(expiry).leases, []);
    assert_eq!(reserved(&c, "login-3"), [0.0]);
    assert_eq!(c.next_deadline(), None);
    assert!(
        outcome(
            &mut c,
            qb_core::ReportSubject::Lease(lease),
            OutcomeClass::Ok,
            None,
            expiry
        )
        .is_err()
    );
}

#[test]
fn window_staleness_and_resets_are_deadlines_too() {
    let mut c = vendor_b();
    let at = NOW + 2 * HOUR;
    observe(&mut c, "login-3", &[("five_hour", 0.6, Some(at))], NOW);
    assert_eq!(c.next_deadline(), Some(NOW + 301), "TTL 300 s");
    c.tick(NOW + 301);
    assert!(login_view(&c, "login-3", NOW + 301).windows[0].stale);
    assert_eq!(c.next_deadline(), Some(at));
    c.tick(at);
    let w = &login_view(&c, "login-3", at).windows[0];
    assert_eq!((w.used, w.source), (0.0, Source::Assumed));
    assert_eq!(c.next_deadline(), None);
}

#[test]
fn stale_heap_entries_are_skipped() {
    let mut c = vendor_b();
    let short = lease_of(&pick_for(&mut c, "worker", 1, 10, NOW));
    lease_of(&pick_for(&mut c, "worker", 1, 20, NOW));
    release(&mut c, short, NOW);
    assert_eq!(c.next_deadline(), Some(NOW + HOUR + 1200), "released lease");

    outcome(&mut c, on("login-3"), OutcomeClass::Http429, None, NOW).expect("known");
    outcome(&mut c, on("login-3"), OutcomeClass::Http429, None, NOW + 30).expect("known");
    assert_eq!(c.next_deadline(), Some(NOW + 90), "replaced back-off");
}
