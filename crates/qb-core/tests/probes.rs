//! Lazy-probe bookkeeping: when a login is due, singleflight, back-off, timeouts and results.

mod common;

use common::{NOW, cand, core, login_view, observe, on, outcome, pick, role, spec, step};
use qb_core::{
    Core, LoginStatus, OutcomeClass, PROBE_TIMEOUT_S, ProbeError, ProbeJob, ProbeOutcome,
    ProbeSpec, Source, WindowObservation,
};

const AGENT: &str = "agent-1";

/// The common spec with probes on (back-off 30 s doubling to 120 s) and a worker role whose
/// difficulty 1 runs on `vendor-a` only, so a pick considers `login-1` and `login-2`.
fn probing() -> Core {
    let mut s = spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "model-small", 1)])],
        Vec::new(),
    )]);
    s.probe = Some(ProbeSpec {
        backoff_initial_s: 30,
        backoff_max_s: 120,
    });
    core(s)
}

fn logins(names: &[&str]) -> Vec<String> {
    names.iter().map(|&n| n.to_owned()).collect()
}

/// A worker pick at `at`; it wants every considered login with stale data.
fn want(core: &mut Core, at: u64) {
    let mut input = common::input("worker", qb_core::Target::Difficulty(1), None);
    input.client = "client-a".into();
    core.pick(&input, at);
}

fn next(core: &mut Core, names: &[&str], at: u64) -> Option<ProbeJob> {
    core.probe_next(AGENT, &logins(names), at)
}

fn window(name: &str, used: f64) -> WindowObservation {
    WindowObservation {
        name: name.into(),
        used,
        resets_at: Some(NOW + 3600),
    }
}

#[test]
fn a_pick_on_stale_logins_makes_each_due_once() {
    let mut core = probing();
    assert_eq!(next(&mut core, &["login-1"], NOW), None, "nobody asked yet");
    want(&mut core, NOW);
    let job = next(&mut core, &["login-1", "login-2"], NOW).expect("due");
    assert_eq!(job.login, "login-1", "the agent's order");
    assert_eq!(next(&mut core, &["login-1"], NOW), None, "in flight");
    want(&mut core, NOW + 1);
    assert_eq!(next(&mut core, &["login-1"], NOW + 1), None, "singleflight");
    let other = next(&mut core, &["login-1", "login-2"], NOW + 1).expect("login-2 is due");
    assert_eq!(other.login, "login-2");
    assert_ne!(other.id, job.id);
    assert_eq!(
        next(&mut core, &["login-3"], NOW + 1),
        None,
        "not a candidate"
    );
    assert_eq!(next(&mut core, &["login-9"], NOW + 1), None, "undeclared");
}

#[test]
fn fresh_or_freshly_reported_logins_are_not_probed() {
    let mut core = probing();
    observe(
        &mut core,
        "login-1",
        &[("five_hour", 0.1, None), ("seven_day", 0.1, None)],
        NOW,
    );
    want(&mut core, NOW);
    assert_eq!(next(&mut core, &["login-1"], NOW), None, "fresh");
    observe(&mut core, "login-2", &[("five_hour", 0.1, None)], NOW);
    assert_eq!(
        next(&mut core, &["login-2"], NOW),
        None,
        "a report after the pick satisfies it"
    );
}

#[test]
fn probes_off_hand_out_nothing() {
    let mut core = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "model-small", 1)])],
        Vec::new(),
    )]));
    pick(&mut core, "worker", 1, None);
    assert_eq!(next(&mut core, &["login-1", "login-2"], NOW), None);
}

#[test]
fn back_off_doubles_to_the_cap_honours_retry_after_and_resets_on_success() {
    let mut core = probing();
    let mut t = NOW;
    want(&mut core, t);
    let mut job = next(&mut core, &["login-1"], t).expect("due");
    let limited = |retry_after_s| ProbeOutcome::Http429 { retry_after_s };
    let table = [
        (ProbeOutcome::Error, 30),
        (ProbeOutcome::Error, 60),
        (ProbeOutcome::Error, 120),
        (ProbeOutcome::Error, 120),
        (ProbeOutcome::Ok(Vec::new()), 0),
        (limited(Some(100)), 100),
        (limited(Some(10)), 60),
        (limited(None), 120),
        (ProbeOutcome::Ok(Vec::new()), 0),
        (ProbeOutcome::Error, 30),
    ];
    for (i, (result, wait)) in table.into_iter().enumerate() {
        core.probe_result(job.id, AGENT, &result, t)
            .unwrap_or_else(|e| panic!("row {i}: {e:?}"));
        want(&mut core, t);
        if wait > 0 {
            assert_eq!(
                next(&mut core, &["login-1"], t + wait - 1),
                None,
                "row {i}: still backing off"
            );
        }
        t += wait;
        job = next(&mut core, &["login-1"], t)
            .unwrap_or_else(|| panic!("row {i}: due after {wait} s"));
    }
}

#[test]
fn a_job_without_result_times_out_as_a_failure() {
    let mut core = probing();
    want(&mut core, NOW);
    let job = next(&mut core, &["login-1"], NOW).expect("due");
    want(&mut core, NOW + PROBE_TIMEOUT_S - 1);
    assert_eq!(
        next(&mut core, &["login-1"], NOW + PROBE_TIMEOUT_S - 1),
        None
    );
    let timed_out = NOW + PROBE_TIMEOUT_S;
    assert_eq!(
        core.probe_result(job.id, AGENT, &ProbeOutcome::Ok(Vec::new()), timed_out),
        Err(ProbeError::UnknownProbe),
        "a late result changes nothing"
    );
    want(&mut core, timed_out);
    assert_eq!(next(&mut core, &["login-1"], timed_out + 29), None);
    assert!(next(&mut core, &["login-1"], timed_out + 30).is_some());
}

#[test]
fn auth_dead_logins_are_never_due() {
    let mut core = probing();
    for _ in 0..2 {
        outcome(&mut core, on("login-1"), OutcomeClass::Http401, None, NOW).expect("known");
    }
    want(&mut core, NOW);
    assert_eq!(next(&mut core, &["login-1"], NOW), None);
    assert!(next(&mut core, &["login-2"], NOW).is_some());
}

#[test]
fn next_deadline_includes_job_timeouts_and_back_off_ends() {
    let mut core = probing();
    want(&mut core, NOW);
    let job = next(&mut core, &["login-1"], NOW).expect("due");
    assert_eq!(core.next_deadline(), Some(NOW + PROBE_TIMEOUT_S));
    core.probe_result(job.id, AGENT, &ProbeOutcome::Error, NOW + 10)
        .expect("in flight");
    assert_eq!(core.next_deadline(), Some(NOW + 10 + 30));
}

#[test]
fn an_ok_result_shows_as_probe_data_and_ignores_undeclared_windows() {
    let mut core = probing();
    want(&mut core, NOW);
    let job = next(&mut core, &["login-1"], NOW).expect("due");
    let result = ProbeOutcome::Ok(vec![
        window("five_hour", 0.25),
        window("seven_day_sonnet", 0.5),
    ]);
    assert_eq!(
        core.probe_result(job.id, AGENT, &result, NOW),
        Ok(("login-1".to_owned(), LoginStatus::Ok))
    );
    let view = login_view(&core, "login-1", NOW);
    let windows: Vec<_> = view
        .windows
        .iter()
        .map(|w| (w.name.as_str(), w.used, w.source, w.observed_at))
        .collect();
    assert_eq!(
        windows,
        [
            ("five_hour", 0.25, Source::Probe, NOW),
            ("seven_day", 0.0, Source::Assumed, 0)
        ]
    );
}

#[test]
fn a_401_result_steps_auth_like_a_report() {
    let mut core = probing();
    let mut statuses = Vec::new();
    for t in [NOW, NOW + 30] {
        want(&mut core, t);
        let job = next(&mut core, &["login-1"], t).expect("due");
        let (_, status) = core
            .probe_result(job.id, AGENT, &ProbeOutcome::Http401, t)
            .expect("in flight");
        statuses.push(status);
    }
    assert_eq!(statuses, [LoginStatus::AuthStale, LoginStatus::AuthDead]);
}

#[test]
fn refused_results_change_nothing() {
    let mut core = probing();
    want(&mut core, NOW);
    let job = next(&mut core, &["login-1"], NOW).expect("due");
    let ok = ProbeOutcome::Ok(vec![window("five_hour", 0.25)]);
    let before = login_view(&core, "login-1", NOW);
    let refusals = [
        (job.id + 1, AGENT, ok.clone(), ProbeError::UnknownProbe),
        (job.id, "agent-2", ok.clone(), ProbeError::OtherClient),
        (
            job.id,
            AGENT,
            ProbeOutcome::Ok(vec![window("five_hour", 1.5)]),
            ProbeError::InvalidUtilization,
        ),
    ];
    for (id, client, result, error) in refusals {
        assert_eq!(core.probe_result(id, client, &result, NOW), Err(error));
        assert_eq!(login_view(&core, "login-1", NOW), before, "{error:?}");
    }
    assert!(
        core.probe_result(job.id, AGENT, &ok, NOW).is_ok(),
        "the job is still in flight for its agent"
    );
}
