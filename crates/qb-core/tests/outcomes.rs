//! Report outcome classes: login and (login, model) marks, and the pick scenarios they decide.

mod common;

use common::{
    DAY, HOUR, NOW, cand, core, input, login_view, observe, on, outcome, pick, pin, ran, role,
    spec, step,
};
use qb_core::{
    Core, LoginStatus, OutcomeClass, Reason, ReportError, ReportInput, ReportSubject, Target,
    Verdict, WindowObservation,
};

/// Role `worker`: step 1 `vendor-a/a` (tier 1), `vendor-b/b` (tier 2); step 2 `vendor-a/c`.
/// Role `single`: the same step 1 only.
fn two_vendors() -> Core {
    let step1 = || step(1, vec![cand("vendor-a", "a", 1), cand("vendor-b", "b", 2)]);
    core(spec(vec![
        role(
            "worker",
            vec![step1(), step(2, vec![cand("vendor-a", "c", 1)])],
            vec![],
        ),
        role("single", vec![step1()], vec![]),
    ]))
}

fn status(c: &Core, login: &str) -> (LoginStatus, Option<u64>) {
    let v = login_view(c, login, NOW);
    (v.status, v.dead_until)
}

fn auth_dead(c: &mut Core, login: &str) {
    for _ in 0..2 {
        outcome(c, on(login), OutcomeClass::Http401, None, NOW).expect("known login");
    }
}

#[test]
fn vendor_a_dead_moves_the_pick_to_vendor_b() {
    type Kill = fn(&mut Core, &str);
    let cases: [(&str, Kill); 2] = [
        ("usage_limit", |c, l| {
            outcome(c, on(l), OutcomeClass::UsageLimit, None, NOW).expect("known login");
        }),
        ("auth_dead", auth_dead),
    ];
    for (name, kill) in cases {
        let mut c = two_vendors();
        assert_eq!(ran(&pick(&mut c, "worker", 1, None)).1, "a", "{name}");
        kill(&mut c, "login-1");
        kill(&mut c, "login-2");
        let v = pick(&mut c, "worker", 1, None);
        assert_eq!(ran(&v), ("login-3", "b"), "{name}");
    }
}

#[test]
fn everything_dead_is_dead_and_everything_exhausted_waits() {
    let mut c = two_vendors();
    for l in ["login-1", "login-2", "login-3"] {
        auth_dead(&mut c, l);
    }
    assert_eq!(
        pick(&mut c, "single", 1, None),
        Verdict::Dead(Reason::AllDead)
    );

    let mut c = two_vendors();
    for (l, m) in [("login-1", "a"), ("login-2", "a"), ("login-3", "b")] {
        outcome(&mut c, on(l), OutcomeClass::ModelUnavailable, Some(m), NOW).expect("known");
    }
    assert_eq!(
        pick(&mut c, "single", 1, None),
        Verdict::Dead(Reason::AllDead),
        "a dead model does not count as a recovery time"
    );

    let mut c = two_vendors();
    auth_dead(&mut c, "login-1");
    outcome(
        &mut c,
        on("login-2"),
        OutcomeClass::ModelUnavailable,
        Some("a"),
        NOW,
    )
    .expect("known");
    auth_dead(&mut c, "login-3");
    assert_eq!(
        pick(&mut c, "single", 1, None),
        Verdict::Dead(Reason::AllDead),
        "mixed dead marks"
    );

    let mut c = two_vendors();
    for (l, resets) in [
        ("login-1", NOW + 2 * HOUR),
        ("login-2", NOW + HOUR),
        ("login-3", NOW + 3 * HOUR),
    ] {
        observe(&mut c, l, &[("five_hour", 1.0, Some(resets))], NOW);
        outcome(&mut c, on(l), OutcomeClass::UsageLimit, None, NOW).expect("known");
    }
    assert_eq!(
        pick(&mut c, "single", 1, None),
        Verdict::Wait {
            retry_after: NOW + HOUR,
            reason: Reason::AllExhausted,
            stale: true,
        },
        "all exhausted with known resets"
    );
}

type Obs<'a> = &'a [(&'a str, f64, Option<u64>)];
/// Name, reports in order, expected status and `dead_until`.
type Case<'a> = (
    &'a str,
    &'a [(OutcomeClass, Obs<'a>)],
    LoginStatus,
    Option<u64>,
);

#[test]
#[allow(clippy::too_many_lines)] // one flat table of cases reads best
fn report_classes_set_the_login_status_and_its_end() {
    let full_short = [
        ("five_hour", 1.0, Some(NOW + 2 * HOUR)),
        ("seven_day", 0.5, Some(NOW + 3 * DAY)),
    ];
    let near_full_both = [
        ("five_hour", 0.995, Some(NOW + HOUR)),
        ("seven_day", 1.0, Some(NOW + 2 * DAY)),
    ];
    let none_full = [
        ("five_hour", 0.5, Some(NOW + HOUR)),
        ("seven_day", 0.6, Some(NOW + 3 * DAY)),
    ];
    let fresh: Obs = &[("five_hour", 0.1, Some(NOW + HOUR))];
    let cases: [Case; 13] = [
        (
            "usage_limit: the full window's reset",
            &[(OutcomeClass::UsageLimit, &full_short)],
            LoginStatus::Exhausted,
            Some(NOW + 2 * HOUR),
        ),
        (
            "rejected: the earliest reset at or near 1.0",
            &[(OutcomeClass::Rejected, &near_full_both)],
            LoginStatus::Exhausted,
            Some(NOW + HOUR),
        ),
        (
            "usage_limit without a full window: the longest window's reset",
            &[(OutcomeClass::UsageLimit, &none_full)],
            LoginStatus::Exhausted,
            Some(NOW + 3 * DAY),
        ),
        (
            "usage_limit without data: one longest-window length",
            &[(OutcomeClass::UsageLimit, &[])],
            LoginStatus::Exhausted,
            Some(NOW + 7 * DAY),
        ),
        (
            "http_401: auth_stale",
            &[(OutcomeClass::Http401, &[])],
            LoginStatus::AuthStale,
            None,
        ),
        (
            "http_401 twice: auth_dead",
            &[(OutcomeClass::Http401, &[]), (OutcomeClass::Http401, &[])],
            LoginStatus::AuthDead,
            None,
        ),
        (
            "ok with windows clears auth_stale",
            &[(OutcomeClass::Http401, &[]), (OutcomeClass::Ok, fresh)],
            LoginStatus::Ok,
            None,
        ),
        (
            "ok without windows keeps auth_stale",
            &[(OutcomeClass::Http401, &[]), (OutcomeClass::Ok, &[])],
            LoginStatus::AuthStale,
            None,
        ),
        (
            "ok without windows keeps auth_dead",
            &[
                (OutcomeClass::Http401, &[]),
                (OutcomeClass::Http401, &[]),
                (OutcomeClass::Ok, &[]),
            ],
            LoginStatus::AuthDead,
            None,
        ),
        (
            "ok with windows clears auth_dead",
            &[
                (OutcomeClass::Http401, &[]),
                (OutcomeClass::Http401, &[]),
                (OutcomeClass::Ok, fresh),
            ],
            LoginStatus::Ok,
            None,
        ),
        (
            "http_429: rate_limited for the back-off",
            &[(OutcomeClass::Http429, &[])],
            LoginStatus::RateLimited,
            Some(NOW + 60),
        ),
        (
            "error changes nothing",
            &[(OutcomeClass::Ok, fresh), (OutcomeClass::Error, &[])],
            LoginStatus::Ok,
            None,
        ),
        (
            "model_unavailable leaves the login status alone",
            &[
                (OutcomeClass::Ok, fresh),
                (OutcomeClass::ModelUnavailable, &[]),
            ],
            LoginStatus::Ok,
            None,
        ),
    ];
    for (name, reports, expected, until) in cases {
        let mut c = two_vendors();
        let mut last = None;
        for (class, windows) in reports {
            let input = ReportInput {
                subject: on("login-1"),
                outcome: *class,
                model: Some("a".into()),
                release: false,
                windows: windows
                    .iter()
                    .map(|&(name, used, resets_at)| WindowObservation {
                        name: name.into(),
                        used,
                        resets_at,
                    })
                    .collect(),
            };
            last = Some(c.report(&input, NOW).expect("valid report"));
        }
        assert_eq!(last, Some(expected), "{name}: returned status");
        assert_eq!(status(&c, "login-1"), (expected, until), "{name}");
    }
}

#[test]
fn auth_stale_logins_stay_pickable_and_auth_dead_ones_do_not() {
    let mut c = two_vendors();
    outcome(&mut c, on("login-2"), OutcomeClass::UsageLimit, None, NOW).expect("known");
    outcome(&mut c, on("login-1"), OutcomeClass::Http401, None, NOW).expect("known");
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, "login-1");
    outcome(&mut c, on("login-1"), OutcomeClass::Http401, None, NOW).expect("known");
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, "login-3");
}

#[test]
fn a_429_back_off_ends_at_its_deadline() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "b", 1)])],
        vec![],
    )]));
    outcome(&mut c, on("login-3"), OutcomeClass::Http429, None, NOW).expect("known");
    assert_eq!(
        c.pick(&input("worker", Target::Difficulty(1), None), NOW + 59),
        Verdict::Wait {
            retry_after: NOW + 60,
            reason: Reason::AllExhausted,
            stale: true,
        }
    );
    assert_eq!(c.next_deadline(), Some(NOW + 60));
    c.tick(NOW + 60);
    assert_eq!(
        login_view(&c, "login-3", NOW + 60).status,
        LoginStatus::Unknown
    );
    let v = c.pick(&input("worker", Target::Difficulty(1), None), NOW + 60);
    assert_eq!(ran(&v).0, "login-3");
}

#[test]
fn a_dead_model_leaves_the_logins_other_models_pickable() {
    let mut c = two_vendors();
    outcome(
        &mut c,
        on("login-1"),
        OutcomeClass::ModelUnavailable,
        Some("a"),
        NOW,
    )
    .expect("known");
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)), ("login-2", "a"));
    assert_eq!(ran(&pick(&mut c, "worker", 2, None)), ("login-1", "c"));
    let pinned = c.pick(
        &input("worker", pin("vendor-a", "other", Some("login-1")), None),
        NOW,
    );
    assert_eq!(ran(&pinned), ("login-1", "other"));

    let pinned_a = |c: &mut Core, now| {
        c.pick(
            &input("worker", pin("vendor-a", "a", Some("login-1")), None),
            now,
        )
    };
    assert_eq!(
        pinned_a(&mut c, NOW + DAY - 1),
        Verdict::Dead(Reason::AllDead)
    );
    let v = pinned_a(&mut c, NOW + DAY);
    assert_eq!(ran(&v), ("login-1", "a"), "the mark lifts at its end");
}

#[test]
fn lease_reports_act_on_the_leases_login_and_model() {
    let mut c = two_vendors();
    let Verdict::Run(g, _) = pick(&mut c, "worker", 1, None) else {
        panic!("expected run")
    };
    assert_eq!((g.login.as_str(), g.model.as_str()), ("login-1", "a"));
    let status = outcome(
        &mut c,
        ReportSubject::Lease(g.lease),
        OutcomeClass::ModelUnavailable,
        Some("c"),
        NOW,
    );
    assert_eq!(status, Ok(LoginStatus::Unknown));
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)), ("login-2", "a"));
    assert_eq!(ran(&pick(&mut c, "worker", 2, None)), ("login-1", "c"));

    let status = outcome(
        &mut c,
        ReportSubject::Lease(g.lease),
        OutcomeClass::UsageLimit,
        None,
        NOW,
    );
    assert_eq!(status, Ok(LoginStatus::Exhausted));
    assert_eq!(status_of(&c, "login-1"), LoginStatus::Exhausted);
}

fn status_of(c: &Core, login: &str) -> LoginStatus {
    login_view(c, login, NOW).status
}

#[test]
fn model_reports_need_a_declared_model() {
    let mut c = two_vendors();
    let cases = [
        (None, ReportError::MissingModel),
        (Some("unknown"), ReportError::UnknownModel),
    ];
    for (model, expected) in cases {
        assert_eq!(
            outcome(
                &mut c,
                on("login-1"),
                OutcomeClass::ModelUnavailable,
                model,
                NOW
            ),
            Err(expected)
        );
    }
    let Verdict::Run(g, _) = c.pick(&input("worker", pin("vendor-a", "x", None), None), NOW) else {
        panic!("expected run")
    };
    assert_eq!(
        outcome(
            &mut c,
            ReportSubject::Lease(g.lease),
            OutcomeClass::ModelUnavailable,
            None,
            NOW
        ),
        Err(ReportError::UnknownModel),
        "a pin of an undeclared model"
    );
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).1, "a");
}
