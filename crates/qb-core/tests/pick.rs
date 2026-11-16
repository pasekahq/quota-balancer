//! Table tests of `Core::pick`: admissibility, ordering, fallback, `wait` and `dead`.

mod common;

use common::{
    DAY, HOUR, NOW, cand, core, input, observe, pick, pin, ran, reserve, role, spec, step,
};
use qb_core::{Reason, Target, Verdict};

/// One vendor-a candidate at difficulty 1 that keeps 20 % of `seven_day` free.
fn keeper() -> qb_core::Core {
    core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "m", 1)])],
        vec![reserve(1, "seven_day", 0.2)],
    )]))
}

#[test]
fn reserve_boundary_and_t_burn() {
    let t_burn = 12 * HOUR;
    let cases = [
        ("left equals the reserve", 0.8, NOW + 3 * DAY, true),
        ("left below the reserve", 0.81, NOW + 3 * DAY, false),
        (
            "reserve dropped inside T_burn",
            0.95,
            NOW + t_burn - 1,
            true,
        ),
        ("reserve kept at exactly T_burn", 0.95, NOW + t_burn, false),
        ("exhausted inside T_burn", 1.0, NOW + HOUR, false),
    ];
    for (name, used, resets_at, admissible) in cases {
        let mut c = keeper();
        observe(
            &mut c,
            "login-1",
            &[("seven_day", used, Some(resets_at))],
            NOW,
        );
        observe(
            &mut c,
            "login-2",
            &[("seven_day", 1.0, Some(NOW + DAY))],
            NOW,
        );
        let v = pick(&mut c, "worker", 1, None);
        if admissible {
            assert_eq!(ran(&v).0, "login-1", "{name}");
        } else {
            assert!(matches!(v, Verdict::Wait { .. }), "{name}: {v:?}");
        }
    }
}

#[test]
fn reserve_constrains_only_windows_the_vendor_declares() {
    for (window, admissible) in [("seven_day", true), ("five_hour", false)] {
        let mut c = core(spec(vec![role(
            "worker",
            vec![step(1, vec![cand("vendor-b", "m", 1)])],
            vec![reserve(1, window, 0.5)],
        )]));
        observe(
            &mut c,
            "login-3",
            &[("five_hour", 0.9, Some(NOW + 4 * HOUR))],
            NOW,
        );
        let v = pick(&mut c, "worker", 1, None);
        assert_eq!(matches!(v, Verdict::Run(..)), admissible, "{window}: {v:?}");
    }
}

#[test]
fn urgency_orders_logins_of_equal_tier() {
    type Obs = (f64, u64);
    let cases: [(&str, Obs, Obs, &str); 4] = [
        (
            "more left, same reset",
            (0.5, 2 * DAY),
            (0.2, 2 * DAY),
            "login-2",
        ),
        (
            "sooner reset, same left",
            (0.5, 3 * DAY),
            (0.5, DAY),
            "login-2",
        ),
        ("horizon floored at 1 h", (0.4, 600), (0.3, 3000), "login-2"),
        (
            "equal urgency, login order",
            (0.5, DAY),
            (0.5, DAY),
            "login-1",
        ),
    ];
    for (name, (used1, in1), (used2, in2), expected) in cases {
        let mut c = core(spec(vec![role(
            "worker",
            vec![step(1, vec![cand("vendor-a", "m", 1)])],
            vec![],
        )]));
        observe(
            &mut c,
            "login-1",
            &[("seven_day", used1, Some(NOW + in1))],
            NOW,
        );
        observe(
            &mut c,
            "login-2",
            &[("seven_day", used2, Some(NOW + in2))],
            NOW,
        );
        assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, expected, "{name}");
    }
}

#[test]
fn thirty_percent_left_resetting_in_six_hours_is_spent_first() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "m", 1)])],
        vec![],
    )]));
    observe(
        &mut c,
        "login-1",
        &[("seven_day", 0.1, Some(NOW + 6 * DAY))],
        NOW,
    );
    observe(
        &mut c,
        "login-2",
        &[("seven_day", 0.7, Some(NOW + 6 * HOUR))],
        NOW,
    );
    let v = pick(&mut c, "worker", 1, None);
    assert_eq!(ran(&v).0, "login-2");
    assert!(matches!(v, Verdict::Run(_, Reason::SpendBeforeReset)));
}

#[test]
fn tier_wins_over_urgency_and_candidate_order_breaks_ties() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(
            1,
            vec![
                cand("vendor-b", "urgent", 2),
                cand("vendor-a", "first", 1),
                cand("vendor-a", "second", 1),
            ],
        )],
        vec![],
    )]));
    observe(
        &mut c,
        "login-3",
        &[("five_hour", 0.0, Some(NOW + HOUR))],
        NOW,
    );
    observe(
        &mut c,
        "login-1",
        &[("seven_day", 0.9, Some(NOW + 6 * DAY))],
        NOW,
    );
    observe(
        &mut c,
        "login-2",
        &[("seven_day", 0.9, Some(NOW + 6 * DAY))],
        NOW,
    );
    let v = pick(&mut c, "worker", 1, None);
    assert_eq!(ran(&v), ("login-1", "first"));
    let Verdict::Run(g, _) = v else {
        unreachable!()
    };
    assert_eq!((g.vendor.as_str(), g.tier), ("vendor-a", Some(1)));
}

#[test]
fn avoid_vendor_drops_its_candidates() {
    let mut c = core(spec(vec![
        role(
            "worker",
            vec![step(
                1,
                vec![cand("vendor-a", "a", 1), cand("vendor-b", "b", 2)],
            )],
            vec![],
        ),
        role(
            "solo",
            vec![step(1, vec![cand("vendor-a", "a", 1)])],
            vec![],
        ),
    ]));
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).1, "a");
    assert_eq!(
        ran(&pick(&mut c, "worker", 1, Some("vendor-a"))),
        ("login-3", "b")
    );
    assert_eq!(
        pick(&mut c, "solo", 1, Some("vendor-a")),
        Verdict::Dead(Reason::NoCandidates)
    );
}

#[test]
fn nothing_on_the_step_falls_back_to_the_lower_then_the_higher_neighbour() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![
            step(1, vec![cand("vendor-b", "small", 1)]),
            step(2, vec![cand("vendor-a", "medium", 1)]),
            step(3, vec![cand("vendor-a", "large", 1)]),
            step(4, vec![cand("vendor-b", "huge", 1)]),
        ],
        vec![reserve(3, "seven_day", 0.5)],
    )]));
    let exhausted = Some(NOW + 2 * HOUR);
    observe(&mut c, "login-1", &[("five_hour", 1.0, exhausted)], NOW);
    observe(
        &mut c,
        "login-2",
        &[("seven_day", 0.6, Some(NOW + 3 * DAY))],
        NOW,
    );
    // login-2 passes step 2 (no reserve) but not step 3 (50 % reserve).
    let v = pick(&mut c, "worker", 3, None);
    assert_eq!(ran(&v), ("login-2", "medium"));
    assert!(matches!(v, Verdict::Run(_, Reason::NeighbourStep)));

    observe(&mut c, "login-2", &[("five_hour", 1.0, exhausted)], NOW);
    let v = pick(&mut c, "worker", 3, None);
    assert_eq!(ran(&v), ("login-3", "huge"), "higher neighbour after lower");

    let v = pick(&mut c, "worker", 2, None);
    assert_eq!(ran(&v), ("login-3", "small"), "lower neighbour first");

    observe(&mut c, "login-3", &[("five_hour", 1.0, exhausted)], NOW);
    let v = pick(&mut c, "worker", 2, None);
    assert!(matches!(v, Verdict::Wait { .. }), "{v:?}");
}

#[test]
fn neighbours_are_only_the_nearest_steps() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![
            step(1, vec![cand("vendor-b", "small", 1)]),
            step(2, vec![cand("vendor-a", "medium", 1)]),
            step(3, vec![cand("vendor-a", "large", 1)]),
        ],
        vec![],
    )]));
    let exhausted = Some(NOW + 2 * HOUR);
    observe(&mut c, "login-1", &[("five_hour", 1.0, exhausted)], NOW);
    observe(&mut c, "login-2", &[("five_hour", 1.0, exhausted)], NOW);
    let v = pick(&mut c, "worker", 3, None);
    assert!(
        matches!(v, Verdict::Wait { retry_after, reason: Reason::AllExhausted, .. }
            if retry_after == NOW + 2 * HOUR),
        "step 1 is not a neighbour of step 3: {v:?}"
    );
}

#[test]
fn wait_returns_the_earliest_reset_that_unblocks_a_candidate() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "m", 1)])],
        vec![],
    )]));
    // login-1 needs both of its windows back; login-2 only its short one.
    observe(
        &mut c,
        "login-1",
        &[
            ("five_hour", 1.0, Some(NOW + HOUR)),
            ("seven_day", 1.0, Some(NOW + 3 * DAY)),
        ],
        NOW,
    );
    observe(
        &mut c,
        "login-2",
        &[("five_hour", 1.0, Some(NOW + 4 * HOUR))],
        NOW,
    );
    match pick(&mut c, "worker", 1, None) {
        Verdict::Wait {
            retry_after,
            reason,
            ..
        } => {
            assert_eq!(retry_after, NOW + 4 * HOUR);
            assert_eq!(reason, Reason::AllExhausted);
        }
        other => panic!("expected wait, got {other:?}"),
    }
}

#[test]
fn dead_without_candidates_or_without_a_known_reset() {
    let mut c = core(spec(vec![
        role(
            "worker",
            vec![step(1, vec![cand("vendor-a", "m", 1)])],
            vec![],
        ),
        role("idle", vec![], vec![]),
    ]));
    let cases = [
        ("unknown role", "nobody", 1),
        ("empty ladder", "idle", 1),
        ("unmatched difficulty", "worker", 7),
    ];
    for (name, role, difficulty) in cases {
        assert_eq!(
            pick(&mut c, role, difficulty, None),
            Verdict::Dead(Reason::NoCandidates),
            "{name}"
        );
    }
    let mut lonely = spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-a", "m", 1)])],
        vec![],
    )]);
    lonely.logins.retain(|l| l.vendor != "vendor-a");
    assert_eq!(
        pick(&mut core(lonely), "worker", 1, None),
        Verdict::Dead(Reason::NoCandidates),
        "vendor without logins"
    );

    observe(&mut c, "login-1", &[("seven_day", 1.0, None)], NOW);
    observe(&mut c, "login-2", &[("seven_day", 1.0, None)], NOW);
    assert_eq!(
        pick(&mut c, "worker", 1, None),
        Verdict::Dead(Reason::NoResetKnown)
    );
}

#[test]
fn pins_choose_among_the_vendor_logins_without_role_reserves() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "m", 1)])],
        vec![reserve(1, "seven_day", 0.5)],
    )]));
    observe(
        &mut c,
        "login-1",
        &[("seven_day", 0.9, Some(NOW + 2 * DAY))],
        NOW,
    );
    observe(
        &mut c,
        "login-2",
        &[("seven_day", 0.2, Some(NOW + 2 * DAY))],
        NOW,
    );
    let mut go = |target: Target, avoid: Option<&str>| c.pick(&input("worker", target, avoid), NOW);

    let v = go(pin("vendor-a", "model-x", None), None);
    let Verdict::Run(g, reason) = &v else {
        panic!("expected run, got {v:?}")
    };
    assert_eq!(reason, &Reason::Pinned);
    assert_eq!(
        (
            g.login.as_str(),
            g.model.as_str(),
            g.effort.as_deref(),
            g.tier
        ),
        ("login-2", "model-x", Some("high"), None)
    );
    assert_eq!(
        ran(&go(pin("vendor-a", "model-x", Some("login-1")), None)).0,
        "login-1"
    );
    assert_eq!(
        go(pin("vendor-a", "model-x", Some("login-3")), None),
        Verdict::Dead(Reason::NoCandidates)
    );
    assert_eq!(
        go(pin("vendor-z", "model-x", None), None),
        Verdict::Dead(Reason::NoCandidates)
    );
    assert_eq!(
        go(pin("vendor-a", "model-x", None), Some("vendor-a")),
        Verdict::Dead(Reason::NoCandidates)
    );
    assert_eq!(
        c.pick(
            &input("nobody", pin("vendor-a", "model-x", None), None),
            NOW
        ),
        Verdict::Dead(Reason::NoCandidates)
    );

    observe(
        &mut c,
        "login-1",
        &[("five_hour", 1.0, Some(NOW + HOUR))],
        NOW,
    );
    assert!(matches!(
        c.pick(&input("worker", pin("vendor-a", "m", Some("login-1")), None), NOW),
        Verdict::Wait { retry_after, .. } if retry_after == NOW + HOUR
    ));
}

#[test]
fn run_and_wait_say_when_their_data_is_stale() {
    let mut c = core(spec(vec![role(
        "worker",
        vec![step(1, vec![cand("vendor-b", "m", 1)])],
        vec![],
    )]));
    let v = pick(&mut c, "worker", 1, None);
    let Verdict::Run(g, _) = v else {
        panic!("a never observed login is usable: {v:?}")
    };
    assert!(g.stale);
    assert_eq!(g.snapshot_at, None);

    observe(
        &mut c,
        "login-3",
        &[("five_hour", 0.5, Some(NOW + HOUR))],
        NOW - 100,
    );
    let Verdict::Run(g, _) = pick(&mut c, "worker", 1, None) else {
        panic!("expected run")
    };
    assert!(!g.stale);
    assert_eq!(g.snapshot_at, Some(NOW - 100));

    observe(
        &mut c,
        "login-3",
        &[("five_hour", 1.0, Some(NOW + HOUR))],
        NOW - 301,
    );
    assert!(matches!(
        pick(&mut c, "worker", 1, None),
        Verdict::Wait { stale: true, .. }
    ));
}

#[test]
fn empty_core_has_no_candidates() {
    let mut c = core(qb_core::Spec::default());
    for target in [Target::Difficulty(0), pin("v", "m", None)] {
        assert_eq!(
            c.pick(&input("worker", target, None), NOW),
            Verdict::Dead(Reason::NoCandidates)
        );
    }
}

#[test]
fn reason_names_are_stable() {
    assert_eq!(Reason::NoCandidates.as_str(), "no_candidates");
}
