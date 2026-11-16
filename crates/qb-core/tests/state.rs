//! Window snapshots through `Core::report` and `Core::snapshot`, and spec validation.

mod common;

use common::{HOUR, NOW, cand, core, login, observe, role, spec, step, vendor, window};
use qb_core::{
    Core, LoginStatus, OutcomeClass, ReportError, ReportInput, ReportSubject, Snapshot, Source,
    Spec, SpecError, WindowObservation, WindowView,
};

fn view(core: &Core, login: &str, now: u64) -> Vec<WindowView> {
    core.snapshot(now)
        .logins
        .into_iter()
        .find(|l| l.name == login)
        .expect("configured login")
        .windows
}

fn report(core: &mut Core, subject: ReportSubject, used: f64) -> Result<LoginStatus, ReportError> {
    let input = ReportInput {
        subject,
        outcome: OutcomeClass::Ok,
        model: None,
        release: false,
        windows: vec![WindowObservation {
            name: "five_hour".into(),
            used,
            resets_at: Some(NOW + HOUR),
        }],
    };
    core.report(&input, NOW)
}

#[test]
fn unobserved_windows_are_assumed_empty_and_stale() {
    let c = core(spec(vec![]));
    let windows = view(&c, "login-1", NOW);
    let names: Vec<&str> = windows.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, ["five_hour", "seven_day"]);
    for w in windows {
        assert_eq!(
            (w.used, w.resets_at, w.observed_at, w.source, w.stale),
            (0.0, None, 0, Source::Assumed, true)
        );
    }
}

#[test]
fn a_report_overwrites_the_named_windows() {
    let mut c = core(spec(vec![]));
    observe(
        &mut c,
        "login-1",
        &[("seven_day", 0.3, Some(NOW + 9 * HOUR))],
        NOW - 10,
    );
    observe(
        &mut c,
        "login-1",
        &[
            ("five_hour", 0.4, Some(NOW + HOUR)),
            ("unknown_window", 0.9, None),
        ],
        NOW,
    );
    let w = view(&c, "login-1", NOW);
    assert_eq!(w.len(), 2, "undeclared window names are ignored");
    assert_eq!(
        w[0],
        WindowView {
            name: "five_hour".into(),
            used: 0.4,
            reserved: 0.0,
            resets_at: Some(NOW + HOUR),
            observed_at: NOW,
            source: Source::Stream,
            stale: false,
        }
    );
    assert_eq!(
        (w[1].used, w[1].observed_at, w[1].source),
        (0.3, NOW - 10, Source::Stream)
    );
}

#[test]
fn a_passed_reset_empties_the_window_and_age_makes_it_stale() {
    let mut c = core(spec(vec![]));
    observe(
        &mut c,
        "login-3",
        &[("five_hour", 0.8, Some(NOW + HOUR))],
        NOW,
    );
    let at = |c: &Core, now| view(c, "login-3", now).remove(0);

    let w = at(&c, NOW + 300);
    assert_eq!((w.used, w.source, w.stale), (0.8, Source::Stream, false));
    let w = at(&c, NOW + 301);
    assert_eq!((w.used, w.source, w.stale), (0.8, Source::Stream, true));
    let w = at(&c, NOW + HOUR);
    assert_eq!(
        (w.used, w.resets_at, w.observed_at, w.source),
        (0.0, None, NOW, Source::Assumed)
    );
}

#[test]
fn reports_are_checked_before_they_apply() {
    let mut c = core(spec(vec![]));
    assert_eq!(
        report(&mut c, ReportSubject::Lease(1), 0.5),
        Err(ReportError::UnknownLease)
    );
    assert_eq!(
        report(&mut c, ReportSubject::Login("nope".into()), 0.5),
        Err(ReportError::UnknownLogin)
    );
    for used in [-0.1, 1.5, f64::NAN] {
        assert_eq!(
            report(&mut c, ReportSubject::Login("login-3".into()), used),
            Err(ReportError::InvalidUtilization)
        );
    }
    assert_eq!(view(&c, "login-3", NOW)[0].source, Source::Assumed);
    assert_eq!(
        report(&mut c, ReportSubject::Login("login-3".into()), 1.0),
        Ok(LoginStatus::Ok),
        "a login with data is no longer unknown"
    );
}

#[test]
fn configured_logins_start_unknown() {
    let c = core(spec(vec![]));
    let snap = c.snapshot(NOW);
    let logins: Vec<(&str, &str, LoginStatus)> = snap
        .logins
        .iter()
        .map(|l| (l.name.as_str(), l.vendor.as_str(), l.status))
        .collect();
    assert_eq!(
        logins,
        [
            ("login-1", "vendor-a", LoginStatus::Unknown),
            ("login-2", "vendor-a", LoginStatus::Unknown),
            ("login-3", "vendor-b", LoginStatus::Unknown),
        ]
    );
}

#[test]
fn empty_snapshot() {
    let c = core(Spec::default());
    assert_eq!(c.snapshot(0), Snapshot::default());
}

#[test]
fn specs_beyond_the_tables_or_with_undeclared_vendors_are_refused() {
    let ladder = |vendor: &str, n: usize| {
        vec![role(
            "worker",
            vec![step(1, (0..n).map(|_| cand(vendor, "m", 1)).collect())],
            vec![],
        )]
    };
    let mut many_logins = spec(vec![]);
    many_logins.logins = (0..33)
        .map(|i| login(&format!("l-{i}"), "vendor-a"))
        .collect();
    let mut many_windows = spec(vec![]);
    many_windows.vendors.push(vendor(
        "vendor-c",
        (0..5).map(|i| window(&format!("w{i}"), HOUR, 0)).collect(),
    ));
    let mut empty_window = spec(vec![]);
    empty_window
        .vendors
        .push(vendor("vendor-c", vec![window("w", 0, 0)]));
    let mut stray_login = spec(vec![]);
    stray_login.logins.push(login("login-9", "vendor-z"));
    let cases = [
        (many_logins, SpecError::TooManyLogins),
        (many_windows, SpecError::TooManyWindows("vendor-c".into())),
        (empty_window, SpecError::EmptyWindow("vendor-c".into())),
        (
            spec(ladder("vendor-a", 9)),
            SpecError::TooManyCandidates("worker".into(), 1),
        ),
        (stray_login, SpecError::UnknownVendor("vendor-z".into())),
        (
            spec(ladder("vendor-z", 1)),
            SpecError::UnknownVendor("vendor-z".into()),
        ),
    ];
    for (spec, expected) in cases {
        assert_eq!(Core::new(spec).map(|_| ()), Err(expected));
    }
}
