//! Spec builders and pick helpers shared by the policy tests.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use qb_core::{
    CandidateSpec, Core, LoginSpec, LoginStatus, LoginView, OutcomeClass, PickInput, ReportError,
    ReportInput, ReportSubject, ReserveSpec, RoleSpec, Spec, StepSpec, Target, VendorSpec, Verdict,
    WindowObservation, WindowSpec,
};

pub const NOW: u64 = 1_800_000_000;
pub const HOUR: u64 = 3600;
pub const DAY: u64 = 86_400;

pub fn window(name: &str, length_s: u64, t_burn_s: u64) -> WindowSpec {
    WindowSpec {
        name: name.into(),
        length_s,
        t_burn_s,
    }
}

/// `five_hour` (`T_burn` 30 min) and `seven_day` (`T_burn` 12 h).
pub fn two_windows() -> Vec<WindowSpec> {
    vec![
        window("five_hour", 5 * HOUR, 1800),
        window("seven_day", 7 * DAY, 12 * HOUR),
    ]
}

pub fn vendor(name: &str, windows: Vec<WindowSpec>) -> VendorSpec {
    VendorSpec {
        name: name.into(),
        windows,
    }
}

pub fn login(name: &str, vendor: &str) -> LoginSpec {
    LoginSpec {
        name: name.into(),
        vendor: vendor.into(),
    }
}

pub fn cand(vendor: &str, model: &str, tier: u8) -> CandidateSpec {
    CandidateSpec {
        vendor: vendor.into(),
        model: model.into(),
        effort: None,
        tier,
        cost_per_minute: None,
    }
}

pub fn step(difficulty: u8, candidates: Vec<CandidateSpec>) -> StepSpec {
    StepSpec {
        difficulty,
        candidates,
    }
}

pub fn reserve(difficulty: u8, window: &str, fraction: f64) -> ReserveSpec {
    ReserveSpec {
        difficulty,
        window: window.into(),
        fraction,
    }
}

pub fn role(name: &str, ladder: Vec<StepSpec>, reserves: Vec<ReserveSpec>) -> RoleSpec {
    RoleSpec {
        name: name.into(),
        ladder,
        reserves,
    }
}

/// `vendor-a` with two windows and logins `login-1`, `login-2`; `vendor-b` with `five_hour`
/// only and `login-3`; the given roles; snapshot TTL 300 s, lease TTL 1 h, cost rate 0.01 per
/// minute, 429 back-off 60 s, model-dead mark 1 day, probes off.
pub fn spec(roles: Vec<RoleSpec>) -> Spec {
    Spec {
        vendors: vec![
            vendor("vendor-a", two_windows()),
            vendor("vendor-b", vec![window("five_hour", 5 * HOUR, 1800)]),
        ],
        logins: vec![
            login("login-1", "vendor-a"),
            login("login-2", "vendor-a"),
            login("login-3", "vendor-b"),
        ],
        roles,
        snapshot_ttl_s: 300,
        lease_ttl_s: HOUR,
        cost_per_minute: 0.01,
        rate_limit_backoff_s: 60,
        model_unavailable_s: DAY,
        probe: None,
    }
}

pub fn core(spec: Spec) -> Core {
    Core::new(spec).expect("valid spec")
}

/// Reports `(window, used, resets_at)` triples for `login` at `at`.
pub fn observe(core: &mut Core, login: &str, windows: &[(&str, f64, Option<u64>)], at: u64) {
    let input = ReportInput {
        subject: ReportSubject::Login(login.into()),
        outcome: OutcomeClass::Ok,
        model: None,
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
    core.report(&input, at).expect("known login");
}

pub fn input(role: &str, target: Target, avoid_vendor: Option<&str>) -> PickInput {
    PickInput {
        role: role.into(),
        target,
        resume_of: None,
        avoid_vendor: avoid_vendor.map(Into::into),
        client: "test".into(),
        expected_minutes: None,
        run_id: None,
    }
}

pub fn pick(core: &mut Core, role: &str, difficulty: u8, avoid_vendor: Option<&str>) -> Verdict {
    core.pick(
        &input(role, Target::Difficulty(difficulty), avoid_vendor),
        NOW,
    )
}

pub fn pin(vendor: &str, model: &str, login: Option<&str>) -> Target {
    Target::Pin {
        vendor: vendor.into(),
        model: model.into(),
        effort: Some("high".into()),
        login: login.map(Into::into),
    }
}

/// `(login, model)` of a run verdict; panics on anything else.
pub fn ran(v: &Verdict) -> (&str, &str) {
    match v {
        Verdict::Run(g, _) => (g.login.as_str(), g.model.as_str()),
        other => panic!("expected run, got {other:?}"),
    }
}

/// Reports `outcome` on `subject` with no windows at `at`.
pub fn outcome(
    core: &mut Core,
    subject: ReportSubject,
    outcome: OutcomeClass,
    model: Option<&str>,
    at: u64,
) -> Result<LoginStatus, ReportError> {
    let input = ReportInput {
        subject,
        outcome,
        model: model.map(Into::into),
        release: false,
        windows: Vec::new(),
    };
    core.report(&input, at)
}

/// Releases lease `id` with an `ok` report at `at`.
pub fn release(core: &mut Core, id: u64, at: u64) {
    let input = ReportInput {
        subject: ReportSubject::Lease(id),
        outcome: OutcomeClass::Ok,
        model: None,
        release: true,
        windows: Vec::new(),
    };
    core.report(&input, at).expect("live lease");
}

/// A login subject.
pub fn on(login: &str) -> ReportSubject {
    ReportSubject::Login(login.into())
}

/// A ladder pick at `now` for a task of `minutes`.
pub fn pick_for(core: &mut Core, role: &str, difficulty: u8, minutes: u32, now: u64) -> Verdict {
    let mut i = input(role, Target::Difficulty(difficulty), None);
    i.expected_minutes = Some(minutes);
    core.pick(&i, now)
}

/// The login's view in a snapshot at `now`.
pub fn login_view(core: &Core, login: &str, now: u64) -> LoginView {
    core.snapshot(now)
        .logins
        .into_iter()
        .find(|l| l.name == login)
        .expect("configured login")
}
