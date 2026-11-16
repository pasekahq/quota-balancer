//! Spec builders and pick helpers shared by the policy tests.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use qb_core::{
    CandidateSpec, Core, LoginSpec, OutcomeClass, PickInput, ReportInput, ReportSubject,
    ReserveSpec, RoleSpec, Spec, StepSpec, Target, VendorSpec, Verdict, WindowObservation,
    WindowSpec,
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
/// only and `login-3`; the given roles; TTL 300 s.
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
