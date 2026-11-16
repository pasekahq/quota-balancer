//! Properties: for random specs, snapshots and `now`, every `run` is admissible under the reserve
//! rule, and `wait`/`dead` happen only when no tried (candidate, login) pair is admissible; over
//! random sequences of pick, report, release and time steps the reserved sums match the live
//! leases, the lease table stays bounded and every `run` is admissible with `reserved` counted.

mod common;

use common::{DAY, HOUR, cand, core, input, login, observe, reserve, role, step, vendor, window};
use qb_core::{
    LoginStatus, LoginView, MAX_LEASES, OutcomeClass, Reason, ReportInput, ReportSubject, RoleSpec,
    Spec, Target, VendorSpec, Verdict, WindowObservation,
};

/// xorshift64*: deterministic, so a failing case reproduces from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(n as u64)).expect("small")
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// A fraction that often lands on 0, 1 or a typical reserve boundary.
    fn fraction(&mut self) -> f64 {
        const EDGES: [f64; 7] = [0.0, 0.2, 0.5, 0.8, 0.95, 1.0, 1.0];
        if self.chance(50) {
            EDGES[self.index(EDGES.len())]
        } else {
            f64::from(u32::try_from(self.below(1001)).expect("small")) / 1000.0
        }
    }
}

const WINDOW_NAMES: [&str; 5] = ["w0", "w1", "w2", "w3", "w4"];

fn random_spec(rng: &mut Rng) -> Spec {
    let vendors: Vec<VendorSpec> = (0..=rng.index(3))
        .map(|v| {
            let mut windows = Vec::new();
            for name in &WINDOW_NAMES[..4] {
                if rng.chance(60) {
                    let length = HOUR + rng.below(30 * DAY);
                    windows.push(window(name, length, rng.below(length + 1)));
                }
            }
            vendor(&format!("v{v}"), windows)
        })
        .collect();
    let logins = (0..=rng.index(6))
        .map(|i| login(&format!("l{i}"), &vendors[rng.index(vendors.len())].name))
        .collect();
    let mut difficulties: Vec<u8> = (0..6).filter(|_| rng.chance(50)).collect();
    difficulties.sort_unstable();
    let ladder = difficulties
        .iter()
        .map(|&d| {
            let cands = (0..=rng.index(4))
                .map(|k| {
                    let v = &vendors[rng.index(vendors.len())].name;
                    let tier = u8::try_from(rng.below(3)).expect("small");
                    cand(v, &format!("m{k}"), tier)
                })
                .collect();
            step(d, cands)
        })
        .collect();
    let mut reserves = Vec::new();
    for &d in &difficulties {
        for name in WINDOW_NAMES {
            if rng.chance(30) {
                reserves.push(reserve(d, name, rng.fraction()));
            }
        }
    }
    Spec {
        vendors,
        logins,
        roles: vec![role("r", ladder, reserves)],
        snapshot_ttl_s: 1 + rng.below(2 * HOUR),
        lease_ttl_s: HOUR,
        cost_per_minute: 0.01,
        rate_limit_backoff_s: 60,
        model_unavailable_s: DAY,
        probe: None,
    }
}

/// The admissibility rule restated over the public view of a login.
fn admissible(spec: &Spec, login: &LoginView, reserve_of: &dyn Fn(&str) -> f64, now: u64) -> bool {
    let vendor = spec
        .vendors
        .iter()
        .find(|v| v.name == login.vendor)
        .expect("declared vendor");
    login.windows.iter().all(|w| {
        let def = vendor
            .windows
            .iter()
            .find(|d| d.name == w.name)
            .expect("declared window");
        let in_burn = w.resets_at.is_some_and(|r| {
            assert!(r > now, "a passed reset is shown as reset");
            r - now < def.t_burn_s
        });
        let reserve = if in_burn { 0.0 } else { reserve_of(&w.name) };
        let left = 1.0 - w.used;
        left > 0.0 && left + 1e-9 >= reserve
    })
}

/// Difficulties `pick` tries for `d`: the step, its nearest lower and nearest higher step.
fn tried_steps(role: &RoleSpec, d: u8) -> Vec<u8> {
    let mut ds: Vec<u8> = role.ladder.iter().map(|s| s.difficulty).collect();
    ds.sort_unstable();
    let Some(at) = ds.iter().position(|&x| x == d) else {
        return Vec::new();
    };
    let mut out = vec![d];
    if at > 0 {
        out.push(ds[at - 1]);
    }
    if let Some(&up) = ds.get(at + 1) {
        out.push(up);
    }
    out
}

/// `(difficulty, vendor, model, tier, login)` of every admissible pair on the tried steps.
fn admissible_pairs(
    spec: &Spec,
    logins: &[LoginView],
    d: u8,
    avoid: Option<&str>,
    now: u64,
) -> Vec<(u8, String, String, u8, String)> {
    let role = &spec.roles[0];
    let mut out = Vec::new();
    for sd in tried_steps(role, d) {
        let step = role
            .ladder
            .iter()
            .find(|s| s.difficulty == sd)
            .expect("step");
        let reserve_of = |w: &str| {
            role.reserves
                .iter()
                .find(|r| r.difficulty == sd && r.window == w)
                .map_or(0.0, |r| r.fraction)
        };
        for c in &step.candidates {
            if avoid == Some(c.vendor.as_str()) {
                continue;
            }
            for l in logins.iter().filter(|l| l.vendor == c.vendor) {
                if admissible(spec, l, &reserve_of, now) {
                    out.push((
                        sd,
                        c.vendor.clone(),
                        c.model.clone(),
                        c.tier,
                        l.name.clone(),
                    ));
                }
            }
        }
    }
    out
}

#[test]
fn run_verdicts_are_admissible_and_refusals_are_justified() {
    const NOW: u64 = 1_800_000_000;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut runs, mut waits, mut deads) = (0, 0, 0);
    for case in 0..3000 {
        let spec = random_spec(&mut rng);
        let mut c = core(spec.clone());
        let now = NOW + rng.below(DAY);
        for l in &spec.logins {
            let at = now - rng.below(3 * HOUR);
            let mut obs = Vec::new();
            for name in WINDOW_NAMES {
                if rng.chance(60) {
                    let resets_at = match rng.below(4) {
                        0 => None,
                        1 => Some(at + rng.below(3 * HOUR)),
                        _ => Some(at + rng.below(8 * DAY)),
                    };
                    obs.push((name, rng.fraction(), resets_at));
                }
            }
            observe(&mut c, &l.name, &obs, at);
        }
        let logins = c.snapshot(now).logins;
        let avoid = rng
            .chance(25)
            .then(|| spec.vendors[rng.index(spec.vendors.len())].name.clone());

        if rng.chance(20) {
            let v = &spec.vendors[rng.index(spec.vendors.len())].name;
            let target = Target::Pin {
                vendor: v.clone(),
                model: "pinned".into(),
                effort: None,
                login: None,
            };
            let verdict = c.pick(&input("r", target, avoid.as_deref()), now);
            let usable: Vec<&LoginView> = logins
                .iter()
                .filter(|l| &l.vendor == v && avoid.as_ref() != Some(v))
                .filter(|l| admissible(&spec, l, &|_| 0.0, now))
                .collect();
            match &verdict {
                Verdict::Run(g, Reason::Pinned) => {
                    assert!(
                        usable.iter().any(|l| l.name == g.login),
                        "case {case}: {g:?}"
                    );
                }
                _ => assert!(
                    usable.is_empty(),
                    "case {case}: {verdict:?} with {usable:?}"
                ),
            }
            continue;
        }

        let ladder = &spec.roles[0].ladder;
        let d = if ladder.is_empty() || rng.chance(10) {
            u8::try_from(rng.below(7)).expect("small")
        } else {
            ladder[rng.index(ladder.len())].difficulty
        };
        let verdict = c.pick(&input("r", Target::Difficulty(d), avoid.as_deref()), now);
        let pairs = admissible_pairs(&spec, &logins, d, avoid.as_deref(), now);
        match &verdict {
            Verdict::Run(g, reason) => {
                runs += 1;
                let matching = pairs.iter().any(|(sd, v, m, t, l)| {
                    (*reason == Reason::SpendBeforeReset) == (*sd == d)
                        && *v == g.vendor
                        && *m == g.model
                        && Some(*t) == g.tier
                        && *l == g.login
                });
                assert!(matching, "case {case}: {g:?} {reason:?} not in {pairs:?}");
            }
            Verdict::Wait { retry_after, .. } => {
                waits += 1;
                assert!(*retry_after > now, "case {case}");
                assert!(pairs.is_empty(), "case {case}: wait with {pairs:?}");
            }
            Verdict::Dead(_) => {
                deads += 1;
                assert!(pairs.is_empty(), "case {case}: dead with {pairs:?}");
            }
        }
    }
    assert!(
        runs > 300 && waits > 50 && deads > 50,
        "generator covers every verdict: {runs} runs, {waits} waits, {deads} deads"
    );
}

/// A lease as the test expects it: login, cost per window name, expiry.
struct Expected {
    login: String,
    cost: Vec<(String, f64)>,
    expires_at: u64,
}

/// Cost per window of `minutes` at 0.01 of the vendor's shortest window per minute.
fn expected_cost(spec: &Spec, vendor: &str, minutes: Option<u32>) -> Vec<(String, f64)> {
    let v = spec
        .vendors
        .iter()
        .find(|v| v.name == vendor)
        .expect("vendor");
    let shortest = v.windows.iter().map(|w| w.length_s).min().unwrap_or(1);
    v.windows
        .iter()
        .map(|w| {
            let m = f64::from(minutes.unwrap_or(0));
            #[allow(clippy::cast_precision_loss)]
            let c = m * 0.01 * shortest as f64 / w.length_s as f64;
            (w.name.clone(), c)
        })
        .collect()
}

/// Every window keeps `1 - used - reserved - cost` above 0 and at least its reserve.
fn admissible_with_cost(
    spec: &Spec,
    login: &LoginView,
    cost: &[(String, f64)],
    reserve_of: &dyn Fn(&str) -> f64,
    now: u64,
) -> bool {
    let vendor = spec
        .vendors
        .iter()
        .find(|v| v.name == login.vendor)
        .expect("vendor");
    let usable = !matches!(
        login.status,
        LoginStatus::AuthDead | LoginStatus::Exhausted | LoginStatus::RateLimited
    );
    usable
        && login.windows.iter().zip(&vendor.windows).all(|(w, def)| {
            let in_burn = w.resets_at.is_some_and(|r| r - now < def.t_burn_s);
            let reserve = if in_burn { 0.0 } else { reserve_of(&w.name) };
            let c = cost.iter().find(|(n, _)| *n == w.name).map_or(0.0, |x| x.1);
            let left = 1.0 - w.used - w.reserved - c;
            left > 0.0 && left + 1e-9 >= reserve
        })
}

/// Step 1 or 2 of the role, or a pin of `vendor-a` with a declared or undeclared model.
fn random_target(rng: &mut Rng) -> Target {
    if rng.chance(15) {
        Target::Pin {
            vendor: "vendor-a".into(),
            model: if rng.chance(50) { "a" } else { "z" }.into(),
            effort: None,
            login: None,
        }
    } else {
        Target::Difficulty(1 + u8::try_from(rng.below(2)).expect("small"))
    }
}

/// Reserve of the only role at difficulty `d` for window `w`.
fn reserve_at(spec: &Spec, d: u8, w: &str) -> f64 {
    spec.roles[0]
        .reserves
        .iter()
        .find(|r| r.difficulty == d && r.window == w)
        .map_or(0.0, |r| r.fraction)
}

/// A report on a random live lease (`Some` index into `live`) or login.
fn random_report(
    rng: &mut Rng,
    names: &[String],
    live: &[(u64, Expected)],
    now: u64,
) -> (ReportInput, Option<usize>) {
    let lease = (!live.is_empty() && rng.chance(70)).then(|| rng.index(live.len()));
    let subject = match lease {
        Some(k) => ReportSubject::Lease(live[k].0),
        None => ReportSubject::Login(names[rng.index(names.len())].clone()),
    };
    let outcome = match rng.below(100) {
        0..=74 => OutcomeClass::Ok,
        75..=79 => OutcomeClass::UsageLimit,
        80..=87 => OutcomeClass::Http429,
        88..=97 => OutcomeClass::Error,
        _ => OutcomeClass::Http401,
    };
    let windows = if rng.chance(50) {
        let name = if rng.chance(50) {
            "five_hour"
        } else {
            "seven_day"
        };
        vec![WindowObservation {
            name: name.into(),
            used: rng.fraction(),
            resets_at: Some(now + 1 + rng.below(3 * DAY)),
        }]
    } else {
        Vec::new()
    };
    let report = ReportInput {
        subject,
        outcome,
        model: None,
        release: lease.is_some() && rng.chance(40),
        windows,
    };
    (report, lease)
}

/// The snapshot's leases are `live` and each (login, window) `reserved` is their cost sum.
fn check_reserved(c: &qb_core::Core, live: &[(u64, Expected)], now: u64, case: &str) {
    let snap = c.snapshot(now);
    assert!(snap.leases.len() <= MAX_LEASES, "{case}");
    let mut ids: Vec<u64> = snap.leases.iter().map(|l| l.id).collect();
    let mut expected: Vec<u64> = live.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    expected.sort_unstable();
    assert_eq!(ids, expected, "{case}: live leases");
    for l in &snap.logins {
        for w in &l.windows {
            let sum: f64 = live
                .iter()
                .filter(|(_, e)| e.login == l.name)
                .flat_map(|(_, e)| &e.cost)
                .filter(|(n, _)| *n == w.name)
                .map(|(_, c)| c)
                .sum();
            assert!(
                (w.reserved - sum).abs() < 1e-9,
                "{case}: {} {} reserved {} != {sum}",
                l.name,
                w.name,
                w.reserved
            );
        }
    }
}

#[test]
fn reserved_sums_match_live_leases_over_random_sequences() {
    const NOW: u64 = 1_800_000_000;
    let mut spec = common::spec(vec![role(
        "worker",
        vec![
            step(1, vec![cand("vendor-a", "a", 1), cand("vendor-b", "b", 2)]),
            step(2, vec![cand("vendor-a", "c", 1)]),
        ],
        vec![reserve(1, "seven_day", 0.2), reserve(2, "five_hour", 0.1)],
    )]);
    spec.lease_ttl_s = 6 * HOUR;
    let names: Vec<String> = spec.logins.iter().map(|l| l.name.clone()).collect();
    let (mut runs, mut full, mut releases, mut expiries) = (0, 0, 0, 0);
    for seed in 1..=6u64 {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D ^ seed.wrapping_mul(0x9E37_79B9));
        let mut c = core(spec.clone());
        let mut now = NOW;
        let mut live: Vec<(u64, Expected)> = Vec::new();
        for step_no in 0..800 {
            let case = format!("seed {seed} step {step_no}");
            match rng.below(100) {
                0..=69 => {
                    let burst = rng.chance(2);
                    for _ in 0..if burst { 120 } else { 1 } {
                        let minutes = (!burst && rng.chance(60))
                            .then(|| u32::try_from(rng.below(90)).expect("small"));
                        let target = random_target(&mut rng);
                        let mut req = input("worker", target.clone(), None);
                        req.expected_minutes = minutes;
                        c.tick(now);
                        let before = c.snapshot(now).logins;
                        match c.pick(&req, now) {
                            Verdict::Run(g, _) => {
                                runs += 1;
                                let cost = expected_cost(&spec, &g.vendor, minutes);
                                let d = match target {
                                    Target::Difficulty(_) if g.model == "c" => 2,
                                    Target::Difficulty(_) => 1,
                                    Target::Pin { .. } => 0,
                                };
                                let reserve_of = |w: &str| reserve_at(&spec, d, w);
                                let view =
                                    before.iter().find(|l| l.name == g.login).expect("login");
                                assert!(
                                    admissible_with_cost(&spec, view, &cost, &reserve_of, now),
                                    "{case}: {g:?} on {view:?}"
                                );
                                let expires_at =
                                    now + spec.lease_ttl_s + 60 * u64::from(minutes.unwrap_or(0));
                                assert_eq!(g.expires_at, expires_at, "{case}");
                                live.push((
                                    g.lease,
                                    Expected {
                                        login: g.login,
                                        cost,
                                        expires_at,
                                    },
                                ));
                            }
                            Verdict::Wait {
                                reason: Reason::LeasesFull,
                                ..
                            } => {
                                full += 1;
                                assert_eq!(live.len(), MAX_LEASES, "{case}");
                            }
                            _ => {}
                        }
                    }
                }
                70..=89 => {
                    let (report, lease) = random_report(&mut rng, &names, &live, now);
                    c.report(&report, now).expect("valid report");
                    if let (true, Some(k)) = (report.release, lease) {
                        live.swap_remove(k);
                        releases += 1;
                    }
                }
                _ => {
                    let span = if rng.chance(90) { 120 } else { 6 * HOUR };
                    now += rng.below(span);
                }
            }

            c.tick(now);
            let before = live.len();
            live.retain(|(_, l)| l.expires_at > now);
            expiries += before - live.len();
            check_reserved(&c, &live, now, &case);
        }
    }
    assert!(
        runs > 1000 && full > 100 && releases > 100 && expiries > 500,
        "generator covers every path: {runs} runs, {full} full, {releases} releases, \
         {expiries} expiries"
    );
}
