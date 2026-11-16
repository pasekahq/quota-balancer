//! Property: for random specs, snapshots and `now`, every `run` is admissible under the reserve
//! rule, and `wait`/`dead` happen only when no tried (candidate, login) pair is admissible.

mod common;

use common::{DAY, HOUR, cand, core, input, login, observe, reserve, role, step, vendor, window};
use qb_core::{LoginView, Reason, RoleSpec, Spec, Target, VendorSpec, Verdict};

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
