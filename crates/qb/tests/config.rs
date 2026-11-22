//! Config loading through the same entry points `qbd` uses.

#![allow(clippy::unwrap_used)]

#[path = "common/cleanup.rs"]
mod cleanup;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use qb::config::{self, Journal, Kind};
use qb::gateway::config::{Api, GatewayConfig, Route};
use qb_core::ProbeSpec;

const BASE: &str = r#"
[journal]
mode = "off"

[[vendors]]
name = "vendor-a"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[logins]]
name = "login-1"
vendor = "vendor-a"

[[roles]]
name = "worker"
ladder = [{ difficulty = 1, candidates = [{ vendor = "vendor-a", model = "m", tier = 1 }] }]
"#;

const FILE: &str = "/etc/qb/test.toml";

fn with(extra: &str) -> String {
    format!("{BASE}\n{extra}\n")
}

fn logins(n: usize) -> String {
    (0..n).fold(String::new(), |mut s, i| {
        let _ = write!(
            s,
            "[[logins]]\nname = \"extra-{i}\"\nvendor = \"vendor-a\"\n"
        );
        s
    })
}

fn role_with_candidates(n: usize) -> String {
    let c = vec![r#"{ vendor = "vendor-a", model = "m", tier = 1 }"#; n].join(", ");
    format!("[[roles]]\nname = \"wide\"\nladder = [{{ difficulty = 1, candidates = [{c}] }}]")
}

fn vendor_with_windows(n: usize) -> String {
    let w: Vec<String> = (0..n)
        .map(|i| format!(r#"{{ name = "w{i}", length_s = 60, t_burn_s = 0 }}"#))
        .collect();
    format!(
        "[[vendors]]\nname = \"vendor-b\"\nwindows = [{}]",
        w.join(", ")
    )
}

fn role_with_reserve(window: &str, fraction: &str) -> String {
    format!(
        "[[roles]]\nname = \"keeper\"\n\
         ladder = [{{ difficulty = 1, candidates = [{{ vendor = \"vendor-a\", model = \"m\", tier = 1 }}] }}]\n\
         reserves = [{{ difficulty = 1, window = \"{window}\", fraction = {fraction} }}]"
    )
}

fn client(extra: &str) -> String {
    format!("[[clients]]\nname = \"client-a\"\nrole = \"worker\"\n{extra}")
}

#[test]
fn base_config_is_valid() {
    let cfg = config::parse(Path::new(FILE), BASE).unwrap();
    assert_eq!(cfg.journal, Journal::Off {});
    let spec = cfg.core_spec();
    assert_eq!(spec.logins[0].vendor, "vendor-a");
    assert_eq!(
        (
            spec.lease_ttl_s,
            spec.cost_per_minute,
            spec.rate_limit_backoff_s,
            spec.model_unavailable_s,
            spec.roles[0].ladder[0].candidates[0].cost_per_minute,
        ),
        (3600, 0.002, 60, 86_400, None),
        "documented defaults"
    );
}

#[test]
fn lease_and_outcome_settings_reach_the_core_spec() {
    let text = with(
        "[leases]
ttl_s = 600
cost_per_minute = 0.01
         [outcomes]
rate_limit_backoff_s = 30
model_unavailable_s = 7200",
    )
    .replace(
        "model = \"m\", tier = 1",
        "model = \"m\", tier = 1, cost_per_minute = 0.5",
    );
    let spec = config::parse(Path::new(FILE), &text).unwrap().core_spec();
    assert_eq!(
        (
            spec.lease_ttl_s,
            spec.cost_per_minute,
            spec.rate_limit_backoff_s,
            spec.model_unavailable_s,
            spec.roles[0].ladder[0].candidates[0].cost_per_minute,
        ),
        (600, 0.01, 30, 7200, Some(0.5))
    );
}

#[test]
fn probe_settings_reach_the_core_spec_only_when_enabled() {
    let off = config::parse(Path::new(FILE), BASE).unwrap();
    assert_eq!(
        (off.probe.enabled, off.probe.agents.len()),
        (false, 0),
        "documented defaults"
    );
    assert_eq!(off.core_spec().probe, None);
    let on = with(&format!(
        "{}\nuid = 1\n[probe]\nenabled = true\nagents = [\"client-a\"]\nbackoff_initial_s = 10\nbackoff_max_s = 40",
        client("")
    ));
    let cfg = config::parse(Path::new(FILE), &on).unwrap();
    assert_eq!(cfg.probe.agents, ["client-a"]);
    assert_eq!(
        cfg.core_spec().probe,
        Some(ProbeSpec {
            backoff_initial_s: 10,
            backoff_max_s: 40
        })
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one flat table of cases reads best
fn rejections_name_the_field() {
    let hex64 = "ab".repeat(32);
    let cases: Vec<(&str, String, &str, &str)> = vec![
        (
            "unknown key in a table",
            with("[[logins]]\nname = \"login-2\"\nvendor = \"vendor-a\"\npassword = \"x\""),
            "logins[1].password",
            "unknown field `password`",
        ),
        (
            "unknown top-level key",
            with("[extra]\nx = 1"),
            "extra",
            "unknown field `extra`",
        ),
        (
            "unknown key in a settings table",
            with("[limits]\nburst = 1\nper_minute = 3"),
            "limits.per_minute",
            "unknown field `per_minute`",
        ),
        (
            "duplicate login",
            with("[[logins]]\nname = \"login-1\"\nvendor = \"vendor-a\""),
            "logins[1].name",
            "duplicate name `login-1`",
        ),
        (
            "duplicate vendor",
            with("[[vendors]]\nname = \"vendor-a\"\nwindows = []"),
            "vendors[1].name",
            "duplicate name `vendor-a`",
        ),
        (
            "duplicate window of a vendor",
            with(
                "[[vendors]]\nname = \"vendor-b\"\nwindows = [\
                 { name = \"w\", length_s = 60, t_burn_s = 0 }, \
                 { name = \"w\", length_s = 90, t_burn_s = 0 }]",
            ),
            "vendors[1].windows[1].name",
            "duplicate name `w`",
        ),
        (
            "duplicate role",
            with("[[roles]]\nname = \"worker\"\nladder = []"),
            "roles[1].name",
            "duplicate name `worker`",
        ),
        (
            "duplicate client",
            with(&format!("{}\nuid = 1\n{}\nuid = 2", client(""), client(""))),
            "clients[1].name",
            "duplicate name `client-a`",
        ),
        (
            "undeclared vendor of a login",
            with("[[logins]]\nname = \"login-2\"\nvendor = \"vendor-z\""),
            "logins[1].vendor",
            "undeclared vendor `vendor-z`",
        ),
        (
            "undeclared vendor of a candidate",
            with(
                "[[roles]]\nname = \"r\"\nladder = [{ difficulty = 0, candidates = [\
                 { vendor = \"vendor-a\", model = \"m\", tier = 1 }, \
                 { vendor = \"vendor-z\", model = \"m\", tier = 1 }] }]",
            ),
            "roles[1].ladder[0].candidates[1].vendor",
            "undeclared vendor `vendor-z`",
        ),
        (
            "undeclared window of a reserve",
            with(&role_with_reserve("one_day", "0.1")),
            "roles[1].reserves[0].window",
            "undeclared window `one_day`",
        ),
        (
            "undeclared role of a client",
            with(&client("uid = 1").replace("\"worker\"", "\"admin\"")),
            "clients[0].role",
            "undeclared role `admin`",
        ),
        (
            "client without a role that is not an agent",
            with("[[clients]]\nname = \"client-a\"\nuid = 1"),
            "clients[0].role",
            "missing; only a client in `probe.agents` may omit it",
        ),
        (
            "undeclared client as an agent",
            with(&format!(
                "{}\nuid = 1\n[probe]\nagents = [\"client-z\"]",
                client("")
            )),
            "probe.agents[0]",
            "undeclared client `client-z`",
        ),
        (
            "more than 32 logins",
            with(&logins(32)),
            "logins",
            "33 entries, at most 32 allowed",
        ),
        (
            "more than 4 windows",
            with(&vendor_with_windows(5)),
            "vendors[1].windows",
            "5 entries, at most 4 allowed",
        ),
        (
            "more than 8 candidates",
            with(&role_with_candidates(9)),
            "roles[1].ladder[0].candidates",
            "9 entries, at most 8 allowed",
        ),
        (
            "fraction above 1",
            with(&role_with_reserve("five_hour", "1.5")),
            "roles[1].reserves[0].fraction",
            "1.5 is outside 0.0..=1.0",
        ),
        (
            "negative fraction",
            with(&role_with_reserve("five_hour", "-0.1")),
            "roles[1].reserves[0].fraction",
            "-0.1 is outside 0.0..=1.0",
        ),
        (
            "plaintext bearer",
            with(&client("bearer_sha256 = \"s3cret-token\"")),
            "clients[0].bearer_sha256",
            "64 hex characters",
        ),
        (
            "64 characters that are not hex",
            with(&client(&format!("bearer_sha256 = \"{}\"", "zz".repeat(32)))),
            "clients[0].bearer_sha256",
            "64 hex characters",
        ),
        (
            "64 characters with a sign",
            with(&client(&format!("bearer_sha256 = \"+f{}\"", &hex64[..62]))),
            "clients[0].bearer_sha256",
            "64 hex characters",
        ),
        (
            "token pasted into the uid",
            with(&client("uid = \"s3cret-token\"")),
            "clients[0].uid",
            "invalid type: string, expected u32",
        ),
        (
            "token with a quote pasted into a number",
            with("[limits]\nburst = 's3cret\"token'"),
            "limits.burst",
            "invalid type: string, expected u32",
        ),
        (
            "token pasted into the journal mode",
            BASE.replace("mode = \"off\"", "mode = \"s3cret-token\""),
            "journal.mode",
            "unknown variant, expected",
        ),
        (
            "token with a backtick and comma pasted into the journal mode",
            BASE.replace("mode = \"off\"", "mode = \"x`, s3cret-token\""),
            "journal.mode",
            "unknown variant, expected",
        ),
        (
            "hex of the wrong length",
            with(&client(&format!("bearer_sha256 = \"{}\"", &hex64[..62]))),
            "clients[0].bearer_sha256",
            "64 hex characters",
        ),
        (
            "plaintext token under another key",
            with(&client("bearer = \"s3cret-token\"")),
            "clients[0].bearer",
            "unknown field `bearer`",
        ),
        (
            "unknown key of the off journal",
            BASE.replace(
                "mode = \"off\"",
                "mode = \"off\"\npath = \"/var/lib/qb/journal\"",
            ),
            "journal",
            "unknown field `path`",
        ),
        (
            "zero lease ttl",
            with("[leases]\nttl_s = 0"),
            "leases.ttl_s",
            "must be positive",
        ),
        (
            "zero 429 back-off",
            with("[outcomes]\nrate_limit_backoff_s = 0"),
            "outcomes.rate_limit_backoff_s",
            "must be positive",
        ),
        (
            "zero model-dead time",
            with("[outcomes]\nmodel_unavailable_s = 0"),
            "outcomes.model_unavailable_s",
            "must be positive",
        ),
        (
            "candidate cost rate above 1",
            BASE.replace("tier = 1 }", "tier = 1, cost_per_minute = 2.0 }"),
            "roles[0].ladder[0].candidates[0].cost_per_minute",
            "2 is outside 0.0..=1.0",
        ),
        (
            "empty hook command",
            with("[hooks]\non_dead = []"),
            "hooks.on_dead",
            "is empty",
        ),
        (
            "relative hook program",
            with("[hooks]\non_recover = [\"bin/alert\", \"/abs/arg\"]"),
            "hooks.on_recover[0]",
            "must be an absolute path",
        ),
        (
            "unknown key in hooks",
            with("[hooks]\non_exhausted = [\"/usr/bin/true\"]"),
            "hooks.on_exhausted",
            "unknown field `on_exhausted`",
        ),
        ("not TOML", with("[[logins]\nname = 1"), "", "line"),
    ];
    for (what, text, field, reason) in cases {
        let err = config::parse(Path::new(FILE), &text).unwrap_err();
        assert_eq!(err.field, field, "{what}: {err}");
        assert!(err.reason.contains(reason), "{what}: {err}");
        assert!(
            !err.reason.contains("s3cret"),
            "{what}: echoes the token: {err}"
        );
    }
}

#[test]
fn hooks_are_optional_and_keep_program_and_arguments() {
    let none = config::parse(Path::new(FILE), BASE).unwrap();
    assert_eq!((none.hooks.on_dead, none.hooks.on_recover), (None, None));
    let text = with(
        "[hooks]\non_dead = [\"/usr/bin/logger\", \"-t\", \"qb\"]\non_recover = [\"/usr/local/libexec/qb-hook\"]",
    );
    let cfg = config::parse(Path::new(FILE), &text).unwrap();
    assert_eq!(
        cfg.hooks.on_dead.as_deref(),
        Some(
            &[
                "/usr/bin/logger".to_owned(),
                "-t".to_owned(),
                "qb".to_owned()
            ][..]
        )
    );
    assert_eq!(
        cfg.hooks.on_recover.as_deref(),
        Some(&["/usr/local/libexec/qb-hook".to_owned()][..])
    );
}

#[test]
fn a_probe_agent_client_may_omit_its_role() {
    let cfg = config::parse(
        Path::new(FILE),
        &with("[[clients]]\nname = \"agent-a\"\nuid = 1\n[probe]\nagents = [\"agent-a\"]"),
    )
    .unwrap();
    assert_eq!(cfg.clients[0].role, None);
}

#[test]
fn limits_at_the_bound_are_accepted() {
    let hex64 = "AB".repeat(32);
    for text in [
        with(&logins(31)),
        with(&vendor_with_windows(4)),
        with(&role_with_candidates(8)),
        with(&role_with_reserve("five_hour", "1.0")),
        with(&role_with_reserve("five_hour", "0")),
        with(&client(&format!("bearer_sha256 = \"{hex64}\""))),
    ] {
        if let Err(e) = config::parse(Path::new(FILE), &text) {
            panic!("{e}\n{text}");
        }
    }
}

#[test]
fn errors_name_the_file() {
    let err = config::parse(
        Path::new(FILE),
        &with("[[logins]]\nname = \"x\"\nvendor = \"v\""),
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "/etc/qb/test.toml: logins[1].vendor: undeclared vendor `v` (line 19)"
    );
    let missing = Path::new("/nonexistent/qbd.toml");
    let err = config::load(missing).unwrap_err();
    assert_eq!(err.file, missing);
    assert!(err.reason.starts_with("cannot read"), "{err}");
}

/// [`BASE`] without its `[[roles]]`.
fn without_roles() -> &'static str {
    BASE.split_once("[[roles]]").unwrap().0
}

/// A roles file of `text` in a directory of its own.
fn roles_file(tag: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qb-config-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::remove_at_test_end(&dir);
    let file = dir.join("roles.toml");
    std::fs::write(&file, text).unwrap();
    file
}

/// [`without_roles`] naming `roles` as its `roles_file`, with `extra` appended.
fn naming(roles: &Path, extra: &str) -> String {
    format!(
        "roles_file = \"{}\"\n{}\n{extra}\n",
        roles.display(),
        without_roles()
    )
}

const WORKER: &str = r#"
[[roles]]
name = "worker"
ladder = [{ difficulty = 1, candidates = [{ vendor = "vendor-a", model = "m", tier = 1 }] }]
"#;

#[test]
fn a_roles_file_holds_the_roles_a_config_without_one_declares_itself() {
    let roles = roles_file("holds", WORKER);
    let cfg = config::parse(Path::new(FILE), &naming(&roles, &client("uid = 1"))).unwrap();
    assert_eq!(cfg.roles_file.as_deref(), Some(roles.as_path()));
    let inline = config::parse(Path::new(FILE), BASE).unwrap();
    assert_eq!(inline.roles_file, None);
    assert_eq!(cfg.core_spec(), inline.core_spec());
}

#[test]
fn roles_file_faults_name_their_file_field_and_line() {
    let worker = roles_file("worker", WORKER);
    let stray = roles_file(
        "stray",
        "[[roles]]\nname = \"worker\"\n\
         ladder = [{ difficulty = 1, candidates = [{ vendor = \"vendor-z\", model = \"m\", tier = 1 }] }]\n",
    );
    let twice = roles_file("twice", &format!("{WORKER}{WORKER}"));
    let settings = roles_file("settings", &format!("{WORKER}\n[limits]\nburst = 1\n"));
    let missing = Path::new("/nonexistent/roles.toml");
    let file = Path::new(FILE);
    let cases: Vec<(&str, String, &Path, &str, &str)> = vec![
        (
            "roles in both files",
            format!("roles_file = \"{}\"\n{BASE}", worker.display()),
            file,
            "roles",
            "is not allowed with `roles_file`, which holds the roles (line 14)",
        ),
        (
            "a client of a role the roles file lacks",
            naming(
                &worker,
                "[[clients]]\nname = \"c\"\nuid = 1\nrole = \"reviewer\"",
            ),
            file,
            "clients[0].role",
            "undeclared role `reviewer` (line 18)",
        ),
        (
            "a candidate of an undeclared vendor",
            naming(&stray, ""),
            &stray,
            "roles[0].ladder[0].candidates[0].vendor",
            "undeclared vendor `vendor-z` (line 3)",
        ),
        (
            "a duplicate role",
            naming(&twice, ""),
            &twice,
            "roles[1].name",
            "duplicate name `worker` (line 7)",
        ),
        (
            "a key other than roles",
            naming(&settings, ""),
            &settings,
            "limits",
            "unknown field `limits`",
        ),
        (
            "a missing roles file",
            naming(missing, ""),
            missing,
            "",
            "cannot read",
        ),
        (
            "a relative roles file",
            naming(Path::new("roles.toml"), ""),
            file,
            "roles_file",
            "must be absolute",
        ),
        (
            "no roles anywhere",
            without_roles().to_owned(),
            file,
            "roles",
            "is missing",
        ),
    ];
    for (what, text, in_file, field, reason) in cases {
        let err = config::parse(file, &text).unwrap_err();
        assert_eq!(
            (err.file.as_path(), err.field.as_str()),
            (in_file, field),
            "{what}: {err}"
        );
        assert!(err.reason.contains(reason), "{what}: {err}");
    }
}

#[test]
fn only_roles_and_clients_change_without_a_restart() {
    let running = config::parse(Path::new(FILE), BASE).unwrap();
    let roles = format!(
        "{BASE}\n[[roles]]\nname = \"reviewer\"\n\
         ladder = [{{ difficulty = 2, candidates = [{{ vendor = \"vendor-a\", model = \"n\", tier = 1 }}] }}]\n{}\nuid = 7",
        client("")
    );
    let roles = config::parse(Path::new(FILE), &roles).unwrap();
    assert_eq!(running.restart_only_change(&roles), None);
    let file = roles_file("restart", WORKER);
    for (text, key) in [
        (
            with("[[logins]]\nname = \"login-2\"\nvendor = \"vendor-a\""),
            "logins",
        ),
        (with("[limits]\nburst = 1"), "limits"),
        (with("[hooks]\non_dead = [\"/usr/bin/true\"]"), "hooks"),
        (naming(&file, ""), "roles_file"),
    ] {
        let candidate = config::parse(Path::new(FILE), &text).unwrap();
        assert_eq!(running.restart_only_change(&candidate), Some(key), "{text}");
    }
}

#[test]
fn shipped_examples_validate() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/examples");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "toml") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let loaded = match name {
                "agent.toml" => config::load_agent(&path).map(drop),
                "gateway.toml" => qb::gateway::config::load(&path).map(drop),
                _ => config::load(&path).map(drop),
            };
            if let Err(e) = loaded {
                panic!("{e}");
            }
            seen += 1;
        }
    }
    assert!(seen > 1, "no examples in {}", dir.display());
}

fn served_by<'a>(qbd: &'a config::Config, vendor: &str) -> Vec<&'a str> {
    qbd.logins
        .iter()
        .filter(|l| l.vendor == vendor)
        .map(|l| l.name.as_str())
        .collect()
}

/// Breaks of the rule that each front's vendor serves gateway logins of the front's API family.
fn front_faults(qbd: &config::Config, gw: &GatewayConfig) -> Vec<String> {
    let mut faults = Vec::new();
    let fronts = gw.fronts.as_ref();
    for (front, vendor, api) in [
        (
            "messages",
            fronts.and_then(|f| f.messages.as_ref()).map(|m| &m.vendor),
            Api::Anthropic,
        ),
        (
            "openai",
            fronts.and_then(|f| f.openai.as_ref()).map(|o| &o.vendor),
            Api::Openai,
        ),
    ] {
        let Some(vendor) = vendor else { continue };
        let logins = served_by(qbd, vendor);
        if logins.is_empty() {
            faults.push(format!(
                "front {front}: vendor `{vendor}` serves no qbd login"
            ));
        }
        for login in logins {
            if gw.login(login).is_none_or(|l| l.api != api) {
                faults.push(format!(
                    "front {front}: `{login}` does not speak {}",
                    api.as_str()
                ));
            }
        }
    }
    faults
}

/// The vendors of the candidates of every ladder step of `role`.
fn candidate_vendors(role: &config::Role) -> impl Iterator<Item = &str> {
    role.ladder
        .iter()
        .flat_map(|s| &s.candidates)
        .map(|c| c.vendor.as_str())
}

/// The vendors of the candidates qbd tries for a pick at `difficulty` of `role`: those of its
/// step and of the steps next to it in difficulty order.
fn reachable_vendors(role: &config::Role, difficulty: u8) -> Vec<&str> {
    let mut steps: Vec<&config::Step> = role.ladder.iter().collect();
    steps.sort_by_key(|s| s.difficulty);
    let Some(at) = steps.iter().position(|s| s.difficulty == difficulty) else {
        return Vec::new();
    };
    steps[at.saturating_sub(1)..steps.len().min(at + 2)]
        .iter()
        .flat_map(|s| &s.candidates)
        .map(|c| c.vendor.as_str())
        .collect()
}

/// Breaks of the rule that a route's `logins` hold a login of its pinned vendor, of each chain
/// step's vendor, or, on a ladder route, of a candidate vendor of its step of `role` or of a
/// step next to it: without one qbd never picks the route, or that chain step.
fn listed_faults(qbd: &config::Config, route: &Route, role: &config::Role) -> Vec<String> {
    let Some(names) = &route.logins else {
        return Vec::new();
    };
    let alias = &route.alias;
    let listed = |vendor: &str| {
        served_by(qbd, vendor)
            .iter()
            .any(|l| names.iter().any(|n| n == l))
    };
    let pinned = route.chain.iter().map(|s| s.vendor.as_str());
    let mut faults: Vec<String> = pinned
        .chain(route.vendor.as_deref())
        .filter(|v| !listed(v))
        .map(|v| format!("route `{alias}`: no listed login serves vendor `{v}`"))
        .collect();
    if let Some(d) = route.difficulty {
        let vendors = reachable_vendors(role, d);
        if !vendors.is_empty() && !vendors.into_iter().any(listed) {
            faults.push(format!(
                "route `{alias}`: no listed login serves a candidate vendor of step {d} of `{}` \
                 or a step next to it",
                role.name
            ));
        }
    }
    faults
}

/// Every break of the rules that make `gw` and `qbd` one installation (docs/config.md, Gateway
/// config and Spend caps), one line each.
fn installation_faults(qbd: &config::Config, gw: &GatewayConfig) -> Vec<String> {
    let mut faults = Vec::new();
    let has_spend = |vendor: &str| {
        qbd.vendors
            .iter()
            .any(|v| v.name == vendor && v.windows.iter().any(|w| w.name == "spend"))
    };
    let mut pickable: Vec<&str> = Vec::new();
    for route in &gw.routes {
        let alias = &route.alias;
        let Some(role) = qbd.roles.iter().find(|r| r.name == route.role) else {
            faults.push(format!("route `{alias}`: role `{}` not in qbd", route.role));
            continue;
        };
        let mut vendors: Vec<&str> = route.chain.iter().map(|s| s.vendor.as_str()).collect();
        vendors.extend(route.vendor.as_deref());
        faults.extend(listed_faults(qbd, route, role));
        if let Some(difficulty) = route.difficulty {
            if !role.ladder.iter().any(|s| s.difficulty == difficulty) {
                faults.push(format!(
                    "route `{alias}`: no step {difficulty} in `{}`",
                    role.name
                ));
            }
            vendors.extend(candidate_vendors(role));
        }
        for vendor in vendors {
            let logins = served_by(qbd, vendor);
            if logins.is_empty() {
                faults.push(format!(
                    "route `{alias}`: vendor `{vendor}` serves no qbd login"
                ));
            }
            for login in logins {
                if gw.login(login).is_none() {
                    faults.push(format!("route `{alias}`: `{login}` is no gateway login"));
                }
            }
            pickable.push(vendor);
        }
    }
    // The gateway's own qbd client needs a role one of the routes names; qbd picks the role a
    // request names, not the caller's, so the other route roles need no client of their own.
    if !gw.routes.is_empty()
        && !qbd.clients.iter().any(|c| {
            c.role
                .as_deref()
                .is_some_and(|role| gw.routes.iter().any(|r| r.role == role))
        })
    {
        faults.push("no qbd client has a role the routes name".to_owned());
    }
    for login in &gw.logins {
        let name = &login.name;
        let Some(declared) = qbd.logins.iter().find(|l| &l.name == name) else {
            faults.push(format!("gateway login `{name}` not in qbd"));
            continue;
        };
        let vendor = declared.vendor.as_str();
        if !pickable.contains(&vendor) {
            faults.push(format!("`{name}`: no route picks vendor `{vendor}`"));
        }
        if login.spend_cap.is_some() && !has_spend(vendor) {
            faults.push(format!(
                "capped `{name}`: vendor `{vendor}` has no spend window"
            ));
        }
    }
    for vendor in qbd.vendors.iter().filter(|v| has_spend(&v.name)) {
        for login in served_by(qbd, &vendor.name) {
            if gw.login(login).is_none_or(|l| l.spend_cap.is_none()) {
                faults.push(format!(
                    "spend vendor `{}`: `{login}` is uncapped",
                    vendor.name
                ));
            }
        }
    }
    faults.extend(front_faults(qbd, gw));
    faults
}

fn example_faults(qbd_edit: (&str, &str), gw_edit: (&str, &str)) -> Vec<String> {
    let edited = |name: &str, (from, to): (&str, &str)| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/examples")
            .join(name);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(from), "{name} has no {from:?}");
        (path, text.replace(from, to))
    };
    let (qbd_path, qbd_text) = edited("qbd.toml", qbd_edit);
    let (gw_path, gw_text) = edited("gateway.toml", gw_edit);
    let qbd = config::parse(&qbd_path, &qbd_text).unwrap();
    let gw = qb::gateway::config::parse(&gw_path, &gw_text).unwrap();
    installation_faults(&qbd, &gw)
}

#[test]
fn shipped_gateway_and_qbd_examples_are_one_installation() {
    assert_eq!(example_faults(("", ""), ("", "")), Vec::<String>::new());
}

#[test]
fn a_broken_installation_rule_is_found_in_either_example() {
    let qbd = |from, to| ((from, to), ("", ""));
    let gw = |from, to| (("", ""), (from, to));
    let cases = [
        (
            qbd(
                "name = \"login-2\"\nvendor = \"vendor-a\"",
                "name = \"login-9\"\nvendor = \"vendor-a\"",
            ),
            "route `chat`: `login-9` is no gateway login",
        ),
        (
            qbd(
                "name = \"key-1\"\nvendor = \"vendor-e\"",
                "name = \"key-9\"\nvendor = \"vendor-e\"",
            ),
            "gateway login `key-1` not in qbd",
        ),
        (
            qbd(
                "name = \"key-3\"\nvendor = \"vendor-d\"",
                "name = \"key-3\"\nvendor = \"vendor-a\"",
            ),
            "capped `key-3`: vendor `vendor-a` has no spend window",
        ),
        (
            qbd(
                "name = \"key-1\"\nvendor = \"vendor-e\"",
                "name = \"key-1\"\nvendor = \"vendor-c\"",
            ),
            "spend vendor `vendor-c`: `key-1` is uncapped",
        ),
        (
            qbd(
                "name = \"gateway\"\nuid = 1003\nrole = \"gateway\"",
                "name = \"gateway\"\nuid = 1003\nrole = \"worker\"",
            ),
            "no qbd client has a role the routes name",
        ),
        (
            gw(
                "{ vendor = \"vendor-d\", model",
                "{ vendor = \"vendor-f\", model",
            ),
            "route `chat`: vendor `vendor-f` serves no qbd login",
        ),
        (
            gw(
                "[fronts.openai]\nvendor = \"vendor-b\"",
                "[fronts.openai]\nvendor = \"vendor-a\"",
            ),
            "front openai: `login-1` does not speak openai",
        ),
        (
            gw("difficulty = 1", "difficulty = 2"),
            "route `work`: no step 2 in `gateway`",
        ),
        (
            gw(
                "vendor = \"vendor-a\"\nmodel = \"model-small\"",
                "vendor = \"vendor-a\"\nmodel = \"model-small\"\nlogins = [\"key-1\"]",
            ),
            "route `compact`: no listed login serves vendor `vendor-a`",
        ),
        (
            gw(
                "expected_minutes = 2",
                "expected_minutes = 2\nlogins = [\"login-1\", \"key-2\"]",
            ),
            "route `chat`: no listed login serves vendor `vendor-d`",
        ),
        (
            gw(
                "logins = [\"login-1\", \"login-3\", \"key-4\"]",
                "logins = [\"key-1\"]",
            ),
            "route `hive-step-1`: no listed login serves a candidate vendor of step 1 of \
             `hive-heads` or a step next to it",
        ),
    ];
    for ((qbd_edit, gw_edit), fault) in cases {
        let faults = example_faults(qbd_edit, gw_edit);
        assert!(faults.iter().any(|f| f == fault), "{fault}: {faults:?}");
    }
}

#[test]
fn a_ladder_route_s_logins_must_serve_its_step_or_a_step_next_to_it() {
    // key-1 (vendor-e) serves a candidate of step 5 of hive-heads only.
    let faults = example_faults(
        (
            "{ vendor = \"vendor-g\", model = \"model-large\", effort = \"max\", tier = 3 }",
            "{ vendor = \"vendor-e\", model = \"model-large\", effort = \"max\", tier = 3 }",
        ),
        (
            "logins = [\"login-1\", \"login-3\", \"key-4\"]",
            "logins = [\"key-1\"]",
        ),
    );
    let ladder: Vec<&str> = faults
        .iter()
        .filter(|f| f.contains("a step next to it"))
        .filter_map(|f| f.strip_prefix("route `")?.split('`').next())
        .collect();
    assert_eq!(
        ladder,
        ["hive-step-1", "hive-step-2", "hive-step-3"],
        "{faults:?}"
    );
}

const AGENT: &str = r#"
[[logins]]
name = "login-1"
kind = "claude"
credentials = ".claude/.credentials.json"
"#;

#[test]
fn agent_config_lists_logins_with_kind_and_credentials() {
    let cfg = config::parse_agent(Path::new(FILE), AGENT).unwrap();
    let login = &cfg.logins[0];
    assert_eq!(
        (login.name.as_str(), login.kind, login.credentials.as_path()),
        (
            "login-1",
            Kind::Claude,
            Path::new(".claude/.credentials.json")
        )
    );
}

#[test]
fn agent_config_rejections_name_the_field() {
    let codex = "[[logins]]\nname = \"login-2\"\nkind = \"codex\"\ncredentials = \"c\"";
    let cases: Vec<(&str, String, &str, &str)> = vec![
        ("no logins", String::new(), "", "missing field `logins`"),
        ("empty logins", "logins = []".into(), "logins", "is empty"),
        (
            "duplicate login",
            format!("{AGENT}{}", AGENT.replace("claude", "codex")),
            "logins[1].name",
            "duplicate name `login-1`",
        ),
        (
            "unknown kind",
            AGENT.replace("claude", "vendor-x"),
            "logins[0].kind",
            "unknown variant",
        ),
        (
            "empty credentials",
            AGENT.replace(".claude/.credentials.json", ""),
            "logins[0].credentials",
            "is empty",
        ),
        (
            "unknown key",
            format!("{AGENT}token = \"s3cret\""),
            "logins[0].token",
            "unknown field `token`",
        ),
        (
            "missing credentials",
            codex.replace("\ncredentials = \"c\"", ""),
            "logins[0]",
            "missing field `credentials`",
        ),
    ];
    for (what, text, field, reason) in cases {
        let err = config::parse_agent(Path::new(FILE), &text).unwrap_err();
        assert_eq!(err.field, field, "{what}: {err}");
        assert!(err.reason.contains(reason), "{what}: {err}");
    }
}
