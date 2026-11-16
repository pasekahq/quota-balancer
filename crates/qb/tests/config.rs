//! Config loading through the same entry points `qbd` uses.

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use qb::config::{self, Journal};

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
        "/etc/qb/test.toml: logins[1].vendor: undeclared vendor `v`"
    );
    let missing = Path::new("/nonexistent/qbd.toml");
    let err = config::load(missing).unwrap_err();
    assert_eq!(err.file, missing);
    assert!(err.reason.starts_with("cannot read"), "{err}");
}

#[test]
fn shipped_examples_validate() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/examples");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "toml") {
            if let Err(e) = config::load(&path) {
                panic!("{e}");
            }
            seen += 1;
        }
    }
    assert!(seen > 0, "no examples in {}", dir.display());
}
