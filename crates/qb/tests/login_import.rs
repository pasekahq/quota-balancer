//! `qb login import` through the binary: every source format and every refusal, with marker
//! secrets that must never reach stdout or stderr.

#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use common::temp_dir;

/// Part of every synthetic secret; it must appear in no output.
const MARK: &str = "mark-5f2c";

/// A gateway config with an `oauth_anthropic`, a `chatgpt_oauth` and an `api_key` login.
struct Setup {
    dir: PathBuf,
    config: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let dir = temp_dir("import");
        std::fs::create_dir_all(dir.join("creds")).unwrap();
        let config = dir.join("gateway.toml");
        let d = dir.display();
        std::fs::write(
            &config,
            format!(
                r#"socket = "{d}/gw.sock"

[[logins]]
name = "login-oauth"
kind = "oauth_anthropic"
credentials = "{d}/creds/login-oauth.json"

[[logins]]
name = "login-chatgpt"
kind = "chatgpt_oauth"
credentials = "{d}/creds/login-chatgpt.json"

[[logins]]
name = "login-key"
kind = "api_key"
api = "anthropic"
credentials = "{d}/creds/login-key.json"

[[routes]]
alias = "chat"
role = "gateway"
difficulty = 1
"#
            ),
        )
        .unwrap();
        Self { dir, config }
    }

    /// Writes the source file `name` with `contents`.
    fn source(&self, name: &str, contents: &str) -> PathBuf {
        let f = self.dir.join(name);
        std::fs::write(&f, contents).unwrap();
        f
    }

    fn target(&self, login: &str) -> PathBuf {
        self.dir.join("creds").join(format!("{login}.json"))
    }

    /// Runs `qb login import <login> --config <config> --source <source> args...`; its exit code
    /// and stdout and stderr together, after checking that no marker is among them.
    fn import(&self, login: &str, source: &Path, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_qb"))
            .args(["login", "import", login, "--config"])
            .arg(&self.config)
            .arg("--source")
            .arg(source)
            .args(args)
            .env_remove("JOURNAL_STREAM")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!text.contains(MARK), "a value leaked: {text}");
        (out.status.code().unwrap(), text)
    }

    /// The written credential file of `login`, after checking it is 0600.
    fn written(&self, login: &str) -> Value {
        let f = self.target(login);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        serde_json::from_slice(&std::fs::read(f).unwrap()).unwrap()
    }
}

fn b64url(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(DIGITS[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    out
}

/// An unsigned JWT with `claims`; the marker sits in its signature.
fn jwt(claims: &Value) -> String {
    format!(
        "{}.{}.sig-{MARK}",
        b64url(br#"{"alg":"none"}"#),
        b64url(claims.to_string().as_bytes())
    )
}

fn account_claims(account: &str) -> Value {
    json!({"https://api.openai.com/auth": {"chatgpt_account_id": account}, "sub": MARK})
}

fn hermes_pool() -> String {
    json!({
        "version": 1,
        "providers": {"nous": {"access_token": format!("nous-{MARK}")}},
        "credential_pool": {
            "anthropic": [
                {
                    "id": "a1b2c3", "label": "work", "auth_type": "oauth", "priority": 0,
                    "source": "manual", "access_token": format!("sk-ant-oat-{MARK}"),
                    "refresh_token": format!("sk-ant-ort-{MARK}"),
                    "expires_at_ms": 1_800_000_123_456_u64, "last_status": null
                },
                {
                    "id": "d4e5f6", "label": "spare", "auth_type": "api_key",
                    "access_token": format!("sk-ant-api-{MARK}")
                },
                {
                    "id": "070809", "label": "spare", "auth_type": "api_key",
                    "access_token": format!("sk-ant-api2-{MARK}")
                }
            ],
            "openai-codex": [
                {
                    "id": "c0dex1", "label": "codex", "auth_type": "oauth",
                    "access_token": jwt(&account_claims(&format!("acct-{MARK}"))),
                    "refresh_token": format!("rt-{MARK}"),
                    "expires_at": "2027-01-15T09:00:00.123456+01:00",
                    "extra_field": format!("x-{MARK}")
                }
            ]
        }
    })
    .to_string()
}

#[test]
fn a_hermes_anthropic_oauth_entry_becomes_an_oauth_anthropic_file_with_a_warning() {
    let s = Setup::new();
    let src = s.source("auth.json", &hermes_pool());
    let (code, out) = s.import(
        "login-oauth",
        &src,
        &[
            "--from",
            "hermes",
            "--provider",
            "anthropic",
            "--entry",
            "work",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        s.written("login-oauth"),
        json!({
            "type": "oauth_anthropic",
            "access_token": format!("sk-ant-oat-{MARK}"),
            "refresh_token": format!("sk-ant-ort-{MARK}"),
            "expires_at": 1_800_000_123_u64,
        })
    );
    assert_eq!(out.matches("warn:").count(), 1, "{out}");
    assert!(
        out.contains("Hermes and the gateway now share one single-use refresh token"),
        "{out}"
    );
    assert!(out.contains("`qb login`"), "{out}");
}

#[test]
fn a_hermes_codex_entry_takes_its_account_from_the_token_claims_and_its_iso_expiry() {
    let s = Setup::new();
    let src = s.source("auth.json", &hermes_pool());
    let (code, out) = s.import(
        "login-chatgpt",
        &src,
        &["--from", "hermes", "--provider", "openai-codex"],
    );
    assert_eq!(code, 0, "{out}");
    let written = s.written("login-chatgpt");
    assert_eq!(written["type"], "chatgpt_oauth");
    assert_eq!(written["account_id"], format!("acct-{MARK}"));
    assert_eq!(written["refresh_token"], format!("rt-{MARK}"));
    assert_eq!(written["expires_at"], 1_800_000_000_u64);
    assert!(out.contains("warn: qb: Hermes and the gateway"), "{out}");
}

#[test]
fn a_hermes_api_key_entry_becomes_an_api_key_file_without_a_warning() {
    let s = Setup::new();
    let src = s.source("auth.json", &hermes_pool());
    let (code, out) = s.import(
        "login-key",
        &src,
        &[
            "--from",
            "hermes",
            "--provider",
            "anthropic",
            "--entry",
            "d4e5f6",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        s.written("login-key"),
        json!({"type": "api_key", "key": format!("sk-ant-api-{MARK}")})
    );
    assert!(!out.contains("warn"), "{out}");
}

#[test]
fn claude_code_credentials_become_an_oauth_anthropic_file() {
    let s = Setup::new();
    let src = s.source(
        ".credentials.json",
        &json!({"claudeAiOauth": {
            "accessToken": format!("at-{MARK}"),
            "refreshToken": format!("rt-{MARK}"),
            "expiresAt": 1_800_000_999_000_u64,
            "scopes": ["user:inference"],
            "subscriptionType": "max"
        }})
        .to_string(),
    );
    let (code, out) = s.import("login-oauth", &src, &["--from", "claude-code"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        s.written("login-oauth"),
        json!({
            "type": "oauth_anthropic",
            "access_token": format!("at-{MARK}"),
            "refresh_token": format!("rt-{MARK}"),
            "expires_at": 1_800_000_999_u64,
        })
    );
    assert!(out.contains("Claude Code and the gateway"), "{out}");
}

#[test]
fn codex_tokens_take_the_account_id_or_else_the_id_token_claim() {
    for (account_id, id_token) in [
        (Some(format!("acct-{MARK}")), None),
        (None, Some(jwt(&account_claims(&format!("acct-{MARK}"))))),
    ] {
        let s = Setup::new();
        let src = s.source(
            "auth.json",
            &json!({
                "OPENAI_API_KEY": null,
                "tokens": {
                    "access_token": format!("at-{MARK}"),
                    "refresh_token": format!("rt-{MARK}"),
                    "id_token": id_token,
                    "account_id": account_id,
                },
                "last_refresh": "2026-01-01T00:00:00Z"
            })
            .to_string(),
        );
        let (code, out) = s.import("login-chatgpt", &src, &["--from", "codex"]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            s.written("login-chatgpt"),
            json!({
                "type": "chatgpt_oauth",
                "access_token": format!("at-{MARK}"),
                "refresh_token": format!("rt-{MARK}"),
                "account_id": format!("acct-{MARK}"),
            })
        );
        assert!(out.contains("the Codex CLI and the gateway"), "{out}");
    }
}

#[test]
fn an_env_variable_becomes_an_api_key_file() {
    let s = Setup::new();
    let src = s.source(
        "vendor.env",
        &format!(
            "# keys\nOTHER=other-{MARK}\nexport VENDOR_KEY=\"sk-{MARK}\"\nVENDOR_KEY_2=x-{MARK}\n"
        ),
    );
    let (code, out) = s.import("login-key", &src, &["--from", "env", "--var", "VENDOR_KEY"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        s.written("login-key"),
        json!({"type": "api_key", "key": format!("sk-{MARK}")})
    );
    assert!(!out.contains("warn"), "{out}");
}

#[test]
fn an_existing_file_is_replaced_only_with_force() {
    let s = Setup::new();
    let old = r#"{"type":"api_key","key":"old"}"#;
    std::fs::write(s.target("login-key"), old).unwrap();
    let src = s.source("vendor.env", &format!("VENDOR_KEY=sk-{MARK}\n"));
    let args = ["--from", "env", "--var", "VENDOR_KEY"];
    let (code, out) = s.import("login-key", &src, &args);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("exists; pass --force"), "{out}");
    assert_eq!(std::fs::read_to_string(s.target("login-key")).unwrap(), old);
    let (code, out) = s.import("login-key", &src, &[&args[..], &["--force"]].concat());
    assert_eq!(code, 0, "{out}");
    assert_eq!(s.written("login-key")["key"], format!("sk-{MARK}"));
}

/// One refused import: the login, the source, the arguments, the exit code and a part of the
/// output.
type Refusal<'a> = (&'a str, PathBuf, Vec<&'a str>, i32, &'a str);

/// Runs every refusal of `cases` and checks that none wrote a file or warned.
fn refused(s: &Setup, cases: Vec<Refusal<'_>>) {
    for (login, source, args, want_code, want) in cases {
        let (code, out) = s.import(login, &source, &args);
        assert_eq!(code, want_code, "{args:?}: {out}");
        assert!(out.contains(want), "{args:?}: {out}");
        assert!(!out.contains("warn"), "{args:?}: {out}");
    }
    let left: Vec<_> = std::fs::read_dir(s.dir.join("creds")).unwrap().collect();
    assert!(left.is_empty(), "a refused import wrote {left:?}");
}

#[test]
fn a_source_of_another_kind_an_unknown_login_or_a_missing_file_is_refused() {
    let s = Setup::new();
    let pool = s.source("auth.json", &hermes_pool());
    let claude = |name: &str, body: &Value| s.source(name, &body.to_string());
    refused(
        &s,
        vec![
            (
                "login-key",
                claude(
                    "claude-1.json",
                    &json!({"claudeAiOauth": {"accessToken": format!("at-{MARK}")}}),
                ),
                vec!["--from", "claude-code"],
                1,
                "holds a `oauth_anthropic` credential, login `login-key` has kind `api_key`",
            ),
            (
                "login-oauth",
                s.source("vendor.env", &format!("VENDOR_KEY=sk-{MARK}\n")),
                vec!["--from", "env", "--var", "VENDOR_KEY"],
                1,
                "holds a `api_key` credential, login `login-oauth` has kind `oauth_anthropic`",
            ),
            (
                "login-none",
                pool.clone(),
                vec!["--from", "claude-code"],
                1,
                "login `login-none` is not in the gateway config",
            ),
            (
                "login-oauth",
                s.dir.join("missing.json"),
                vec!["--from", "claude-code"],
                1,
                "missing.json: No such file or directory",
            ),
        ],
    );
}

#[test]
fn malformed_claude_code_and_codex_sources_are_refused_by_field() {
    let s = Setup::new();
    let claude = |name: &str, body: &Value| s.source(name, &body.to_string());
    refused(
        &s,
        vec![
            (
                "login-oauth",
                claude(
                    "claude-2.json",
                    &json!({"claudeAiOauth": {"accessToken": format!("at-{MARK}"), "expiresAt": MARK}}),
                ),
                vec!["--from", "claude-code"],
                1,
                "`claudeAiOauth.expiresAt` is missing or invalid",
            ),
            (
                "login-oauth",
                claude(
                    "claude-3.json",
                    &json!({"claudeAiOauth": {"refreshToken": format!("rt-{MARK}")}}),
                ),
                vec!["--from", "claude-code"],
                1,
                "no `claudeAiOauth.accessToken`",
            ),
            (
                "login-oauth",
                claude(
                    "claude-4.json",
                    &json!({"claudeAiOauth": {"accessToken": format!("at {MARK}\r\n")}}),
                ),
                vec!["--from", "claude-code"],
                1,
                "`claudeAiOauth.accessToken` is not a non-empty visible ASCII string",
            ),
            (
                "login-chatgpt",
                s.source(
                    "codex.json",
                    &json!({"tokens": {
                        "access_token": format!("at-{MARK}"),
                        "id_token": jwt(&json!({"sub": MARK})),
                    }})
                    .to_string(),
                ),
                vec!["--from", "codex"],
                1,
                "no `tokens.account_id` and no `chatgpt_account_id` claim in `tokens.id_token`",
            ),
            (
                "login-chatgpt",
                s.source(
                    "codex2.json",
                    &json!({"OPENAI_API_KEY": format!("sk-{MARK}")}).to_string(),
                ),
                vec!["--from", "codex"],
                1,
                "no `tokens`",
            ),
        ],
    );
}

#[test]
fn hermes_and_env_sources_without_a_usable_entry_are_refused() {
    let s = Setup::new();
    let pool = s.source("auth.json", &hermes_pool());
    refused(
        &s,
        vec![
            (
                "login-oauth",
                s.source(
                    "broken.json",
                    &format!(r#"{{"claudeAiOauth": {{"accessToken": "{MARK}"#),
                ),
                vec!["--from", "claude-code"],
                1,
                "not valid JSON",
            ),
            (
                "login-oauth",
                pool.clone(),
                vec!["--from", "hermes", "--provider", "anthropic"],
                1,
                "3 `credential_pool.anthropic` entries; name one with --entry",
            ),
            (
                "login-key",
                pool.clone(),
                vec![
                    "--from",
                    "hermes",
                    "--provider",
                    "anthropic",
                    "--entry",
                    "spare",
                ],
                1,
                "several `credential_pool.anthropic` entries have the label `spare`; name one by id",
            ),
            (
                "login-oauth",
                pool.clone(),
                vec![
                    "--from",
                    "hermes",
                    "--provider",
                    "anthropic",
                    "--entry",
                    "nope",
                ],
                1,
                "no `credential_pool.anthropic` entry has the id or label `nope`",
            ),
            (
                "login-chatgpt",
                s.source(
                    "auth2.json",
                    &json!({"credential_pool": {"openai-codex": [{
                        "id": "x", "access_token": format!("opaque-{MARK}"),
                        "expires_at": format!("soon-{MARK}")
                    }]}})
                    .to_string(),
                ),
                vec!["--from", "hermes", "--provider", "openai-codex"],
                1,
                "`credential_pool.openai-codex[0].expires_at` is not an ISO 8601 timestamp",
            ),
            (
                "login-chatgpt",
                s.source(
                    "auth3.json",
                    &json!({"credential_pool": {"openai-codex": [{
                        "id": "x", "access_token": format!("opaque-{MARK}")
                    }]}})
                    .to_string(),
                ),
                vec!["--from", "hermes", "--provider", "openai-codex"],
                1,
                "no `chatgpt_account_id` claim in `credential_pool.openai-codex[0].access_token`",
            ),
            (
                "login-chatgpt",
                s.source("auth4.json", &json!({"providers": {}}).to_string()),
                vec!["--from", "hermes", "--provider", "openai-codex"],
                1,
                "no `credential_pool`",
            ),
            (
                "login-key",
                s.source("other.env", &format!("OTHER=x-{MARK}\nVENDOR_KEY=\n")),
                vec!["--from", "env", "--var", "VENDOR_KEY"],
                1,
                "`VENDOR_KEY` is not a non-empty visible ASCII string",
            ),
            (
                "login-key",
                s.source("other2.env", &format!("OTHER=x-{MARK}\n")),
                vec!["--from", "env", "--var", "VENDOR_KEY"],
                1,
                "no variable `VENDOR_KEY`",
            ),
        ],
    );
}

#[test]
fn usage_errors_exit_2() {
    let s = Setup::new();
    let pool = s.source("auth.json", &hermes_pool());
    refused(
        &s,
        vec![
            (
                "login-oauth",
                pool.clone(),
                vec!["--from", "hermes", "--provider", "nous"],
                2,
                "--provider `nous`: expected `anthropic` or `openai-codex`",
            ),
            (
                "login-oauth",
                pool.clone(),
                vec!["--from", "hermes"],
                2,
                "--from hermes needs --provider",
            ),
            (
                "login-oauth",
                pool.clone(),
                vec!["--from", "keychain"],
                2,
                "--from `keychain`: expected",
            ),
            (
                "login-key",
                pool,
                vec!["--from", "env"],
                2,
                "--from env needs --var",
            ),
        ],
    );
}
