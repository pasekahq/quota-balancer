//! `qb login`: the binary up to the token request, and the exchange through `SignIn` against a
//! scripted loopback token endpoint, which the binary's sandbox (TCP port 443 only) would not
//! reach. Marker values must never reach any output.

#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use qb::gateway::config::load_login;
use qb::gateway::creds::CredentialStore;
use qb::gateway::oauth::OauthRefresher;
use qb::gateway::signin::SignIn;
use qb::gateway::upstream::Credential;
use serde_json::{Value, json};

use common::credentials::{jwt, written};
use common::pkce::{param, params, s256};
use common::temp_dir;
use common::vendor::{Answer, Vendor};

/// Part of every synthetic secret; it must appear in no output.
const MARK: &str = "mark-9d41";

const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const ANTHROPIC_REDIRECT: &str = "https://console.anthropic.com/oauth/code/callback";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_REDIRECT: &str = "http://localhost:1455/auth/callback";

/// A gateway config with an `oauth_anthropic`, a `chatgpt_oauth` and an `api_key` login; the
/// OAuth logins exchange codes at `token_url` when given.
struct Setup {
    dir: PathBuf,
    config: PathBuf,
}

impl Setup {
    fn new(token_url: Option<&str>) -> Self {
        let dir = temp_dir("login");
        std::fs::create_dir_all(dir.join("creds")).unwrap();
        let config = dir.join("gateway.toml");
        let d = dir.display();
        let token = token_url.map_or(String::new(), |u| format!("token_url = \"{u}\"\n"));
        std::fs::write(
            &config,
            format!(
                r#"socket = "{d}/gw.sock"

[[logins]]
name = "login-oauth"
kind = "oauth_anthropic"
credentials = "{d}/creds/login-oauth.json"
{token}
[[logins]]
name = "login-chatgpt"
kind = "chatgpt_oauth"
credentials = "{d}/creds/login-chatgpt.json"
{token}
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

    fn target(&self, login: &str) -> PathBuf {
        self.dir.join("creds").join(format!("{login}.json"))
    }

    /// Runs `qb login <login> --config <config> args...`, answering the authorize URL it prints
    /// with `paste(url)` on stdin; the exit code, the URL (`None` when none was printed) and
    /// stdout and stderr together, after checking that no marker is among them.
    fn run(
        &self,
        login: &str,
        args: &[&str],
        paste: impl FnOnce(&str) -> String,
    ) -> (i32, Option<String>, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_qb"))
            .args(["login", login, "--config"])
            .arg(&self.config)
            .args(args)
            .env_remove("JOURNAL_STREAM")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        stdout.read_line(&mut first).unwrap();
        let url = first
            .starts_with("https://")
            .then(|| first.trim().to_owned());
        if let Some(url) = &url {
            let line = paste(url);
            child
                .stdin
                .take()
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!("{first}{rest}{}", String::from_utf8_lossy(&out.stderr));
        assert!(!text.contains(MARK), "a value leaked: {text}");
        (out.status.code().unwrap(), url, text)
    }

    /// A sign-in of `login` through the library, with its authorize URL.
    fn start(&self, login: &str) -> (SignIn, String) {
        let signin = SignIn::start(load_login(&self.config, login).unwrap(), false).unwrap();
        let url = signin.url();
        (signin, url)
    }

    fn assert_nothing_written(&self) {
        let left: Vec<_> = std::fs::read_dir(self.dir.join("creds")).unwrap().collect();
        assert!(left.is_empty(), "a refused sign-in wrote {left:?}");
    }
}

/// The decoded fields of a form body.
fn form(body: &str) -> Vec<(String, String)> {
    params(&format!("?{body}"))
}

fn json_answer(status: u16, body: &Value) -> Answer {
    Answer::Full(
        status,
        vec![("content-type".into(), "application/json".into())],
        body.to_string().into_bytes(),
    )
}

fn chatgpt_redirect(code: &str, state: &str) -> String {
    format!("{CODEX_REDIRECT}?code={code}&scope=openid+profile+email+offline_access&state={state}")
}

#[test]
fn each_run_prints_a_fresh_s256_authorize_url_and_refuses_a_state_it_did_not_send() {
    let s = Setup::new(None);
    let mut states = Vec::new();
    for (login, authorize, fixed) in [
        (
            "login-oauth",
            "https://claude.ai/oauth/authorize",
            vec![
                ("code", "true"),
                ("client_id", ANTHROPIC_CLIENT_ID),
                ("response_type", "code"),
                ("redirect_uri", ANTHROPIC_REDIRECT),
                ("scope", "org:create_api_key user:profile user:inference"),
            ],
        ),
        (
            "login-chatgpt",
            "https://auth.openai.com/oauth/authorize",
            vec![
                ("response_type", "code"),
                ("client_id", CODEX_CLIENT_ID),
                ("redirect_uri", CODEX_REDIRECT),
                ("scope", "openid profile email offline_access"),
                ("id_token_add_organizations", "true"),
                ("codex_cli_simplified_flow", "true"),
                ("originator", "codex_cli_rs"),
            ],
        ),
    ] {
        for _ in 0..2 {
            let (code, url, out) = s.run(login, &[], |url| {
                let other = format!("not-{}", param(url, "state"));
                if login == "login-chatgpt" {
                    chatgpt_redirect(&format!("code-{MARK}"), &other)
                } else {
                    format!("code-{MARK}#{other}\n")
                }
            });
            assert_eq!(code, 1, "{out}");
            assert!(
                out.contains("the pasted state is not the one this sign-in sent"),
                "{out}"
            );
            let url = url.unwrap();
            assert!(url.starts_with(&format!("{authorize}?")), "{url}");
            let mut want: Vec<(String, String)> = fixed
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let (challenge, state) = (param(&url, "code_challenge"), param(&url, "state"));
            want.extend([
                ("code_challenge".to_owned(), challenge.clone()),
                ("code_challenge_method".to_owned(), "S256".to_owned()),
                ("state".to_owned(), state.clone()),
            ]);
            assert_eq!(params(&url), want);
            for v in [&challenge, &state] {
                assert_eq!(v.len(), 43, "{v}");
                assert!(
                    v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                );
            }
            assert!(!states.contains(&state), "a state came twice");
            states.push(state);
        }
    }
    s.assert_nothing_written();
}

#[test]
fn an_api_key_login_an_unknown_login_or_an_existing_file_is_refused_before_the_url() {
    let s = Setup::new(None);
    let old = r#"{"type":"oauth_anthropic","access_token":"old"}"#;
    for (login, want) in [
        (
            "login-key",
            "login `login-key` has kind `api_key`; `qb login` signs in `oauth_anthropic` and `chatgpt_oauth` logins",
        ),
        (
            "login-none",
            "login `login-none` is not in the gateway config",
        ),
    ] {
        let (code, url, out) = s.run(login, &[], |_| unreachable!());
        assert_eq!((code, url), (1, None), "{out}");
        assert!(out.contains(want), "{out}");
    }
    s.assert_nothing_written();
    std::fs::write(s.target("login-oauth"), old).unwrap();
    let (code, url, out) = s.run("login-oauth", &[], |_| unreachable!());
    assert_eq!((code, url), (1, None), "{out}");
    assert!(
        out.contains("login-oauth.json: exists; pass --force"),
        "{out}"
    );
    let (code, url, out) = s.run("login-oauth", &["--force"], |_| format!("code-{MARK}#x\n"));
    assert_eq!(code, 1, "{out}");
    assert!(url.is_some(), "--force goes on to the URL: {out}");
    assert!(out.contains("the pasted state is not the one"), "{out}");
    assert_eq!(
        std::fs::read_to_string(s.target("login-oauth")).unwrap(),
        old
    );
}

#[test]
fn an_unreachable_token_endpoint_fails_the_sign_in_without_a_file() {
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/oauth/token", l.local_addr().unwrap())
    };
    let s = Setup::new(Some(&closed));
    let (code, _, out) = s.run("login-chatgpt", &[], |url| {
        chatgpt_redirect(&format!("code-{MARK}"), &param(url, "state"))
    });
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("qb: login refused: the token exchange failed:"),
        "{out}"
    );
    assert!(out.contains("request failed"), "{out}");
    s.assert_nothing_written();
}

#[test]
fn an_empty_paste_or_an_import_flag_is_refused() {
    let s = Setup::new(None);
    let (code, url, out) = s.run("login-oauth", &[], |_| String::new());
    assert_eq!(code, 1, "{out}");
    assert!(url.is_some());
    assert!(out.contains("stdin: no line was pasted"), "{out}");
    let (code, url, out) = s.run("login-oauth", &["--from", "codex"], |_| unreachable!());
    assert_eq!((code, url), (2, None), "{out}");
    assert!(out.contains("go with `login import`"), "{out}");
    s.assert_nothing_written();
}

#[test]
fn an_anthropic_code_is_exchanged_as_json_with_the_verifier_and_written_with_its_refresh_token() {
    let tokens = Vendor::start();
    let s = Setup::new(Some(&format!("{}/v1/oauth/token", tokens.base_url)));
    tokens.answer(json_answer(
        200,
        &json!({
            "token_type": "Bearer", "access_token": format!("sk-ant-oat-{MARK}"),
            "refresh_token": format!("sk-ant-ort-{MARK}"), "expires_in": 28800,
            "scope": "user:inference", "account": {"email_address": MARK}
        }),
    ));
    let (signin, url) = s.start("login-oauth");
    let state = param(&url, "state");
    let before = qb::server::unix_now();
    let done = signin
        .finish(&format!("  code-{MARK}#{state}\r\n"))
        .unwrap();
    let after = qb::server::unix_now();
    let line = done.to_string();
    assert_eq!(
        line,
        format!(
            "{}: wrote the `oauth_anthropic` credential of login `login-oauth`",
            s.target("login-oauth").display()
        )
    );
    let written = written(&s.target("login-oauth"));
    assert_eq!(written["type"], "oauth_anthropic");
    assert_eq!(written["access_token"], format!("sk-ant-oat-{MARK}"));
    assert_eq!(written["refresh_token"], format!("sk-ant-ort-{MARK}"));
    let expires_at = written["expires_at"].as_u64().unwrap();
    assert!((before + 28800..=after + 28800).contains(&expires_at));
    assert_eq!(written.as_object().unwrap().len(), 4, "{written}");
    let received = tokens.received();
    let req = &received[0];
    assert_eq!(req.path, "/v1/oauth/token");
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert_eq!(req.header("user-agent"), Some("axios/1.7.9"));
    let verifier = req.body["code_verifier"].as_str().unwrap().to_owned();
    assert_eq!(
        req.body,
        json!({
            "grant_type": "authorization_code", "code": format!("code-{MARK}"), "state": state,
            "client_id": ANTHROPIC_CLIENT_ID, "redirect_uri": ANTHROPIC_REDIRECT,
            "code_verifier": verifier,
        })
    );
    assert_eq!(verifier.len(), 43);
    assert_eq!(s256(&verifier), param(&url, "code_challenge"));
    assert!(
        !url.contains(&verifier),
        "the URL carries only the challenge"
    );
}

#[test]
fn a_chatgpt_redirect_is_exchanged_as_a_form_and_takes_the_account_from_the_id_token() {
    let tokens = Vendor::start();
    let s = Setup::new(Some(&format!("{}/oauth/token", tokens.base_url)));
    let id_token = jwt(
        &json!({
            "exp": 1_900_000_100_u64, "email": MARK,
            "https://api.openai.com/auth": {"chatgpt_account_id": format!("acct-{MARK}")}
        }),
        MARK,
    );
    let access = jwt(&json!({"exp": 1_900_000_200_u64}), MARK);
    tokens.answer(json_answer(
        200,
        &json!({
            "id_token": id_token, "access_token": access,
            "refresh_token": format!("rt-{MARK}")
        }),
    ));
    let (signin, url) = s.start("login-chatgpt");
    let state = param(&url, "state");
    let pasted = format!(
        "{CODEX_REDIRECT}?code=ac_{MARK}%2Dx&scope=openid+profile&state={state}#frag-{MARK}\n"
    );
    let done = signin.finish(&pasted).unwrap();
    assert_eq!(
        done.to_string(),
        format!(
            "{}: wrote the `chatgpt_oauth` credential of login `login-chatgpt`",
            s.target("login-chatgpt").display()
        )
    );
    assert_eq!(
        written(&s.target("login-chatgpt")),
        json!({
            "type": "chatgpt_oauth", "access_token": access, "refresh_token": format!("rt-{MARK}"),
            "account_id": format!("acct-{MARK}"), "expires_at": 1_900_000_100_u64,
        })
    );
    let received = tokens.received();
    let req = &received[0];
    assert_eq!(req.path, "/oauth/token");
    let fields = form(req.body.as_str().unwrap());
    let verifier = fields
        .iter()
        .find(|(k, _)| k == "code_verifier")
        .unwrap()
        .1
        .clone();
    let want: Vec<(String, String)> = [
        ("grant_type", "authorization_code"),
        ("code", &format!("ac_{MARK}-x")),
        ("redirect_uri", CODEX_REDIRECT),
        ("client_id", CODEX_CLIENT_ID),
        ("code_verifier", &verifier),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    assert_eq!(fields, want);
    assert_eq!(s256(&verifier), param(&url, "code_challenge"));
}

/// One sign-in against a token endpoint: the login, its answer (`None` when the paste is
/// refused before any request), the paste of a state, and a part of the error.
type Case = (
    &'static str,
    Option<Answer>,
    fn(&str) -> String,
    &'static str,
);

/// Runs every sign-in of `cases` and checks that each error names its part and no value, that
/// only a case with an answer asked the endpoint, and that none wrote a file.
fn refused(cases: Vec<Case>) {
    for (login, answer, paste, want) in cases {
        let tokens = Vendor::start();
        let s = Setup::new(Some(&format!("{}/token", tokens.base_url)));
        let asked = answer.is_some();
        if let Some(answer) = answer {
            tokens.answer(answer);
        }
        let (signin, url) = s.start(login);
        let e = signin.finish(&paste(&param(&url, "state"))).unwrap_err();
        assert!(e.contains(want), "{want}: {e}");
        assert!(!e.contains(MARK), "a value leaked: {e}");
        assert_eq!(tokens.received().len(), usize::from(asked), "{want}");
        s.assert_nothing_written();
    }
}

#[test]
fn refused_and_failed_exchanges_write_nothing_and_name_no_value() {
    let echo = json!({"error": "invalid_grant", "error_description": format!("bad {MARK}")});
    let cases: Vec<Case> = vec![
        (
            "login-oauth",
            Some(json_answer(400, &echo)),
            |state| format!("code-{MARK}#{state}"),
            "the token endpoint refused the code: http://",
        ),
        (
            "login-chatgpt",
            Some(json_answer(
                403,
                &json!({"error": {"code": "token_expired", "message": MARK}}),
            )),
            |state| chatgpt_redirect(&format!("code-{MARK}"), state),
            "/token: HTTP 403 token_expired",
        ),
        (
            "login-oauth",
            Some(json_answer(503, &echo)),
            |state| format!("code-{MARK}#{state}"),
            "the token exchange failed: http://",
        ),
        (
            "login-oauth",
            Some(Answer::Full(
                200,
                Vec::new(),
                format!(r#"{{"access_token":"{MARK}""#).into_bytes(),
            )),
            |state| format!("code-{MARK}#{state}"),
            "malformed answer (line 1, column",
        ),
        (
            "login-oauth",
            Some(json_answer(
                200,
                &json!({"access_token": format!("at-{MARK}"), "expires_in": 60}),
            )),
            |state| format!("code-{MARK}#{state}"),
            "the token answer has no `refresh_token`",
        ),
        (
            "login-oauth",
            Some(json_answer(
                200,
                &json!({"access_token": format!("at-{MARK}"), "refresh_token": format!("rt-{MARK}")}),
            )),
            |state| format!("code-{MARK}#{state}"),
            "answer has no `expires_in`",
        ),
        (
            "login-chatgpt",
            Some(json_answer(
                200,
                &json!({
                    "access_token": format!("at-{MARK}"), "refresh_token": format!("rt-{MARK}"),
                    "expires_in": 3600, "id_token": jwt(&json!({"email": MARK}), MARK),
                }),
            )),
            |state| chatgpt_redirect(&format!("code-{MARK}"), state),
            "the token answer has no `id_token` with a `chatgpt_account_id` claim",
        ),
    ];
    refused(cases);
}

#[test]
fn a_paste_with_another_state_or_without_a_code_is_refused_before_any_request() {
    let cases: Vec<Case> = vec![
        (
            "login-oauth",
            None,
            |state| format!("code-{MARK}#{state}-{MARK}"),
            "the pasted state is not the one this sign-in sent",
        ),
        (
            "login-oauth",
            None,
            |_| format!("code-{MARK}"),
            "the pasted line is not `code#state`",
        ),
        (
            "login-chatgpt",
            None,
            |state| format!("{CODEX_REDIRECT}?error=access_denied&state={state}"),
            "the vendor refused the sign-in: `access_denied`",
        ),
        (
            "login-chatgpt",
            None,
            |state| format!("{CODEX_REDIRECT}?state={state}"),
            "the pasted URL has no `code`",
        ),
        (
            "login-chatgpt",
            None,
            |_| chatgpt_redirect(&format!("code-{MARK}"), &format!("s-{MARK}")),
            "the pasted state is not the one this sign-in sent",
        ),
    ];
    refused(cases);
}

#[test]
fn the_gateway_serves_the_credential_a_sign_in_wrote() {
    let tokens = Vendor::start();
    let s = Setup::new(Some(&format!("{}/token", tokens.base_url)));
    let id_token = jwt(
        &json!({"https://api.openai.com/auth": {"chatgpt_account_id": "acct-1"}}),
        MARK,
    );
    tokens.answer(json_answer(
        200,
        &json!({"access_token": "at-1", "refresh_token": "rt-1", "id_token": id_token, "expires_in": 3600}),
    ));
    let (signin, url) = s.start("login-chatgpt");
    signin
        .finish(&chatgpt_redirect("code-1", &param(&url, "state")))
        .unwrap();
    let store = CredentialStore::new(Box::new(OauthRefresher::new()));
    let login = load_login(&s.config, "login-chatgpt").unwrap();
    let loaded = store.load(&login, qb::server::unix_now(), false).unwrap();
    let Credential::ChatgptOauth {
        access_token,
        account_id,
    } = loaded
    else {
        panic!("not a ChatGPT credential");
    };
    assert_eq!(
        (access_token.as_str(), account_id.as_str()),
        ("at-1", "acct-1")
    );
}
