//! Credential fingerprints on reports: a changed credential clears an auth mark, and an explicit
//! reset clears it too; both survive a restore.

mod common;

use common::{NOW, cand, core, login_view, on, pick, ran, role, spec, step};
use qb_core::{Auth, Core, LoginStatus, OutcomeClass, Record, ReportInput, Verdict};

/// Role `worker`: `vendor-a/a` (tier 1, logins 1 and 2), then `vendor-b/b` (tier 2, login 3).
fn worker() -> Core {
    core(spec(vec![role(
        "worker",
        vec![step(
            1,
            vec![cand("vendor-a", "a", 1), cand("vendor-b", "b", 2)],
        )],
        vec![],
    )]))
}

/// Reports `outcome` on `login` with the credential fingerprint `fp`.
fn report(c: &mut Core, login: &str, outcome: OutcomeClass, fp: Option<&str>) -> LoginStatus {
    let input = ReportInput {
        subject: on(login),
        outcome,
        model: None,
        release: false,
        credential: fp.map(Into::into),
        windows: Vec::new(),
    };
    c.report(&input, NOW).expect("known login")
}

fn credential(c: &Core, login: &str) -> Option<String> {
    c.marks(login).and_then(|m| m.credential)
}

const A: &str = "aaaaaaaa";
const B: &str = "bbbbbbbb";
const C: &str = "cccccccc";

#[test]
fn a_changed_credential_clears_the_auth_mark_and_the_same_one_keeps_it() {
    use OutcomeClass::{Error, Http401};
    type Step = (OutcomeClass, Option<&'static str>);
    let cases: &[(&str, &[Step], LoginStatus, Option<&str>)] = &[
        (
            "two 401s of one credential: auth_dead holding it",
            &[(Http401, Some(A)), (Http401, Some(A))],
            LoginStatus::AuthDead,
            Some(A),
        ),
        (
            "another credential clears auth_dead",
            &[(Http401, Some(A)), (Http401, Some(A)), (Error, Some(B))],
            LoginStatus::Unknown,
            None,
        ),
        (
            "the same credential keeps auth_dead",
            &[(Http401, Some(A)), (Http401, Some(A)), (Error, Some(A))],
            LoginStatus::AuthDead,
            Some(A),
        ),
        (
            "a report without one keeps auth_dead",
            &[(Http401, Some(A)), (Http401, Some(A)), (Error, None)],
            LoginStatus::AuthDead,
            Some(A),
        ),
        (
            "another credential clears auth_stale",
            &[(Http401, Some(A)), (Error, Some(B))],
            LoginStatus::Unknown,
            None,
        ),
        (
            "a 401 of another credential is its first: auth_stale",
            &[(Http401, Some(A)), (Http401, Some(A)), (Http401, Some(B))],
            LoginStatus::AuthStale,
            Some(B),
        ),
        (
            "a mark without a credential takes the first one reported",
            &[(Http401, None), (Http401, None), (Error, Some(B))],
            LoginStatus::AuthDead,
            Some(B),
        ),
        (
            "and a later change clears it",
            &[
                (Http401, None),
                (Http401, None),
                (Error, Some(B)),
                (Error, Some(C)),
            ],
            LoginStatus::Unknown,
            None,
        ),
        (
            "a login without an auth mark keeps no credential",
            &[(Error, Some(A))],
            LoginStatus::Unknown,
            None,
        ),
    ];
    for (name, steps, want, fp) in cases {
        let mut c = worker();
        let mut got = LoginStatus::Unknown;
        for &(outcome, credential) in *steps {
            got = report(&mut c, "login-1", outcome, credential);
        }
        assert_eq!(got, *want, "{name}");
        assert_eq!(login_view(&c, "login-1", NOW).status, *want, "{name}");
        assert_eq!(credential(&c, "login-1").as_deref(), *fp, "{name}");
    }
}

#[test]
fn a_renewed_credential_makes_a_dead_login_pickable_again() {
    let mut c = worker();
    for login in ["login-1", "login-2"] {
        report(&mut c, login, OutcomeClass::Http401, Some(A));
        report(&mut c, login, OutcomeClass::Http401, Some(A));
    }
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, "login-3");
    report(&mut c, "login-2", OutcomeClass::Error, Some(B));
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, "login-2");
}

#[test]
fn a_reset_clears_auth_marks_only() {
    let mut c = worker();
    report(&mut c, "login-1", OutcomeClass::Http401, Some(A));
    report(&mut c, "login-1", OutcomeClass::Http401, Some(A));
    report(&mut c, "login-1", OutcomeClass::UsageLimit, None);
    assert_eq!(
        c.reset_auth("login-1", NOW),
        Some((true, LoginStatus::Exhausted))
    );
    let marks = c.marks("login-1").expect("declared");
    assert_eq!((marks.auth, marks.credential), (Auth::Ok, None));
    assert!(marks.exhausted_until.is_some(), "other marks stay");
    assert_eq!(
        c.reset_auth("login-2", NOW),
        Some((false, LoginStatus::Unknown))
    );
    assert_eq!(c.reset_auth("login-9", NOW), None);
    assert_eq!(
        c.login_names().collect::<Vec<_>>(),
        ["login-1", "login-2", "login-3"]
    );
}

#[test]
fn a_quota_reset_clears_a_stuck_exhausted_mark_and_keeps_the_auth_mark() {
    let mut c = worker();
    report(&mut c, "login-1", OutcomeClass::Http401, Some(A));
    report(&mut c, "login-1", OutcomeClass::UsageLimit, None);
    report(&mut c, "login-2", OutcomeClass::UsageLimit, None);
    report(&mut c, "login-3", OutcomeClass::Http429, None);
    assert!(!matches!(pick(&mut c, "worker", 1, None), Verdict::Run(..)));
    assert_eq!(
        c.reset_quota("login-2", NOW),
        Some((true, LoginStatus::Unknown))
    );
    let marks = c.marks("login-2").expect("declared");
    assert_eq!(marks, qb_core::Marks::default(), "nothing left to journal");
    assert_eq!(ran(&pick(&mut c, "worker", 1, None)).0, "login-2");
    assert_eq!(
        c.reset_quota("login-1", NOW),
        Some((true, LoginStatus::AuthStale)),
        "the auth mark stays"
    );
    assert_eq!(
        c.reset_quota("login-1", NOW),
        Some((false, LoginStatus::AuthStale))
    );
    assert_eq!(c.reset_quota("login-9", NOW), None);
}

#[test]
fn the_credential_of_a_mark_survives_a_restore() {
    let mut c = worker();
    report(&mut c, "login-1", OutcomeClass::Http401, Some(A));
    report(&mut c, "login-1", OutcomeClass::Http401, Some(A));
    let mut again = worker();
    for r in c.records() {
        again.restore(&r, NOW).expect("same config");
    }
    assert!(again.records().iter().any(
        |r| matches!(r, Record::Marks { marks, .. } if marks.credential.as_deref() == Some(A))
    ));
    assert_eq!(
        report(&mut again, "login-1", OutcomeClass::Error, Some(A)),
        LoginStatus::AuthDead
    );
    assert_eq!(
        report(&mut again, "login-1", OutcomeClass::Error, Some(B)),
        LoginStatus::Unknown
    );
}
