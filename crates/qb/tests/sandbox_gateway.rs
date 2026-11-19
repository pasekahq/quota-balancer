//! `qb gateway` hardening in a thread of its own; the dumpable flag it clears is process-wide, so
//! this file holds one test.

#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use landlock::{ABI, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr};
use qb_proto::{AuditAction, AuditEntry, AuditResult};
use rustix::process::{DumpableBehavior, dumpable_behavior};

fn kernel_abi() -> Option<ABI> {
    std::thread::spawn(|| {
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap();
        match status.landlock {
            LandlockStatus::Available { effective_abi, .. } => Some(effective_abi),
            _ => None,
        }
    })
    .join()
    .unwrap()
}

/// The enforced ruleset: no gaps; its startup line names the credential, spend, audit and config
/// directories and the two resolver files, TCP connect to 443 and bind on `port`; `opened` are
/// the credential, spend and audit directories.
fn assert_applied(applied: &qb::sandbox::Confined, port: u16, opened: &[PathBuf]) {
    assert_eq!(applied.gaps, Vec::<String>::new());
    let want = format!(
        "non-dumpable; landlock V4: files beneath 6 paths only, TCP connect 443, bind {port} only"
    );
    assert_eq!(applied.summary, want);
    assert_eq!(applied.opened, opened);
}

/// An audit entry of a SIGHUP reload at `at`.
fn signal_reload(at: u64) -> AuditEntry {
    AuditEntry {
        at,
        actor: "signal".into(),
        action: AuditAction::Reload,
        object: None,
        result: AuditResult::Ok,
        reason: None,
        config_sha256_before: None,
        config_sha256_after: None,
        backup: None,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // the dumpable flag is process-wide, so one test covers it all
fn gateway_may_write_its_credentials_spend_and_audit_read_its_config_and_reach_qbd_only() {
    let dir = Path::new("/tmp").join(format!("qb-gw-sandbox-{}", std::process::id()));
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    let credential = creds.join("login-1.json");
    std::fs::write(&credential, r#"{"type":"api_key","key":"test-token-1"}"#).unwrap();
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let spend_file = state.join("spend.json");
    let audit = dir.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let audit_file = audit.join("audit.jsonl");
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    let qbd = dir.join("qb.sock");
    let _qbd = UnixListener::bind(&qbd).unwrap();
    // The HTTP fronts' listener, bound before the sandbox; a client waits in its backlog.
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let etc = dir.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    let file = etc.join("gateway.toml");
    let text = format!(
        "socket = \"{}\"\nqbd_socket = \"{}\"\nspend_file = \"{}\"\naudit_file = \"{}\"\n\
             [[logins]]\nname = \"login-1\"\nkind = \"api_key\"\napi = \"anthropic\"\ncredentials = \"{}\"\n\
             [[routes]]\nalias = \"chat\"\nrole = \"gateway\"\ndifficulty = 1\n\
             [fronts]\nlisten = \"127.0.0.1:{port}\"\ntoken_sha256 = \"{}\"\n\
             [fronts.messages]\nvendor = \"vendor-a\"\n",
        dir.join("gw.sock").display(),
        qbd.display(),
        spend_file.display(),
        audit_file.display(),
        credential.display(),
        "0".repeat(64)
    );
    std::fs::write(&file, &text).unwrap();
    let config = qb::gateway::config::load(&file).unwrap();
    let abi = kernel_abi();
    if std::env::var_os("QB_REQUIRE_LANDLOCK").is_some() {
        assert!(abi >= Some(ABI::V4), "landlock ABI {abi:?} < V4");
    }
    let (written, unreadable) = (credential.clone(), outside.clone());
    let counted = spend_file.clone();
    let audited = audit_file.clone();
    let (hardened, edit) = std::sync::mpsc::channel();
    let (edited, reload) = std::sync::mpsc::channel();
    let reread = file.clone();
    let gateway = std::thread::spawn(move || {
        let applied = qb::sandbox::harden_gateway(&config).unwrap();
        hardened.send(()).unwrap();
        reload.recv().unwrap();
        assert_eq!(
            qb::gateway::config::load(&reread).unwrap(),
            config,
            "a reload reads the replaced file"
        );
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        qb::gateway::creds::write_atomic(&written, br#"{"type":"api_key","key":"k2"}"#).unwrap();
        let now = qb::server::unix_now();
        let mut ledger = qb::gateway::spend::Ledger::open(&counted, now).unwrap();
        ledger.add("login-1", 1.5, now).unwrap();
        qb::gateway::audit::append(&audited, &signal_reload(now));
        assert!(UnixStream::connect(&qbd).is_ok(), "qbd stays reachable");
        let (accepted, _) = tcp.accept().unwrap();
        assert_eq!(
            accepted.peer_addr().unwrap(),
            client.local_addr().unwrap(),
            "the listener made before the sandbox still serves"
        );
        if abi >= Some(ABI::V4) {
            eprintln!("landlock {abi:?}: enforcing branch");
            assert_applied(&applied, port, &[creds, state, audit]);
            let denied = std::fs::read(&unreadable).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let denied = std::fs::write(unreadable.with_extension("new"), "x").unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let moved = written
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("moved.json");
            let denied = std::fs::rename(&written, moved).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied, "no REFER");
            let denied = TcpStream::connect(("127.0.0.1", port)).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let denied = TcpListener::bind("127.0.0.1:0").unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied, "no other bind");
        } else {
            eprintln!("landlock {abi:?}: warning branch");
            let gaps = &applied.gaps;
            assert!(gaps.iter().any(|g| g.contains("landlock")), "{gaps:?}");
        }
    });
    // An editor replaces the config by rename while the sandboxed gateway runs.
    if edit.recv().is_ok() {
        let replaced = file.with_extension("new");
        std::fs::write(&replaced, &text).unwrap();
        std::fs::rename(&replaced, &file).unwrap();
        let _ = edited.send(());
    }
    gateway.join().unwrap();
    assert_eq!(
        std::fs::read_to_string(&credential).unwrap(),
        r#"{"type":"api_key","key":"k2"}"#
    );
    assert!(spend_file.exists(), "written in the sandbox");
    let appended = std::fs::read_to_string(&audit_file).unwrap();
    assert!(appended.contains(r#""action":"reload""#), "{appended}");
    let _ = std::fs::remove_dir_all(&dir);
}
