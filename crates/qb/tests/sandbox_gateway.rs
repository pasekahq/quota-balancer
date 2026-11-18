//! `qb gateway` hardening in a thread of its own; the dumpable flag it clears is process-wide, so
//! this file holds one test.

#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use landlock::{ABI, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr};
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

#[test]
fn gateway_may_rewrite_credentials_and_its_spend_file_read_its_config_and_reach_qbd_only() {
    let dir = Path::new("/tmp").join(format!("qb-gw-sandbox-{}", std::process::id()));
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    let credential = creds.join("login-1.json");
    std::fs::write(&credential, r#"{"type":"api_key","key":"test-token-1"}"#).unwrap();
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let spend_file = state.join("spend.json");
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
        "socket = \"{}\"\nqbd_socket = \"{}\"\nspend_file = \"{}\"\n\
             [[logins]]\nname = \"login-1\"\nkind = \"api_key\"\napi = \"anthropic\"\ncredentials = \"{}\"\n\
             [[routes]]\nalias = \"chat\"\nrole = \"gateway\"\ndifficulty = 1\n\
             [fronts]\nlisten = \"127.0.0.1:{port}\"\ntoken_sha256 = \"{}\"\n\
             [fronts.messages]\nvendor = \"vendor-a\"\n",
        dir.join("gw.sock").display(),
        qbd.display(),
        spend_file.display(),
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
    let (hardened, edit) = std::sync::mpsc::channel();
    let (edited, reload) = std::sync::mpsc::channel();
    let reread = file.clone();
    let gateway = std::thread::spawn(move || {
        let gaps = qb::sandbox::harden_gateway(&config).unwrap();
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
        assert!(UnixStream::connect(&qbd).is_ok(), "qbd stays reachable");
        let (accepted, _) = tcp.accept().unwrap();
        assert_eq!(
            accepted.peer_addr().unwrap(),
            client.local_addr().unwrap(),
            "the listener made before the sandbox still serves"
        );
        if abi >= Some(ABI::V4) {
            eprintln!("landlock {abi:?}: enforcing branch");
            assert_eq!(gaps, Vec::<String>::new());
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
    let _ = std::fs::remove_dir_all(&dir);
}
