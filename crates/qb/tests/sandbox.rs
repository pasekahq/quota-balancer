//! `qb agent` hardening in a thread of its own; the dumpable flag it clears is process-wide, so
//! this file holds one test.

#![allow(clippy::unwrap_used)]

#[path = "common/cleanup.rs"]
mod cleanup;

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use landlock::{ABI, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr};
use rustix::process::{DumpableBehavior, dumpable_behavior};

/// The kernel's landlock ABI, `None` without landlock, read in a throwaway restricted thread.
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
fn hardening_allows_only_credentials_and_tcp_443() {
    let dir = std::env::temp_dir().join(format!("qb-sandbox-{}", std::process::id()));
    cleanup::remove_at_test_end(&dir);
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    let allowed = creds.join(".credentials.json");
    std::fs::write(&allowed, r#"{"claudeAiOauth":{"accessToken":"synthetic"}}"#).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_ne!(port, 443);
    let config = qb::config::parse_agent(
        Path::new("agent.toml"),
        &format!(
            "[[logins]]\nname = \"login-1\"\nkind = \"claude\"\ncredentials = \"{}\"\n",
            allowed.display()
        ),
    )
    .unwrap();
    let abi = kernel_abi();
    // CI sets this so a green run proves the enforcing branch ran.
    if std::env::var_os("QB_REQUIRE_LANDLOCK").is_some() {
        assert!(abi >= Some(ABI::V4), "landlock ABI {abi:?} < V4");
    }

    let (readable, unreadable) = (allowed.clone(), outside.clone());
    std::thread::spawn(move || {
        let gaps = qb::sandbox::harden(&config).unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        if abi >= Some(ABI::V4) {
            eprintln!("landlock {abi:?}: enforcing branch");
            assert_eq!(gaps, Vec::<String>::new());
            assert!(std::fs::read(&readable).is_ok());
            let denied = std::fs::read(&unreadable).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let denied = TcpStream::connect(("127.0.0.1", port)).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
        } else {
            eprintln!("landlock {abi:?}: warning branch");
            assert!(gaps.iter().any(|g| g.contains("landlock")), "{gaps:?}");
        }
    })
    .join()
    .unwrap();
    // The main thread is not restricted.
    assert!(std::fs::read(&outside).is_ok());
}
