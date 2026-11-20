//! `qb login import` hardening in a thread of its own; the dumpable flag it clears is
//! process-wide, so this file holds one test.

#![allow(clippy::unwrap_used)]

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
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
fn import_may_read_its_config_and_source_write_the_target_directory_and_nothing_else() {
    let dir = Path::new("/tmp").join(format!("qb-import-sandbox-{}", std::process::id()));
    let (etc, src, creds) = (dir.join("etc"), dir.join("src"), dir.join("creds"));
    for d in [&etc, &src, &creds] {
        std::fs::create_dir_all(d).unwrap();
    }
    let config = etc.join("gateway.toml");
    std::fs::write(&config, "socket = \"/run/qb/gw.sock\"\n").unwrap();
    let source = src.join("vendor.env");
    std::fs::write(&source, "VENDOR_KEY=test-token-1\n").unwrap();
    let target = creds.join("login-1.json");
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let abi = kernel_abi();
    if std::env::var_os("QB_REQUIRE_LANDLOCK").is_some() {
        assert!(abi >= Some(ABI::V4), "landlock ABI {abi:?} < V4");
    }
    let written = target.clone();
    std::thread::spawn(move || {
        let gaps = qb::sandbox::harden_import(&config, &source, &target).unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        assert!(std::fs::read(&config).is_ok(), "the config stays readable");
        assert!(std::fs::read(&source).is_ok(), "the source stays readable");
        qb::rewrite::write_atomic(&target, br#"{"type":"api_key","key":"k"}"#).unwrap();
        if abi >= Some(ABI::V4) {
            eprintln!("landlock {abi:?}: enforcing branch");
            assert_eq!(gaps, Vec::<String>::new());
            let denied = std::fs::read(&outside).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let denied = std::fs::write(source.with_extension("new"), "x").unwrap_err();
            assert_eq!(
                denied.kind(),
                ErrorKind::PermissionDenied,
                "the source is read-only"
            );
            let denied = std::fs::read("/etc/hosts").unwrap_err();
            assert_eq!(
                denied.kind(),
                ErrorKind::PermissionDenied,
                "no resolver files"
            );
            let denied = TcpStream::connect(("127.0.0.1", port)).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied, "no TCP");
        } else {
            eprintln!("landlock {abi:?}: warning branch");
            assert!(gaps.iter().any(|g| g.contains("landlock")), "{gaps:?}");
        }
    })
    .join()
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&written).unwrap(),
        r#"{"type":"api_key","key":"k"}"#
    );
    let _ = std::fs::remove_dir_all(&dir);
}
