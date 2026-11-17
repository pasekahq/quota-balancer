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
fn gateway_may_rewrite_credentials_read_media_and_reach_qbd_only() {
    let dir = Path::new("/tmp").join(format!("qb-gw-sandbox-{}", std::process::id()));
    let (creds, media) = (dir.join("creds"), dir.join("media"));
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(&media).unwrap();
    let credential = creds.join("login-1.json");
    std::fs::write(&credential, r#"{"type":"api_key","key":"test-token-1"}"#).unwrap();
    let image = media.join("photo-1.png");
    std::fs::write(&image, "png").unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    let qbd = dir.join("qb.sock");
    let _qbd = UnixListener::bind(&qbd).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let config = qb::gateway::config::parse(
        Path::new("gateway.toml"),
        &format!(
            "socket = \"{}\"\nmedia_dirs = [\"{}\"]\nqbd_socket = \"{}\"\n\
             [[logins]]\nname = \"login-1\"\ncredentials = \"{}\"\n\
             [[routes]]\nalias = \"chat\"\nrole = \"gateway\"\ndifficulty = 1\n",
            dir.join("gw.sock").display(),
            media.display(),
            qbd.display(),
            credential.display()
        ),
    )
    .unwrap();
    let abi = kernel_abi();
    if std::env::var_os("QB_REQUIRE_LANDLOCK").is_some() {
        assert!(abi >= Some(ABI::V4), "landlock ABI {abi:?} < V4");
    }
    let (written, readable, unreadable) = (credential.clone(), image.clone(), outside.clone());
    std::thread::spawn(move || {
        let gaps = qb::sandbox::harden_gateway(&config).unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        qb::gateway::creds::write_atomic(&written, br#"{"type":"api_key","key":"k2"}"#).unwrap();
        assert!(std::fs::read(&readable).is_ok());
        assert!(UnixStream::connect(&qbd).is_ok(), "qbd stays reachable");
        if abi >= Some(ABI::V4) {
            eprintln!("landlock {abi:?}: enforcing branch");
            assert_eq!(gaps, Vec::<String>::new());
            let denied = std::fs::read(&unreadable).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
            let denied = std::fs::write(readable.with_extension("new"), "x").unwrap_err();
            assert_eq!(
                denied.kind(),
                ErrorKind::PermissionDenied,
                "media is read-only"
            );
            let denied = TcpStream::connect(("127.0.0.1", port)).unwrap_err();
            assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
        } else {
            eprintln!("landlock {abi:?}: warning branch");
            assert!(gaps.iter().any(|g| g.contains("landlock")), "{gaps:?}");
        }
    })
    .join()
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&credential).unwrap(),
        r#"{"type":"api_key","key":"k2"}"#
    );
    let _ = std::fs::remove_dir_all(&dir);
}
