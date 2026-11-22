//! Embeds the git revision the binary is built from as `QB_REVISION`, so that `qb --version`
//! tells builds of the same version apart.
//!
//! Order: `QB_BUILD_REVISION` from the environment (for builds without a git checkout, such as a
//! source tarball), else `git rev-parse --short=12 HEAD` of the checkout this crate sits in, else
//! `unknown`. Uncommitted changes are not marked: the build script reruns when HEAD moves, not on
//! every edit. No dependencies.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_owned())
}

/// The revision of the checkout `manifest_dir` belongs to, or `None` when it is not this
/// repository's checkout (no git, no repository, or an unrelated repository around a tarball).
fn revision(manifest_dir: &Path) -> Option<String> {
    let top = git(manifest_dir, &["rev-parse", "--show-toplevel"])?;
    let ours = Path::new(&top).join("crates/qb/Cargo.toml");
    let here = manifest_dir.join("Cargo.toml");
    if ours.canonicalize().ok()? != here.canonicalize().ok()? {
        return None;
    }
    let mut watch = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    watch.extend(git(manifest_dir, &["symbolic-ref", "-q", "HEAD"]));
    for path in &watch {
        // Relative to `manifest_dir`, which `git -C` made the working directory.
        // A missing file would rerun the script on every build.
        if let Some(p) = git(manifest_dir, &["rev-parse", "--git-path", path])
            .map(|p| manifest_dir.join(p))
            .filter(|p| p.exists())
        {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
    git(manifest_dir, &["rev-parse", "--short=12", "HEAD"])
}

fn main() {
    println!("cargo:rerun-if-env-changed=QB_BUILD_REVISION");
    let from_env = std::env::var("QB_BUILD_REVISION")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let rev = from_env.or_else(|| {
        let dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
        revision(Path::new(&dir))
    });
    println!(
        "cargo:rustc-env=QB_REVISION={}",
        rev.as_deref().unwrap_or("unknown")
    );
}
