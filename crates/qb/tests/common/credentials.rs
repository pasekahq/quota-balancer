//! Synthetic JWTs and the credential files `qb login` and `qb login import` write.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::Value;

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

/// An unsigned JWT with `claims`; the marker `mark` sits in its signature.
pub fn jwt(claims: &Value, mark: &str) -> String {
    format!(
        "{}.{}.sig-{mark}",
        b64url(br#"{"alg":"none"}"#),
        b64url(claims.to_string().as_bytes())
    )
}

/// The credential file `file` as JSON, after checking it is 0600.
pub fn written(file: &Path) -> Value {
    let mode = std::fs::metadata(file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
}
