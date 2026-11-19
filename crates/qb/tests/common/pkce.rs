//! The query of an authorize URL and the S256 challenge of a PKCE verifier, computed outside the
//! gateway.

use std::process::Command;

/// The decoded query parameters of `url`, in order.
pub fn params(url: &str) -> Vec<(String, String)> {
    let (_, query) = url.split_once('?').unwrap();
    query
        .split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap();
            (k.to_owned(), unescape(v))
        })
        .collect()
}

pub fn param(url: &str, key: &str) -> String {
    let found = params(url).into_iter().find(|(k, _)| k == key);
    found.unwrap_or_else(|| panic!("no `{key}` in {url}")).1
}

fn unescape(v: &str) -> String {
    let mut out = Vec::new();
    let mut bytes = v.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next().unwrap(), bytes.next().unwrap()];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).unwrap(), 16).unwrap());
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).unwrap()
}

/// The S256 challenge of `verifier`: base64url of its SHA-256, unpadded.
pub fn s256(verifier: &str) -> String {
    let out = Command::new("python3")
        .args([
            "-c",
            "import base64,hashlib,sys; print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b'=').decode())",
            verifier,
        ])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
