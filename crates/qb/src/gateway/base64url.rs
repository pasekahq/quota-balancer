//! Base64url (RFC 4648, section 5) without padding, for PKCE values, JWT payloads and client
//! tokens.

use rustix::io::Errno;
use rustix::rand::{GetRandomFlags, getrandom};
use zeroize::Zeroizing;

/// Random bytes behind a [`random`] value: 43 base64url characters.
const RANDOM_BYTES: usize = 32;

const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `bytes` encoded without padding.
pub(super) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
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

/// [`RANDOM_BYTES`] from the kernel's random source, base64url-encoded.
pub(super) fn random() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; RANDOM_BYTES]);
    let mut filled = 0;
    while filled < RANDOM_BYTES {
        match getrandom(&mut bytes[filled..], GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(Errno::INTR) => {}
            Err(e) => return Err(format!("getrandom: {e}")),
        }
    }
    Ok(Zeroizing::new(encode(&*bytes)))
}

/// `text` decoded, padded or not, in a buffer zeroized on drop; `None` for a byte outside the
/// alphabet.
pub(super) fn decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let digits = text.trim_end_matches('=').as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(digits.len() * 3 / 4));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in digits {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648, section 10, without padding; `+/` become `-_`.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn the_rfc_vectors_encode_and_decode() {
        for (plain, coded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).unwrap().as_slice(), plain.as_bytes());
        }
        assert_eq!(encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(decode("-_-_").unwrap().as_slice(), [0xfb, 0xff, 0xbf]);
        assert_eq!(decode("Zm8=").unwrap().as_slice(), b"fo");
    }

    #[test]
    fn a_byte_outside_the_alphabet_is_refused() {
        assert!(decode("Zm9v+").is_none());
        assert!(decode("Zm 9v").is_none());
    }
}
