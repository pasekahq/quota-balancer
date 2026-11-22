//! The decoder of the request bodies that carry a secret: the key of
//! `POST /v1/model/logins/{name}/key` and the paste of `.../oauth/code`. Each body is one JSON
//! object with one string field.
//!
//! Decoding such a body into its `qb-proto` type leaves copies of the secret in memory that is
//! freed without being overwritten. `serde_json` unescapes a string with escapes into a scratch
//! buffer of its deserializer, serde then builds the field's `String`, and a refused body (an
//! unknown field under `deny_unknown_fields`, say) drops that `String` before the caller can wrap
//! it. Here `serde_json` only borrows the field's raw JSON text from the body, which the caller
//! holds in a zeroizing buffer. The text is then unescaped straight into a zeroizing string
//! allocated at a size it never outgrows. Field names are compared where `serde_json` holds them
//! and never copied into an error, in case a secret was sent as a name. Every refusal is a
//! `serde_json` data or syntax error as before, so the gateway's messages read the same.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer as _, MapAccess, Visitor};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// The string `field` of `body`, which must be one JSON object with that field only, as the
/// `qb-proto` request type with `deny_unknown_fields` would decode it.
///
/// # Errors
/// The [`serde_json::Error`] of a body that is not such an object: invalid JSON, another type,
/// an unknown, repeated or missing field, a field that is not a string, or trailing bytes. The
/// error never holds the field's value.
pub(crate) fn decode(
    body: &[u8],
    field: &'static str,
) -> Result<Zeroizing<String>, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let raw = de.deserialize_map(OneField(field))?;
    de.end()?;
    unescape(raw.get())
        .ok_or_else(|| de::Error::invalid_type(de::Unexpected::Other("not a string"), &"a string"))
}

/// The visitor of an object with the one field `.0`, whose value is borrowed raw.
struct OneField(&'static str);

impl<'de> Visitor<'de> for OneField {
    type Value = &'de RawValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an object with the string `{}` only", self.0)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut value = None;
        while let Some(known) = map.next_key_seed(IsField(self.0))? {
            if !known {
                // A secret sent by mistake as a field name must not reach the error text.
                return Err(de::Error::custom("unknown field"));
            }
            if value.is_some() {
                return Err(de::Error::duplicate_field(self.0));
            }
            value = Some(map.next_value::<&RawValue>()?);
        }
        value.ok_or_else(|| de::Error::missing_field(self.0))
    }
}

/// The seed and visitor of a field name: whether it is `.0`. It compares the name where
/// `serde_json` holds it, so no copy of a name is made here: one sent without escapes is
/// borrowed from the body, one with escapes sits in `serde_json`'s scratch buffer, as any
/// field name of any body would.
struct IsField(&'static str);

impl<'de> DeserializeSeed<'de> for IsField {
    type Value = bool;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
        d.deserialize_str(self)
    }
}

impl Visitor<'_> for IsField {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a field name")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<bool, E> {
        Ok(name == self.0)
    }
}

/// The string the JSON string literal `raw` stands for, or `None` when `raw` is no string or
/// holds a lone surrogate. `raw` is valid JSON, as `serde_json` checked it. The result is
/// allocated once at `raw.len()` bytes: every escape is longer than what it stands for, so it never
/// grows and leaves no reallocated copy behind.
fn unescape(raw: &str) -> Option<Zeroizing<String>> {
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Zeroizing::new(String::with_capacity(inner.len()));
    let mut rest = inner;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let mut chars = rest[at + 1..].chars();
        let c = match chars.next()? {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let (c, after) = unicode(chars.as_str())?;
                rest = after;
                out.push(c);
                continue;
            }
            _ => return None,
        };
        out.push(c);
        rest = chars.as_str();
    }
    out.push_str(rest);
    Some(out)
}

/// The character of the `\u` escape whose hex digits start `s`, a surrogate pair taking the
/// second escape too, and what follows it.
fn unicode(s: &str) -> Option<(char, &str)> {
    let hex = |s: &str| -> Option<u32> {
        let digits = s.get(..4)?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(digits, 16).ok()
    };
    let first = hex(s)?;
    let rest = &s[4..];
    match first {
        0xD800..=0xDBFF => {
            let low_part = rest.strip_prefix("\\u")?;
            let low = hex(low_part)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return None;
            }
            let c = char::from_u32(0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00))?;
            Some((c, &low_part[4..]))
        }
        _ => Some((char::from_u32(first)?, rest)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(body: &str) -> Result<String, String> {
        decode(body.as_bytes(), "key")
            .map(|s| s.as_str().to_owned())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn the_field_is_decoded_as_serde_json_decodes_it() {
        for body in [
            r#"{"key":"plain-value"}"#,
            r#" { "key" : "a\"b\\c\/d" } "#,
            r#"{"key":"Aé€😀 \b\f\n\r\t"}"#,
            r#"{"key":""}"#,
            r#"{"key":"x"}"#,
        ] {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Plain {
                key: String,
            }
            let want: Plain = serde_json::from_str(body).unwrap();
            assert_eq!(decoded(body), Ok(want.key), "{body}");
        }
    }

    #[test]
    fn a_body_of_another_shape_is_refused_as_data_or_syntax() {
        for (body, data) in [
            (r#"{"key":"x","extra":1}"#, true),
            (r#"{"extra":"x","key":"y"}"#, true),
            (r#"{"key":"x","key":"y"}"#, true),
            ("{}", true),
            (r#"{"key":1}"#, true),
            (r#"{"key":null}"#, true),
            (r#"{"key":["x"]}"#, true),
            (r#"["x"]"#, true),
            (r#""x""#, true),
            (r#"{"key":"x"} {}"#, false),
            (r#"{"key":"x""#, false),
            (r#"{"key":"x\q"}"#, false),
            ("", false),
        ] {
            let e = decode(body.as_bytes(), "key").map(|_| ()).unwrap_err();
            assert_eq!(e.is_data(), data, "{body}: {e}");
        }
    }

    #[test]
    fn a_lone_surrogate_is_refused() {
        for body in [
            r#"{"key":"\ud83d"}"#,
            r#"{"key":"\ude00x"}"#,
            r#"{"key":"\ud83dx"}"#,
        ] {
            let e = decode(body.as_bytes(), "key").map(|_| ()).unwrap_err();
            // serde_json refused these as syntax when it built the `String`; the raw text it
            // borrows passes, so the refusal is now a data error, as for a value of another type.
            assert!(e.is_data(), "{body}: {e}");
        }
    }

    #[test]
    fn a_refusal_never_names_the_value() {
        for body in [
            r#"{"key":"secret-value","extra":"other"}"#,
            r#"{"key":"secret-value","key":"secret-value"}"#,
            r#"{"key":"secret-value"} trailing"#,
            r#"{"key":"secret-value\ud800"}"#,
            r#"{"secret-value":"x"}"#,
            r#"{"key":"x","secret-value":"x"}"#,
        ] {
            let e = decode(body.as_bytes(), "key").map(|_| ()).unwrap_err();
            assert!(!e.to_string().contains("secret-value"), "{body}: {e}");
        }
    }

    #[test]
    fn the_result_is_never_reallocated() {
        let body = r#"{"key":"😀A\"\\\/xyz"}"#;
        let raw_len = r#"😀A\"\\\/xyz"#.len();
        let s = decode(body.as_bytes(), "key").unwrap();
        assert!(s.len() <= raw_len);
        assert_eq!(s.capacity(), raw_len, "allocated once at the raw length");
    }
}
