//! The config file edit of `PUT /v1/model/config/routes`: routes rendered as `[[routes]]` tables
//! and spliced over the file's `[[routes]]` items, every byte outside those items kept.
//!
//! An item spans from its `[[routes]]` header to the end of the line of its last value, so
//! comments and blank lines after that line stay, and comments inside an item go with it.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, ErrorKind, Write as _};
use std::ops::Range;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use qb_proto::{ConfigRoute, ConfigStep};
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use super::config::Route;
use crate::config::{Error, toml_error};

/// `routes` key for key, as `/v1/model/config/routes` carries them.
pub fn routes_of(routes: &[Route]) -> Vec<ConfigRoute> {
    routes
        .iter()
        .map(|r| ConfigRoute {
            alias: r.alias.clone(),
            role: r.role.clone(),
            difficulty: r.difficulty.map(i64::from),
            vendor: r.vendor.clone(),
            model: r.model.clone(),
            effort: r.effort.clone(),
            chain: (!r.chain.is_empty()).then(|| {
                r.chain
                    .iter()
                    .map(|s| ConfigStep {
                        vendor: s.vendor.clone(),
                        model: s.model.clone(),
                        effort: s.effort.clone(),
                    })
                    .collect()
            }),
            expected_minutes: r.expected_minutes.map(i64::from),
        })
        .collect()
}

/// `routes` as `[[routes]]` tables separated by a blank line, the last one ending in a newline.
pub fn render(routes: &[ConfigRoute]) -> String {
    let mut out = String::new();
    for (i, r) in routes.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str("[[routes]]\n");
        key(&mut out, "alias", &r.alias);
        key(&mut out, "role", &r.role);
        if let Some(d) = r.difficulty {
            let _ = writeln!(out, "difficulty = {d}");
        }
        for (name, value) in [
            ("vendor", &r.vendor),
            ("model", &r.model),
            ("effort", &r.effort),
        ] {
            if let Some(v) = value {
                key(&mut out, name, v);
            }
        }
        if let Some(chain) = &r.chain {
            out.push_str("chain = [\n");
            for s in chain {
                let _ = write!(
                    out,
                    "  {{ vendor = {}, model = {}",
                    basic(&s.vendor),
                    basic(&s.model)
                );
                if let Some(effort) = &s.effort {
                    let _ = write!(out, ", effort = {}", basic(effort));
                }
                out.push_str(" },\n");
            }
            out.push_str("]\n");
        }
        if let Some(m) = r.expected_minutes {
            let _ = writeln!(out, "expected_minutes = {m}");
        }
    }
    out
}

/// Appends the line `name = "<value>"`.
fn key(out: &mut String, name: &str, value: &str) {
    let _ = writeln!(out, "{name} = {}", basic(value));
}

/// `s` as a TOML basic string.
fn basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `text`, the config file `file`, with its `[[routes]]` items replaced by `items` at the place
/// of the first one; without any, `items` go at the end.
///
/// # Errors
/// `text` is not TOML, or its `routes` are not `[[routes]]` tables.
pub fn splice(file: &Path, text: &str, items: &str) -> Result<String, Error> {
    let ranges = item_ranges(file, text)?;
    let mut out = String::with_capacity(text.len() + items.len());
    let Some(first) = ranges.first() else {
        out.push_str(text);
        if !text.is_empty() && !text.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(items);
        return Ok(out);
    };
    out.push_str(&text[..first.start]);
    out.push_str(items);
    let mut at = first.end;
    for r in &ranges[1..] {
        out.push_str(&text[at..r.start]);
        at = r.end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}

/// The byte ranges of the `[[routes]]` items of `text`, in file order.
fn item_ranges(file: &Path, text: &str) -> Result<Vec<Range<usize>>, Error> {
    let doc = DeTable::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))?;
    let Some(routes) = doc.get_ref().get("routes") else {
        return Ok(Vec::new());
    };
    let not_tables = || Error {
        file: file.to_owned(),
        field: "routes".into(),
        reason: "only `[[routes]]` tables can be replaced".into(),
    };
    let items = routes.get_ref().as_array().ok_or_else(not_tables)?;
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        let start = item.span().start;
        if item.get_ref().as_table().is_none() || !text[start..].starts_with("[[") {
            return Err(not_tables());
        }
        let last = last_end(item);
        let end = text[last..].find('\n').map_or(text.len(), |n| last + n + 1);
        ranges.push(start..end);
    }
    Ok(ranges)
}

/// The end of the last byte of `v` and of everything beneath it.
fn last_end(v: &Spanned<DeValue<'_>>) -> usize {
    let own = v.span().end;
    match v.get_ref() {
        DeValue::Table(t) => t
            .iter()
            .map(|(k, v)| k.span().end.max(last_end(v)))
            .fold(own, usize::max),
        DeValue::Array(a) => a.iter().map(last_end).fold(own, usize::max),
        _ => own,
    }
}

/// Most backups of one second; one more is refused.
const BACKUPS_PER_SECOND: u32 = 100;

/// Writes `bytes` to a new 0600 file `<file>.bak-<now>`, with `-<n>` appended when a backup of
/// that second exists; never replaces a file.
///
/// # Errors
/// The file cannot be created or written; a partly written one is removed.
pub fn backup(file: &Path, bytes: &[u8], now: u64) -> io::Result<PathBuf> {
    for n in 0..BACKUPS_PER_SECOND {
        let mut name = file.as_os_str().to_owned();
        name.push(format!(".bak-{now}"));
        if n > 0 {
            name.push(format!("-{n}"));
        }
        let path = PathBuf::from(name);
        let mut f = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        return Ok(path);
    }
    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        format!("{BACKUPS_PER_SECOND} backups of second {now} exist"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(alias: &str) -> ConfigRoute {
        ConfigRoute {
            alias: alias.into(),
            role: "gateway".into(),
            difficulty: Some(1),
            vendor: None,
            model: None,
            effort: None,
            chain: None,
            expected_minutes: None,
        }
    }

    fn spliced(text: &str, routes: &[ConfigRoute]) -> String {
        splice(Path::new("gw.toml"), text, &render(routes)).unwrap()
    }

    #[test]
    fn items_are_replaced_at_the_first_one_and_every_other_byte_stays() {
        let text = "socket = \"/s\" # top\n\n# routes follow\n[[routes]]\nalias = \"a\"\n\
                    # inside a\nrole = \"r\" # trailing\ndifficulty = 1\n\n# between\n\
                    [fronts]\nlisten = \"x\"\n[[routes]]\nalias = \"b\"\nrole = \"r\"\n\
                    chain = [\n  { vendor = \"v\", model = \"m\" },\n]\n# after b\n";
        let mut new = route("c");
        new.chain = Some(vec![ConfigStep {
            vendor: "v".into(),
            model: "m".into(),
            effort: Some("high".into()),
        }]);
        new.difficulty = None;
        new.expected_minutes = Some(5);
        let got = spliced(text, &[route("a"), new]);
        let want = "socket = \"/s\" # top\n\n# routes follow\n[[routes]]\nalias = \"a\"\n\
                    role = \"gateway\"\ndifficulty = 1\n\n[[routes]]\nalias = \"c\"\n\
                    role = \"gateway\"\nchain = [\n  { vendor = \"v\", model = \"m\", \
                    effort = \"high\" },\n]\nexpected_minutes = 5\n\n# between\n\
                    [fronts]\nlisten = \"x\"\n# after b\n";
        assert_eq!(got, want);
    }

    #[test]
    fn sub_tables_of_an_item_and_a_last_line_without_newline_go_with_it() {
        let text = "[[routes]]\nalias = \"a\"\nrole = \"r\"\n[[routes.chain]]\nvendor = \"v\"\n\
                    model = \"m\"\n[usage]\nfile = \"/u\"\n[[routes]]\nalias = \"b\"\nrole = \"r\"";
        let got = spliced(text, &[route("z")]);
        assert_eq!(
            got,
            "[[routes]]\nalias = \"z\"\nrole = \"gateway\"\ndifficulty = 1\n[usage]\nfile = \"/u\"\n"
        );
    }

    #[test]
    fn strings_are_escaped_so_toml_reads_them_back() {
        let odd = "q\"b\\s\n\t\r\u{1}\u{7f}é";
        let mut r = route("a");
        r.role = odd.into();
        let text = render(&[r]);
        let doc = DeTable::parse(&text).unwrap();
        let items = doc
            .get_ref()
            .get("routes")
            .unwrap()
            .get_ref()
            .as_array()
            .unwrap();
        let role = items[0].get_ref().as_table().unwrap().get("role").unwrap();
        assert_eq!(role.get_ref().as_str(), Some(odd));
    }

    #[test]
    fn an_inline_routes_array_or_a_file_that_is_not_toml_is_refused() {
        let file = Path::new("gw.toml");
        let inline = "routes = [{ alias = \"a\", role = \"r\", difficulty = 1 }]\n";
        let e = splice(file, inline, "").unwrap_err().to_string();
        assert_eq!(
            e,
            "gw.toml: routes: only `[[routes]]` tables can be replaced"
        );
        let e = splice(file, "[[routes]\n", "").unwrap_err().to_string();
        assert!(e.starts_with("gw.toml: "), "{e}");
    }

    #[test]
    fn without_routes_the_items_are_appended() {
        assert_eq!(
            spliced("socket = \"/s\"", &[route("a")]),
            "socket = \"/s\"\n[[routes]]\nalias = \"a\"\nrole = \"gateway\"\ndifficulty = 1\n"
        );
    }
}
