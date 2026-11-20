//! The config file edit of `PUT /v1/model/config/routes`: routes rendered as `[[routes]]` tables
//! and spliced over the file's `[[routes]]` items, and `spend_cap` values of `[[logins]]` set,
//! added or removed in place; every other byte is kept.
//!
//! An item spans from its `[[routes]]` header to the end of the line of its last value, so
//! comments and blank lines after that line stay, and comments inside an item go with it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::Path;

use qb_proto::{ConfigRoute, ConfigStep};
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use super::config::{CredentialKind, GatewayLogin, Route};
use crate::config::{Error, toml_error};
use crate::rewrite::{basic, float};

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
            client_effort: r.client_effort.map(|c| c.as_str().to_owned()),
            logins: r.logins.clone(),
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
        if let Some(c) = &r.client_effort {
            key(&mut out, "client_effort", c);
        }
        if let Some(logins) = &r.logins {
            let names: Vec<String> = logins.iter().map(|l| basic(l)).collect();
            let _ = writeln!(out, "logins = [{}]", names.join(", "));
        }
    }
    out
}

/// Appends the line `name = "<value>"`.
fn key(out: &mut String, name: &str, value: &str) {
    let _ = writeln!(out, "{name} = {}", basic(value));
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
///
/// # Errors
/// `text` is not TOML, its `routes` are not `[[routes]]` tables, or a key outside `routes` lies
/// within an item, as a table placed between an item and its sub-tables does.
fn item_ranges(file: &Path, text: &str) -> Result<Vec<Range<usize>>, Error> {
    let doc = parse(file, text)?;
    let Some(routes) = doc.get_ref().get("routes") else {
        return Ok(Vec::new());
    };
    let refused = |reason: &str| Error {
        file: file.to_owned(),
        field: "routes".into(),
        reason: reason.into(),
    };
    let not_tables = || refused("only `[[routes]]` tables can be replaced");
    let items = routes.get_ref().as_array().ok_or_else(not_tables)?;
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        let start = item.span().start;
        if item.get_ref().as_table().is_none() || !text[start..].starts_with("[[") {
            return Err(not_tables());
        }
        ranges.push(start..line_end(text, last_end(item)));
    }
    let mut others = Vec::new();
    for (k, v) in doc
        .get_ref()
        .iter()
        .filter(|(k, _)| k.get_ref() != "routes")
    {
        others.push(k.span().start);
        starts(v, &mut others);
    }
    if others
        .iter()
        .any(|at| ranges.iter().any(|r| r.contains(at)))
    {
        return Err(refused(
            "a table outside `routes` lies between a `[[routes]]` item and its sub-tables",
        ));
    }
    Ok(ranges)
}

fn parse<'t>(file: &Path, text: &'t str) -> Result<Spanned<DeTable<'t>>, Error> {
    DeTable::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))
}

/// The end of the line of `text` that holds byte `at`, past its newline.
fn line_end(text: &str, at: usize) -> usize {
    text[at..].find('\n').map_or(text.len(), |n| at + n + 1)
}

/// Pushes onto `out` the start of every key and non-empty value beneath `v`.
fn starts(v: &Spanned<DeValue<'_>>, out: &mut Vec<usize>) {
    if !v.span().is_empty() {
        out.push(v.span().start);
    }
    match v.get_ref() {
        DeValue::Table(t) => {
            for (k, v) in t {
                out.push(k.span().start);
                starts(v, out);
            }
        }
        DeValue::Array(a) => a.iter().for_each(|v| starts(v, out)),
        _ => {}
    }
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

/// `spend_cap` of each `api_key` login of `logins` by name.
pub fn spend_caps_of(logins: &[GatewayLogin]) -> BTreeMap<String, Option<f64>> {
    logins
        .iter()
        .filter(|l| l.kind == CredentialKind::ApiKey)
        .map(|l| (l.name.clone(), l.spend_cap))
        .collect()
}

/// `text`, the config file `file`, with the `spend_cap` of each login named in `caps` set to its
/// value in place, added as a line at the end of the login's table, or its line removed for
/// `None`.
///
/// # Errors
/// `text` is not TOML, a named login is not a `[[logins]]` table of the file, or its `kind` is
/// not `api_key`.
pub fn set_spend_caps(
    file: &Path,
    text: &str,
    caps: &BTreeMap<String, Option<f64>>,
) -> Result<String, Error> {
    let doc = parse(file, text)?;
    let refused = |reason: String| Error {
        file: file.to_owned(),
        field: "logins".into(),
        reason,
    };
    let logins: Vec<_> = match doc.get_ref().get("logins") {
        Some(l) => l.get_ref().as_array(),
        None => None,
    }
    .into_iter()
    .flatten()
    .filter_map(|l| Some((l, l.get_ref().as_table()?)))
    .collect();
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    for (name, cap) in caps {
        let named = |(_, t): &&(_, &DeTable<'_>)| {
            t.get("name").and_then(|n| n.get_ref().as_str()) == Some(name.as_str())
        };
        let Some(&(login, table)) = logins.iter().find(named) else {
            return Err(refused(format!("no login `{name}`")));
        };
        let kind = table.get("kind").and_then(|k| k.get_ref().as_str());
        if kind != Some(CredentialKind::ApiKey.as_str()) {
            return Err(refused(format!("login `{name}` is not an `api_key` login")));
        }
        if !text[login.span().start..].starts_with("[[") {
            return Err(refused(format!(
                "login `{name}` is not a `[[logins]]` table"
            )));
        }
        let key = table.iter().find(|(k, _)| k.get_ref() == "spend_cap");
        match (key, cap) {
            (Some((_, v)), Some(cap)) => edits.push((v.span(), float(*cap))),
            (Some((k, v)), None) => {
                let start = text[..k.span().start].rfind('\n').map_or(0, |n| n + 1);
                edits.push((start..line_end(text, v.span().end), String::new()));
            }
            (None, Some(cap)) => {
                let at = line_end(text, last_end(login));
                let newline = if text[..at].ends_with('\n') { "" } else { "\n" };
                edits.push((at..at, format!("{newline}spend_cap = {}\n", float(*cap))));
            }
            (None, None) => {}
        }
    }
    edits.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
    let mut out = text.to_owned();
    for (range, with) in edits {
        out.replace_range(range, &with);
    }
    Ok(out)
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
            client_effort: None,
            logins: None,
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
    fn a_table_between_an_item_and_its_sub_tables_is_refused() {
        let text = "[[routes]]\nalias = \"a\"\nrole = \"r\"\n[usage]\nfile = \"/u\"\n\
                    [[routes.chain]]\nvendor = \"v\"\nmodel = \"m\"\n";
        let e = splice(Path::new("gw.toml"), text, "")
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            "gw.toml: routes: a table outside `routes` lies between a `[[routes]]` item and its \
             sub-tables"
        );
    }

    const LOGINS: &str = "spend_file = \"/s.json\"\n[[logins]]\nname = \"key-1\" # one\n\
                          kind = \"api_key\"\nspend_cap = 25 # monthly\ncredentials = \"/c1\"\n\n\
                          # between\n[[logins]]\nname = \"key-2\"\nkind = \"api_key\"\n\
                          credentials = \"/c2\" # two\n# after key-2\n[[logins]]\n\
                          name = \"oauth-1\"\nkind = \"oauth_anthropic\"\ncredentials = \"/c3\"";

    fn capped(text: &str, caps: &[(&str, Option<f64>)]) -> Result<String, String> {
        let caps = caps.iter().map(|(n, c)| ((*n).to_owned(), *c)).collect();
        set_spend_caps(Path::new("gw.toml"), text, &caps).map_err(|e| e.to_string())
    }

    #[test]
    fn caps_are_set_in_place_added_after_the_login_s_last_line_or_removed_with_their_line() {
        let got = capped(LOGINS, &[("key-1", Some(0.1)), ("key-2", Some(1e21))]).unwrap();
        let want = LOGINS
            .replace("spend_cap = 25 #", "spend_cap = 0.1 #")
            .replace(
                "credentials = \"/c2\" # two\n",
                "credentials = \"/c2\" # two\nspend_cap = 1e21\n",
            );
        assert_eq!(got, want);
        let got = capped(&got, &[("key-1", None), ("key-2", None)]).unwrap();
        assert_eq!(got, LOGINS.replace("spend_cap = 25 # monthly\n", ""));
        assert_eq!(capped(LOGINS, &[("key-2", None)]).unwrap(), LOGINS);
    }

    #[test]
    fn a_cap_added_to_a_last_line_without_newline_gets_its_own_line() {
        let text = "[[logins]]\nname = \"key-1\"\nkind = \"api_key\"";
        assert_eq!(
            capped(text, &[("key-1", Some(3.5))]).unwrap(),
            format!("{text}\nspend_cap = 3.5\n")
        );
    }

    #[test]
    fn an_unknown_inline_or_other_kind_login_is_refused_by_name() {
        let refused = |caps: &[(&str, Option<f64>)]| capped(LOGINS, caps).unwrap_err();
        assert_eq!(
            refused(&[("key-9", Some(1.0))]),
            "gw.toml: logins: no login `key-9`"
        );
        assert_eq!(
            refused(&[("oauth-1", None)]),
            "gw.toml: logins: login `oauth-1` is not an `api_key` login"
        );
        let inline = "logins = [{ name = \"key-1\", kind = \"api_key\", credentials = \"/c\" }]\n";
        assert_eq!(
            capped(inline, &[("key-1", Some(1.0))]).unwrap_err(),
            "gw.toml: logins: login `key-1` is not a `[[logins]]` table"
        );
    }

    #[test]
    fn without_routes_the_items_are_appended() {
        assert_eq!(
            spliced("socket = \"/s\"", &[route("a")]),
            "socket = \"/s\"\n[[routes]]\nalias = \"a\"\nrole = \"gateway\"\ndifficulty = 1\n"
        );
    }
}
