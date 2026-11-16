//! Hostile inputs give a typed error, "no rate-limit data" or a dropped window, never a panic.

mod common;

use common::{FIXTURES, NOW, Parsed, SOURCES, Source, fixture, window};
use qb_proto::WindowReport;
use qb_vendors::Error;

type Want = Result<Option<Parsed>, Error>;

fn parsed(status: Option<&str>, windows: Vec<WindowReport>) -> Parsed {
    Parsed {
        status: status.map(str::to_owned),
        windows,
    }
}

fn h5(utilization: f64, resets_at: Option<u64>) -> Vec<WindowReport> {
    vec![window("five_hour", utilization, resets_at, 18_000)]
}

fn check(source: Source, cases: &[(&str, Want)]) {
    for (input, want) in cases {
        assert_eq!(
            &source.parse(input.as_bytes(), NOW),
            want,
            "{source:?} {input}"
        );
    }
}

#[test]
fn malformed_documents_fail_on_every_parser() {
    let cases: [(&[u8], Error); 11] = [
        (b"", Error::NotJson),
        (b"not json", Error::NotJson),
        (b"\xff\xfe{}", Error::NotJson),
        (b"{\"a\":1} {\"b\":2}", Error::NotJson),
        (b"{\"utilization\": NaN}", Error::NotJson),
        (b"{\"utilization\": Infinity}", Error::NotJson),
        (b"null", Error::WrongType("$")),
        (b"[]", Error::WrongType("$")),
        (b"42", Error::WrongType("$")),
        (b"\"rate_limits\"", Error::WrongType("$")),
        (b"true", Error::WrongType("$")),
    ];
    for source in SOURCES {
        for (input, want) in &cases {
            assert_eq!(source.parse(input, NOW), Err(*want), "{source:?} {input:?}");
        }
    }
}

#[test]
fn truncated_fixtures_fail_as_not_json() {
    for (name, source) in FIXTURES {
        let full = fixture(name);
        let cut = &full[..full.len() / 2];
        assert_eq!(source.parse(cut, NOW), Err(Error::NotJson), "{name}");
    }
}

#[test]
fn stream_line_fields() {
    check(
        Source::Stream,
        &[
            (r#"{"type":7}"#, Ok(None)),
            (r#"{"type":"result","rate_limit_info":[]}"#, Ok(None)),
            (
                r#"{"type":"rate_limit_event"}"#,
                Err(Error::Missing("rate_limit_info")),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":[]}"#,
                Err(Error::WrongType("rate_limit_info")),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{}}"#,
                Err(Error::Missing("rate_limit_info.status")),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":1}}"#,
                Err(Error::WrongType("rate_limit_info.status")),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":"x"}}"#,
                Err(Error::WrongType("rate_limit_info.unifiedWindows")),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":null}}"#,
                Ok(Some(parsed(Some("allowed"), vec![]))),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"weird","unifiedWindows":{"five_hour":null,"seven_day":[],"":{"utilization":0.5}}}}"#,
                Ok(Some(parsed(Some("weird"), vec![]))),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":"0.5"},"seven_day":{"utilization":-0.1}}}}"#,
                Ok(Some(parsed(Some("allowed"), vec![]))),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":1e308,"resetsAt":null}}}}"#,
                Ok(Some(parsed(Some("allowed"), h5(1.0, None)))),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":0.5,"resetsAt":"1800000000"},"seven_day":{"utilization":0.5,"resetsAt":-1},"seven_day_opus":{"utilization":0.5,"resetsAt":1e30}}}}"#,
                Ok(Some(parsed(Some("allowed"), vec![]))),
            ),
            (
                r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","unifiedWindows":{"five_hour":{"utilization":0.5,"resetsAt":18446744073709551615}}}}"#,
                Ok(Some(parsed(Some("allowed"), vec![]))),
            ),
        ],
    );
}

#[test]
fn statusline_fields() {
    check(
        Source::Statusline,
        &[
            (r#"{"rate_limits":null}"#, Ok(None)),
            (
                r#"{"rate_limits":[]}"#,
                Err(Error::WrongType("rate_limits")),
            ),
            (
                r#"{"rate_limits":{"five_hour":null,"seven_day":{"used_percentage":"41"},"ten_minute":{"used_percentage":5}}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"rate_limits":{"five_hour":{"used_percentage":250,"resets_at":1800018000.9},"seven_day":{"used_percentage":-1}}}"#,
                Ok(Some(parsed(None, h5(1.0, Some(1_800_018_000))))),
            ),
        ],
    );
}

#[test]
fn rollout_line_fields() {
    check(
        Source::Rollout,
        &[
            (r#"{"type":"session_meta"}"#, Ok(None)),
            (r#"{"payload":{"info":null,"rate_limits":null}}"#, Ok(None)),
            (r#"{"payload":"x"}"#, Err(Error::WrongType("payload"))),
            (
                r#"{"payload":{"rate_limits":3}}"#,
                Err(Error::WrongType("payload.rate_limits")),
            ),
            (
                r#"{"payload":{"info":3}}"#,
                Err(Error::WrongType("payload.info")),
            ),
            (
                r#"{"payload":{"info":{"rate_limits":"x"}}}"#,
                Err(Error::WrongType("payload.info.rate_limits")),
            ),
            (
                r#"{"payload":{"rate_limits":{"primary":{"used_percent":5,"window_minutes":"300"},"secondary":{"used_percent":5,"window_minutes":0}}}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"payload":{"rate_limits":{"primary":{"used_percent":5,"window_minutes":18446744073709551615},"secondary":{"used_percent":-5,"window_minutes":300}}}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"payload":{"rate_limits":{"primary":{"used_percent":50,"window_minutes":300,"resets_in_seconds":-1},"secondary":{"used_percent":50,"window_minutes":300,"resets_in_seconds":1.8e19}}}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"timestamp":"2027-02-30T00:00:00Z","payload":{"rate_limits":{"primary":{"used_percent":50,"window_minutes":300,"resets_in_seconds":60}}}}"#,
                Ok(Some(parsed(None, h5(0.5, Some(NOW + 60))))),
            ),
        ],
    );
}

#[test]
fn claude_usage_fields() {
    check(
        Source::ClaudeUsage,
        &[
            ("{}", Ok(Some(parsed(None, vec![])))),
            (
                r#"{"five_hour":[],"seven_day":{"utilization":"6"},"seven_day_opus":{"utilization":-0.1},"seven_day_":{"utilization":1}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"five_hour":{"utilization":5,"resets_at":1800000000},"seven_day":{"utilization":5,"resets_at":"2027-02-30T00:00:00Z"}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"five_hour":{"utilization":1e300,"resets_at":"2027-01-15T08:00:00Z"}}"#,
                Ok(Some(parsed(None, h5(1.0, Some(1_800_000_000))))),
            ),
        ],
    );
}

#[test]
fn codex_usage_fields() {
    check(
        Source::CodexUsage,
        &[
            ("{}", Ok(Some(parsed(None, vec![])))),
            (r#"{"rate_limit":null}"#, Ok(Some(parsed(None, vec![])))),
            (r#"{"rate_limit":"x"}"#, Err(Error::WrongType("rate_limit"))),
            (
                r#"{"rate_limit":{"primary_window":{"used_percent":5,"limit_window_seconds":61},"secondary_window":{"used_percent":5,"limit_window_seconds":18000,"reset_after_seconds":"60"}}}"#,
                Ok(Some(parsed(None, vec![]))),
            ),
            (
                r#"{"rate_limit":{"primary_window":{"used_percent":25,"limit_window_seconds":3600,"reset_after_seconds":60.7},"secondary_window":[]}}"#,
                Ok(Some(parsed(
                    None,
                    vec![window("window_60m", 0.25, Some(NOW + 60), 3600)],
                ))),
            ),
        ],
    );
}
