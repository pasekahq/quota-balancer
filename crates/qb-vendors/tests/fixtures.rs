//! Every synthetic fixture parses into exactly the expected windows and stream status.

mod common;

use common::{FIXTURES, NOW, Parsed, fixture, window};

const H5: u32 = 18_000;
const D7: u32 = 604_800;

fn expected(name: &str) -> Option<Parsed> {
    let status = |s: &str| Some(s.to_owned());
    let (status, windows) = match name {
        "claude_stream_seconds.json" => (
            status("allowed"),
            vec![
                window("five_hour", 0.15, Some(1_800_018_000), H5),
                window("seven_day", 0.42, Some(1_800_432_000), D7),
            ],
        ),
        "claude_stream_ms.json" => (
            status("allowed_warning"),
            vec![
                window("five_hour", 0.81, Some(1_800_018_000), H5),
                window("seven_day", 0.5, Some(1_800_432_000), D7),
            ],
        ),
        "claude_stream_rejected.json" => (
            status("rejected"),
            vec![window("five_hour", 1.0, Some(1_800_018_000), H5)],
        ),
        "claude_statusline.json" => (
            None,
            vec![
                window("five_hour", 0.235, Some(1_800_018_000), H5),
                window("seven_day", 0.41, Some(1_800_432_000), D7),
            ],
        ),
        "claude_usage.json" => (
            None,
            vec![
                window("five_hour", 0.06, Some(1_800_018_000), H5),
                window("seven_day", 0.35, Some(1_800_432_000), D7),
                window("seven_day_sonnet", 0.125, Some(1_800_432_000), D7),
            ],
        ),
        "claude_usage_idle.json" => (
            None,
            vec![
                window("five_hour", 0.0, None, H5),
                window("seven_day", 0.03, Some(1_800_027_000), D7),
            ],
        ),
        "codex_rollout_resets_at.jsonl" => (
            None,
            vec![
                window("five_hour", 0.12, Some(1_800_018_000), H5),
                window("seven_day", 0.305, Some(1_800_432_000), D7),
            ],
        ),
        // The line time 2027-01-15T08:00:00.500+02:00 is 1_799_992_800.
        "codex_rollout_resets_in.jsonl" => (
            None,
            vec![
                window("five_hour", 0.04, Some(1_799_996_400), H5),
                window("window_1440m", 0.09, Some(1_800_000_000), 86_400),
            ],
        ),
        "codex_rollout_resets_in_no_timestamp.jsonl" => {
            (None, vec![window("five_hour", 0.55, Some(NOW + 600), H5)])
        }
        "codex_usage_reset_at.json" => (
            None,
            vec![
                window("five_hour", 0.07, Some(1_800_018_000), H5),
                window("seven_day", 0.22, Some(1_800_432_000), D7),
            ],
        ),
        "codex_usage_reset_after.json" => (
            None,
            vec![
                window("five_hour", 1.0, Some(NOW + 3600), H5),
                window("seven_day", 0.645, Some(NOW + 86_400), D7),
            ],
        ),
        "codex_usage_same_length.json" => {
            (None, vec![window("five_hour", 0.2, Some(NOW + 3600), H5)])
        }
        "claude_stream_other.json"
        | "claude_statusline_no_limits.json"
        | "codex_rollout_other.jsonl" => return None,
        other => panic!("no expectation for fixture {other}"),
    };
    Some(Parsed { status, windows })
}

#[test]
fn fixtures_parse_to_expected_windows() {
    for (name, source) in FIXTURES {
        let got = source
            .parse(&fixture(name), NOW)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = expected(name);
        let (Some(got), Some(want)) = (&got, &want) else {
            assert_eq!(got, want, "{name}");
            continue;
        };
        assert_eq!(got.status, want.status, "{name}: status");
        assert_eq!(got.windows.len(), want.windows.len(), "{name}: {got:?}");
        for (g, w) in got.windows.iter().zip(&want.windows) {
            assert_eq!(
                (&g.name, g.resets_at, g.length_s),
                (&w.name, w.resets_at, w.length_s),
                "{name}"
            );
            assert!(
                (g.utilization - w.utilization).abs() < 1e-12,
                "{name}: {} utilization {} != {}",
                g.name,
                g.utilization,
                w.utilization
            );
        }
    }
}
