//! One entry point over every parser, and the fixture list, shared by the parser tests.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use qb_proto::WindowReport;
use qb_vendors::{Error, claude, codex};

pub const NOW: u64 = 1_800_000_000;

#[derive(Debug, Clone, Copy)]
pub enum Source {
    Stream,
    Statusline,
    Rollout,
    ClaudeUsage,
    CodexUsage,
}

pub const SOURCES: [Source; 5] = [
    Source::Stream,
    Source::Statusline,
    Source::Rollout,
    Source::ClaudeUsage,
    Source::CodexUsage,
];

/// A parser's answer with the per-source shapes flattened; `status` is set only for stream lines.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub status: Option<String>,
    pub windows: Vec<WindowReport>,
}

impl Source {
    pub fn parse(self, input: &[u8], now: u64) -> Result<Option<Parsed>, Error> {
        let plain = |windows| Parsed {
            status: None,
            windows,
        };
        match self {
            Self::Stream => Ok(claude::stream_line(input)?.map(|e| Parsed {
                status: Some(e.status),
                windows: e.windows,
            })),
            Self::Statusline => Ok(claude::statusline(input)?.map(plain)),
            Self::Rollout => Ok(codex::rollout_line(input, now)?.map(plain)),
            Self::ClaudeUsage => Ok(Some(plain(claude::usage(input)?))),
            Self::CodexUsage => Ok(Some(plain(codex::usage(input, now)?))),
        }
    }
}

pub const FIXTURES: [(&str, Source); 15] = [
    ("claude_stream_seconds.json", Source::Stream),
    ("claude_stream_ms.json", Source::Stream),
    ("claude_stream_rejected.json", Source::Stream),
    ("claude_stream_other.json", Source::Stream),
    ("claude_statusline.json", Source::Statusline),
    ("claude_statusline_no_limits.json", Source::Statusline),
    ("claude_usage.json", Source::ClaudeUsage),
    ("claude_usage_idle.json", Source::ClaudeUsage),
    ("codex_rollout_resets_at.jsonl", Source::Rollout),
    ("codex_rollout_resets_in.jsonl", Source::Rollout),
    (
        "codex_rollout_resets_in_no_timestamp.jsonl",
        Source::Rollout,
    ),
    ("codex_rollout_other.jsonl", Source::Rollout),
    ("codex_usage_reset_at.json", Source::CodexUsage),
    ("codex_usage_reset_after.json", Source::CodexUsage),
    ("codex_usage_same_length.json", Source::CodexUsage),
];

pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

pub fn window(name: &str, utilization: f64, resets_at: Option<u64>, length_s: u32) -> WindowReport {
    WindowReport {
        name: name.into(),
        utilization,
        resets_at,
        length_s: Some(length_s),
    }
}
