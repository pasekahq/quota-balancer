//! Fixture loading, a stream driver and a deterministic RNG shared by the tests.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use qb_anthropic::limits::{Failure, RateLimits};
use qb_anthropic::stream::{Progress, Reader};
use qb_proto::{StopReason, StreamEvent};
use serde_json::Value;

pub const VENDOR: &str = "vendor-a";
pub const NOW: u64 = 1_800_000_000;

pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A recorded vendor answer: status, headers and body bytes.
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn load(name: &str) -> Self {
        let v: Value = serde_json::from_slice(&fixture(name)).expect("answer fixture is JSON");
        let headers = v["headers"]
            .as_array()
            .expect("headers")
            .iter()
            .map(|p| {
                (
                    p[0].as_str().expect("name").to_owned(),
                    p[1].as_str().expect("value").to_owned(),
                )
            })
            .collect();
        let body = match &v["body"] {
            Value::Null => Vec::new(),
            Value::String(s) => s.clone().into_bytes(),
            other => other.to_string().into_bytes(),
        };
        Self {
            status: u16::try_from(v["status"].as_u64().expect("status")).expect("u16"),
            headers,
            body,
        }
    }

    pub fn pairs(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect()
    }
}

/// Everything a reader made of a stream fed in the given chunk sizes (cycled).
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub events: Vec<StreamEvent>,
    pub end: Result<StopReason, Failure>,
}

pub fn run_chunked(bytes: &[u8], sizes: &[usize]) -> Run {
    let mut reader = Reader::new(VENDOR, RateLimits::default());
    let mut events = Vec::new();
    let mut rest = bytes;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes[i % sizes.len()].clamp(1, rest.len());
        i += 1;
        let (chunk, tail) = rest.split_at(n);
        rest = tail;
        match reader.feed(chunk, &mut events) {
            Ok(Progress::Continue) => {}
            Ok(Progress::Finished(stop)) => {
                return Run {
                    events,
                    end: Ok(stop),
                };
            }
            Err(f) => {
                return Run {
                    events,
                    end: Err(f),
                };
            }
        }
    }
    Run {
        end: reader.finish(),
        events,
    }
}

pub fn run(bytes: &[u8]) -> Run {
    run_chunked(bytes, &[bytes.len().max(1)])
}

/// xorshift64*: deterministic, so a failing case reproduces from its seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }
}
