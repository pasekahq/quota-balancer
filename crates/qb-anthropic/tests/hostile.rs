//! Hostile input: any chunking of a stream gives the same events, and garbage in any parser
//! gives an error value, never a panic.

mod common;

use common::{Answer, Rng, VENDOR, fixture, run, run_chunked};
use qb_anthropic::front::decode_request;
use qb_anthropic::limits::{RateLimits, classify_response, rate_limits};
use qb_anthropic::stream::Reader;

const STREAMS: &[&str] = &[
    "upstream_text.sse",
    "upstream_text_crlf.sse",
    "upstream_tool_use.sse",
    "upstream_thinking.sse",
    "upstream_max_tokens.sse",
    "upstream_error_overloaded.sse",
    "client_stream.sse",
];

#[test]
fn every_chunking_gives_the_same_events() {
    let mut rng = Rng(0x00c0_ffee);
    for name in STREAMS {
        let bytes = fixture(name);
        let whole = run(&bytes);
        for split in 1..=3 {
            assert_eq!(run_chunked(&bytes, &[split]), whole, "{name} by {split}");
        }
        for _ in 0..200 {
            let sizes: Vec<usize> = (0..8).map(|_| 1 + rng.below(64)).collect();
            assert_eq!(run_chunked(&bytes, &sizes), whole, "{name} {sizes:?}");
        }
    }
}

fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    const INTERESTING: &[u8] = b"{}[]\":,\r\n \\\xff\x00:ade";
    if input.is_empty() {
        input.push(b'{');
        return;
    }
    let at = rng.below(input.len());
    match rng.below(5) {
        0 => input[at] ^= 1 << rng.below(8),
        1 => input[at] = INTERESTING[rng.below(INTERESTING.len())],
        2 => input.insert(at, INTERESTING[rng.below(INTERESTING.len())]),
        3 => {
            input.remove(at);
        }
        _ => input.truncate(at),
    }
}

#[test]
fn mutated_streams_never_panic() {
    let mut rng = Rng(0xbad5_eed5);
    for name in STREAMS {
        let original = fixture(name);
        for _ in 0..500 {
            let mut bytes = original.clone();
            for _ in 0..=rng.below(6) {
                mutate(&mut rng, &mut bytes);
            }
            let sizes = [1 + rng.below(40), 1 + rng.below(400)];
            let _ = run_chunked(&bytes, &sizes);
        }
    }
}

#[test]
fn random_bytes_never_panic_and_oversized_events_fail() {
    let mut rng = Rng(42);
    for _ in 0..500 {
        let n = rng.below(512);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next().to_le_bytes()[0]).collect();
        let _ = run(&bytes);
        let _ = decode_request(&bytes, "m", VENDOR, &|_| Some("chat".into()));
        let _ = classify_response(429, &[], &bytes);
    }
    let mut reader = Reader::new(VENDOR, RateLimits::default());
    let mut out = Vec::new();
    let line = vec![b'a'; 1 << 20];
    let mut failed = false;
    for _ in 0..8 {
        if reader
            .feed(b"data: ", &mut out)
            .and_then(|_| reader.feed(&line, &mut out))
            .is_err()
        {
            failed = true;
            break;
        }
    }
    assert!(failed, "an unbounded event must fail");
}

#[test]
fn mutated_requests_and_headers_never_panic() {
    let mut rng = Rng(7);
    let original = fixture("client_sdk_request.json");
    for _ in 0..2000 {
        let mut bytes = original.clone();
        for _ in 0..=rng.below(4) {
            mutate(&mut rng, &mut bytes);
        }
        let _ = decode_request(&bytes, "m", VENDOR, &|_| Some("chat".into()));
    }
    let answer = Answer::load("answer_429_usage_limit.json");
    for _ in 0..2000 {
        let mut headers = answer.headers.clone();
        for (_, v) in &mut headers {
            let mut b = v.clone().into_bytes();
            mutate(&mut rng, &mut b);
            *v = String::from_utf8_lossy(&b).into_owned();
        }
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let limits = rate_limits(&pairs);
        assert!(
            limits
                .windows
                .iter()
                .all(|w| (0.0..=1.0).contains(&w.utilization))
        );
        let _ = classify_response(429, &pairs, &answer.body);
    }
}
