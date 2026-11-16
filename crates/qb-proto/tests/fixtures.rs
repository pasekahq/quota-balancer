//! Contract fixtures: every fixture decodes into its type and re-encodes to the same JSON.

use qb_proto::{
    Decision, ErrorBody, HealthResponse, Outcome, PickRequest, PickResponse, ReportRequest,
    ReportResponse, StateResponse,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Decodes the fixture as `T`, re-encodes it and checks the JSON is unchanged.
fn roundtrip<T: Serialize + DeserializeOwned>(name: &str) -> T {
    let raw = fixture(name);
    let value: T = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
    let original: Value = serde_json::from_str(&raw).expect("fixture is JSON");
    let again = serde_json::to_value(&value).expect("encode");
    assert_eq!(original, again, "{name} does not round-trip");
    value
}

#[test]
fn pick_requests() {
    let d: PickRequest = roundtrip("pick_request_difficulty.json");
    assert_eq!(d.difficulty, Some(2));
    assert!(d.validate().is_ok());
    let p: PickRequest = roundtrip("pick_request_pin.json");
    assert_eq!(p.pin.as_ref().map(|p| p.vendor.as_str()), Some("vendor-b"));
    assert!(p.validate().is_ok());
}

#[test]
fn pick_responses() {
    let run: PickResponse = roundtrip("pick_response_run.json");
    assert_eq!(run.decision, Decision::Run);
    let wait: PickResponse = roundtrip("pick_response_wait.json");
    assert_eq!(wait.decision, Decision::Wait);
    assert!(wait.stale);
}

#[test]
fn reports() {
    let stream: ReportRequest = roundtrip("report_request_stream.json");
    assert_eq!(stream.windows.len(), 2);
    let limit: ReportRequest = roundtrip("report_request_limit.json");
    assert_eq!(limit.outcome, Outcome::UsageLimit);
    let _: ReportResponse = roundtrip("report_response.json");
}

#[test]
fn state_health_error() {
    let s: StateResponse = roundtrip("state_response.json");
    assert_eq!(s.logins.len(), 1);
    let _: HealthResponse = roundtrip("health_response.json");
    let _: ErrorBody = roundtrip("error_body.json");
}

#[test]
fn requests_reject_unknown_fields() {
    let err = serde_json::from_str::<PickRequest>(r#"{"role":"worker","difficulty":1,"x":1}"#);
    assert!(err.is_err());
    let err = serde_json::from_str::<ReportRequest>(r#"{"outcome":"ok","token":"t"}"#);
    assert!(err.is_err());
}
