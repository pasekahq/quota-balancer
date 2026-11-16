//! Every pick reason survives the trip through its journal name.

use qb_core::Reason;

#[test]
fn every_reason_round_trips_by_name() {
    for &r in Reason::ALL {
        assert_eq!(Reason::from_name(r.as_str()), Some(r), "{r:?}");
    }
    let mut names: Vec<&str> = Reason::ALL.iter().map(|r| r.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), Reason::ALL.len(), "names are unique");
    assert_eq!(Reason::from_name("no_such_reason"), None);
}
