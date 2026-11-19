//! The last Claude `rate_limit_event` of a stream-json log, read one line at a time.

use std::io::{self, BufRead};

use qb_vendors::claude::{self, Event};

use crate::{jsonl, log};

/// Longest stream-json line read; a longer line is skipped like a malformed one.
pub const MAX_LINE: usize = 1024 * 1024;

/// The last `rate_limit_event` of `input`, `None` without one. A line that does not parse is
/// skipped with a warning naming `name` and the line number. Memory stays within one
/// [`MAX_LINE`] whatever the length of `input`.
///
/// # Errors
/// Reading `input` failed.
pub fn last_rate_limit_event(input: &mut impl BufRead, name: &str) -> io::Result<Option<Event>> {
    let mut last = None;
    let mut line = Vec::new();
    let mut n = 0;
    while let Some(fits) = jsonl::next_line(input, &mut line, MAX_LINE)? {
        n += 1;
        if !fits {
            log::warn(&format!(
                "{name}: line {n}: skipped: longer than {MAX_LINE} bytes"
            ));
            continue;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match claude::stream_line(&line) {
            Ok(Some(event)) => last = Some(event),
            Ok(None) => {}
            Err(e) => log::warn(&format!("{name}: line {n}: skipped: {e}")),
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn event(status: &str, used: f64) -> String {
        format!(
            r#"{{"type":"rate_limit_event","rate_limit_info":{{"status":"{status}","unifiedWindows":{{"five_hour":{{"utilization":{used},"resetsAt":1800018000}}}}}}}}"#
        )
    }

    #[test]
    fn an_overlong_line_is_skipped_and_reading_goes_on() {
        let pad = format!(r#"{{"pad":"{}","#, "x".repeat(MAX_LINE));
        let long = event("rejected", 0.9).replacen('{', &pad, 1);
        let (first, second) = (event("allowed", 0.1), event("allowed", 0.2));
        let text = format!("{first}\n{long}\n{second}\n{long}");
        let last = last_rate_limit_event(&mut Cursor::new(text), "test")
            .expect("readable")
            .expect("an event");
        assert_eq!(
            (last.status.as_str(), last.windows[0].utilization),
            ("allowed", 0.2)
        );
    }
}
