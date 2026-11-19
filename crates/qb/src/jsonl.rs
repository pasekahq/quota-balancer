//! Bounded reading of newline-separated lines and of JSONL files the gateway reads back.

use std::fs::File;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};
use std::ops::ControlFlow;
use std::path::Path;

use serde::de::DeserializeOwned;

/// Longest line of a JSONL file [`read`] parses; a longer one is skipped.
pub(crate) const MAX_LINE: usize = 64 * 1024;

/// Reads the next line of `input` into `line` without its newline: `Some(true)` when it holds at
/// most `max` bytes, `Some(false)` when it is longer and was consumed without being kept, `None`
/// at the end of `input`. `line` never grows past `max` + 1 bytes.
///
/// # Errors
/// Reading `input` failed.
pub(crate) fn next_line(
    input: &mut impl BufRead,
    line: &mut Vec<u8>,
    max: usize,
) -> io::Result<Option<bool>> {
    line.clear();
    if (&mut *input).take(max as u64 + 1).read_until(b'\n', line)? == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > max {
        line.clear();
        skip_line(input)?;
        return Ok(Some(false));
    }
    Ok(Some(true))
}

/// Consumes `input` up to and including the next newline.
fn skip_line(input: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buf = input.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            input.consume(i + 1);
            return Ok(());
        }
        let len = buf.len();
        input.consume(len);
    }
}

/// Calls `each` with every line of `file` that parses as a `T`, in file order, until it breaks;
/// a missing file has no lines. Answers the number of lines read that do not parse or are longer
/// than [`MAX_LINE`]; memory stays within one [`MAX_LINE`] whatever the file holds.
///
/// # Errors
/// The file cannot be opened or read.
pub(crate) fn read<T: DeserializeOwned>(
    file: &Path,
    mut each: impl FnMut(T) -> ControlFlow<()>,
) -> io::Result<u64> {
    let f = match File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(f);
    let mut line = Vec::new();
    let mut skipped = 0;
    while let Some(fits) = next_line(&mut reader, &mut line, MAX_LINE)? {
        let value = fits.then(|| serde_json::from_slice::<T>(&line).ok());
        match value.flatten() {
            Some(value) => {
                if each(value).is_break() {
                    break;
                }
            }
            None => skipped += 1,
        }
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn a_line_over_the_limit_is_consumed_without_being_kept() {
        let mut input = Cursor::new(b"abcd\nabcdefgh\nabc\nabcde".to_vec());
        let mut line = Vec::new();
        let mut seen = Vec::new();
        while let Some(fits) = next_line(&mut input, &mut line, 4).unwrap() {
            seen.push((fits, String::from_utf8(line.clone()).unwrap()));
        }
        let want = [(true, "abcd"), (false, ""), (true, "abc"), (false, "")];
        assert_eq!(seen, want.map(|(fits, l)| (fits, l.to_owned())));
    }
}
