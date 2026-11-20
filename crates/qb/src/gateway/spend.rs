//! The spend count of the logins with a `spend_cap`: USD per login for the current UTC calendar
//! month, kept in the gateway's `spend_file` and replaced by rename (mode 0600) on each change.
//! qbd sees a capped login's count as its [`WINDOW`] window.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use qb_proto::{Usage, UsdSource, WindowReport};
use qb_vendors::rfc3339::days_in_month;
use serde::{Deserialize, Serialize};

use super::config::Price;
use crate::rewrite::write_atomic;

/// Name of the window a capped login's spend is reported as; its vendor declares it in qbd.
pub const WINDOW: &str = "spend";

/// The file's contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    /// Start of the month the counts belong to.
    period_start: u64,
    /// USD per login.
    spent_usd: BTreeMap<String, f64>,
}

/// The counts of the current month and the models already warned about as unpriced.
#[derive(Debug)]
pub struct Ledger {
    file: PathBuf,
    /// Start and end of the month the counts belong to.
    period: (u64, u64),
    spent: BTreeMap<String, f64>,
    unpriced: Vec<String>,
}

impl Ledger {
    /// The counts in `file` for the month of `now`; a missing file, or one of an earlier month,
    /// counts zero.
    ///
    /// # Errors
    /// The file cannot be read or is not a spend file.
    pub fn open(file: &Path, now: u64) -> Result<Self, String> {
        let period = month(now);
        let spent = match std::fs::read(file) {
            Ok(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{}: not a spend file: {e}", file.display()))?;
                if stored.period_start == period.0 {
                    stored.spent_usd
                } else {
                    BTreeMap::new()
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(format!("{}: {e}", file.display())),
        };
        Ok(Self {
            file: file.to_owned(),
            period,
            spent,
            unpriced: Vec::new(),
        })
    }

    /// Moves to the month of `now` once the counted one is over.
    fn roll(&mut self, now: u64) {
        if now >= self.period.1 {
            self.period = month(now);
            self.spent.clear();
        }
    }

    /// USD `login` spent in the month of `now`.
    pub fn spent(&mut self, login: &str, now: u64) -> f64 {
        self.roll(now);
        self.spent.get(login).copied().unwrap_or(0.0)
    }

    /// Unix time the month of `now` ends.
    pub fn period_end(&mut self, now: u64) -> u64 {
        self.roll(now);
        self.period.1
    }

    /// Adds `usd` to the count of `login` and writes the file. The count stays raised in memory
    /// when the write fails.
    ///
    /// # Errors
    /// The file could not be written.
    pub fn add(&mut self, login: &str, usd: f64, now: u64) -> Result<(), String> {
        self.roll(now);
        *self.spent.entry(login.to_owned()).or_insert(0.0) += usd;
        self.save()
    }

    /// Sets the count of `login` to zero and writes the file.
    ///
    /// # Errors
    /// The file could not be written.
    pub fn reset(&mut self, login: &str, now: u64) -> Result<(), String> {
        self.roll(now);
        self.spent.remove(login);
        self.save()
    }

    /// The [`WINDOW`] of `login` under `cap`: its count's fraction of the cap, at most 1, until
    /// the month ends.
    pub fn window(&mut self, login: &str, cap: f64, now: u64) -> WindowReport {
        WindowReport {
            name: WINDOW.to_owned(),
            utilization: (self.spent(login, now) / cap).min(1.0),
            resets_at: Some(self.period_end(now)),
            length_s: None,
        }
    }

    /// True the first time `model` is named, so an unpriced model is logged once per run.
    pub fn first_unpriced(&mut self, model: &str) -> bool {
        if self.unpriced.iter().any(|m| m == model) {
            return false;
        }
        self.unpriced.push(model.to_owned());
        true
    }

    fn save(&self) -> Result<(), String> {
        let stored = Stored {
            period_start: self.period.0,
            spent_usd: self.spent.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|e| e.to_string())?;
        write_atomic(&self.file, &bytes).map_err(|e| format!("{}: {e}", self.file.display()))
    }
}

/// USD of an attempt and where it comes from: the vendor's `cost`, else `usage` at `price`,
/// none counting as zero tokens; `None` without either.
pub fn attempt_usd(
    cost: Option<f64>,
    price: Option<&Price>,
    usage: Option<&Usage>,
) -> Option<(f64, UsdSource)> {
    match (cost, price) {
        (Some(usd), _) => Some((usd, UsdSource::Vendor)),
        (None, Some(price)) => Some((usage.map_or(0.0, |u| priced(u, price)), UsdSource::Prices)),
        (None, None) => None,
    }
}

/// USD of `usage` at `price`.
#[allow(clippy::cast_precision_loss)] // token counts stay far below 2^53
pub fn priced(usage: &Usage, price: &Price) -> f64 {
    let tokens = |n: u64, per_million: f64| n as f64 * per_million / 1_000_000.0;
    tokens(usage.input, price.input)
        + tokens(usage.output, price.output)
        + tokens(usage.cache_read, price.cache_read)
        + tokens(usage.cache_write, price.cache_write)
}

/// Start and end of the UTC calendar month holding `now`.
pub fn month(now: u64) -> (u64, u64) {
    // Hinnant's civil_from_days, on days since 0000-03-01; leap years repeat every 400 years,
    // so the era drops out.
    let days = now / 86_400;
    #[allow(clippy::cast_possible_truncation)] // a day of a 400-year era fits u32
    let doe = ((days + 719_468) % 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year_of_era = yoe + u32::from(month <= 2);
    let start = days - u64::from(day);
    let length = days_in_month(year_of_era, month);
    (start * 86_400, (start + u64::from(length)) * 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months_are_utc_calendar_months() {
        // 2024-02-01, 2024-03-01, 2025-01-01, 2026-01-01.
        let (feb, mar) = (1_706_745_600, 1_709_251_200);
        let (y2025, y2026) = (1_735_689_600, 1_767_225_600);
        assert_eq!(month(feb), (feb, mar), "a leap February");
        assert_eq!(month(mar - 1), (feb, mar));
        assert_eq!(month(0), (0, 31 * 86_400));
        let dec = y2026 - 31 * 86_400;
        assert_eq!(month(y2026 - 1), (dec, y2026));
        assert_eq!(month(y2025 + 86_400 * 40).0, y2025 + 86_400 * 31);
    }

    #[test]
    fn usage_is_priced_per_million_tokens() {
        let price = Price {
            model: "model-a".into(),
            input: 2.0,
            output: 10.0,
            cache_read: 0.5,
            cache_write: 4.0,
        };
        let usage = Usage {
            input: 1_000_000,
            output: 200_000,
            cache_read: 2_000_000,
            cache_write: 500_000,
        };
        assert!((priced(&usage, &price) - 7.0).abs() < 1e-9);
    }

    #[test]
    fn counts_persist_within_their_month_and_restart_from_zero_in_the_next() {
        let dir = std::env::temp_dir().join(format!("qb-spend-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("spend.json");
        let (start, end) = month(1_706_745_600);
        let mut ledger = Ledger::open(&file, start).unwrap();
        ledger.add("key-1", 1.25, start + 10).unwrap();
        ledger.add("key-1", 0.5, start + 20).unwrap();
        ledger.add("key-2", 3.0, start + 30).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&file).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let mut again = Ledger::open(&file, end - 1).unwrap();
        assert!((again.spent("key-1", end - 1) - 1.75).abs() < 1e-9);
        again.reset("key-2", end - 1).unwrap();
        assert_eq!(
            Ledger::open(&file, end - 1)
                .unwrap()
                .spent("key-2", end - 1),
            0.0
        );
        assert_eq!(
            again.spent("key-1", end),
            0.0,
            "a new month counts from zero"
        );
        assert_eq!(again.period_end(end), month(end).1);
        assert_eq!(Ledger::open(&file, end).unwrap().spent("key-1", end), 0.0);
        std::fs::write(&file, "{}").unwrap();
        let e = Ledger::open(&file, end).unwrap_err();
        assert!(e.contains("not a spend file"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
