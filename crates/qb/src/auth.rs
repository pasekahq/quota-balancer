//! Who is calling and whether they may call now: bearer or peer uid to a configured client,
//! then that client's token bucket. The order is described in `docs/api.md`.

use std::time::Instant;

use crate::api::Caller;
use crate::config::{BearerHash, Client, Limits};
use crate::sha256;

/// Most buckets kept when no clients are declared and callers are keyed by uid.
pub const MAX_UID_BUCKETS: usize = 64;

/// Whether `token` hashes to `hash`, compared in constant time.
pub fn token_matches(token: &str, hash: &BearerHash) -> bool {
    sha256::ct_eq(&sha256::digest(token.as_bytes()), &hash.0)
}

/// Why a request is refused before routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The bearer or the peer uid names no configured client.
    Unauthorized,
    /// The caller's bucket is empty.
    TooManyRequests,
}

/// Identification and rate limiting for the daemon loop.
#[derive(Debug)]
pub struct Gate {
    clients: Vec<Client>,
    rate_per_s: f64,
    burst: f64,
    cap: usize,
    buckets: Vec<(String, Bucket)>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Gate {
    /// A gate for the configured `clients`, each held to `limits`.
    pub fn new(clients: &[Client], limits: &Limits) -> Self {
        let cap = if clients.is_empty() {
            MAX_UID_BUCKETS
        } else {
            clients.len()
        };
        Self {
            clients: clients.to_vec(),
            rate_per_s: limits.rate_per_s,
            burst: f64::from(limits.burst),
            cap,
            buckets: Vec::with_capacity(cap),
        }
    }

    /// The caller behind `bearer` or else peer `uid`, charged one token at monotonic `now`.
    ///
    /// # Errors
    /// [`Denied::Unauthorized`] without a matching client, before any bucket is touched;
    /// [`Denied::TooManyRequests`] when the caller's bucket is empty.
    pub fn admit(
        &mut self,
        uid: Option<u32>,
        bearer: Option<&str>,
        now: Instant,
    ) -> Result<Caller, Denied> {
        let caller = self.identify(uid, bearer).ok_or(Denied::Unauthorized)?;
        if self.take(&caller.client, now) {
            Ok(caller)
        } else {
            Err(Denied::TooManyRequests)
        }
    }

    fn identify(&self, uid: Option<u32>, bearer: Option<&str>) -> Option<Caller> {
        let name = if let Some(token) = bearer {
            // Every configured hash is compared so the time does not depend on which one matches.
            let mut found = None;
            for c in &self.clients {
                if let Some(h) = &c.bearer_sha256 {
                    if token_matches(token, h) {
                        found = Some(&c.name);
                    }
                }
            }
            found?.clone()
        } else if self.clients.is_empty() {
            format!("uid:{}", uid?)
        } else {
            let uid = uid?;
            self.clients
                .iter()
                .find(|c| c.uid == Some(uid))?
                .name
                .clone()
        };
        Some(Caller { client: name })
    }

    fn take(&mut self, key: &str, now: Instant) -> bool {
        let i = if let Some(i) = self.buckets.iter().position(|(k, _)| k == key) {
            i
        } else {
            let fresh = Bucket {
                tokens: self.burst,
                at: now,
            };
            if self.buckets.len() < self.cap {
                self.buckets.push((key.to_owned(), fresh));
                self.buckets.len() - 1
            } else {
                // The fullest bucket is closest to a fresh one, so dropping it loses the least.
                let i = self
                    .buckets
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| self.level(a.1, now).total_cmp(&self.level(b.1, now)))
                    .map_or(0, |(i, _)| i);
                self.buckets[i] = (key.to_owned(), fresh);
                i
            }
        };
        let tokens = self.level(self.buckets[i].1, now);
        let bucket = &mut self.buckets[i].1;
        bucket.at = now;
        if tokens >= 1.0 {
            bucket.tokens = tokens - 1.0;
            true
        } else {
            bucket.tokens = tokens;
            false
        }
    }

    fn level(&self, b: Bucket, now: Instant) -> f64 {
        let refill = now.saturating_duration_since(b.at).as_secs_f64() * self.rate_per_s;
        (b.tokens + refill).min(self.burst)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn client(name: &str, uid: Option<u32>, token: Option<&str>) -> Client {
        Client {
            name: name.into(),
            uid,
            bearer_sha256: token.map(|t| BearerHash(sha256::digest(t.as_bytes()))),
            role: Some("worker".into()),
        }
    }

    fn limits(rate_per_s: f64, burst: u32) -> Limits {
        Limits { rate_per_s, burst }
    }

    fn name(r: Result<Caller, Denied>) -> Result<String, Denied> {
        r.map(|c| c.client)
    }

    #[test]
    fn bearer_wins_over_uid_and_must_match() {
        let clients = [
            client("client-a", Some(1001), None),
            client("client-b", Some(1002), Some("token-b")),
        ];
        let mut gate = Gate::new(&clients, &limits(5.0, 20));
        let now = Instant::now();
        let cases = [
            (Some(1001), None, Ok("client-a")),
            (Some(1001), Some("token-b"), Ok("client-b")),
            (None, Some("token-b"), Ok("client-b")),
            (Some(1001), Some("token-x"), Err(Denied::Unauthorized)),
            (Some(7), None, Err(Denied::Unauthorized)),
            (None, None, Err(Denied::Unauthorized)),
        ];
        for (uid, bearer, expected) in cases {
            assert_eq!(
                name(gate.admit(uid, bearer, now)),
                expected.map(str::to_owned),
                "{uid:?} {bearer:?}"
            );
        }
    }

    #[test]
    fn without_clients_every_uid_is_its_own_caller() {
        let mut gate = Gate::new(&[], &limits(5.0, 20));
        let now = Instant::now();
        assert_eq!(name(gate.admit(Some(42), None, now)), Ok("uid:42".into()));
        assert_eq!(
            name(gate.admit(Some(42), Some("token"), now)),
            Err(Denied::Unauthorized)
        );
        assert_eq!(name(gate.admit(None, None, now)), Err(Denied::Unauthorized));
    }

    #[test]
    fn bucket_drains_and_refills_per_client() {
        let clients = [
            client("client-a", Some(1), None),
            client("client-b", Some(2), None),
        ];
        let mut gate = Gate::new(&clients, &limits(2.0, 3));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(gate.admit(Some(1), None, t0).is_ok());
        }
        assert_eq!(
            name(gate.admit(Some(1), None, t0)),
            Err(Denied::TooManyRequests)
        );
        assert!(gate.admit(Some(9), None, t0).is_err());
        assert!(gate.admit(Some(2), None, t0).is_ok(), "own bucket");
        let half = t0 + Duration::from_millis(500);
        assert!(gate.admit(Some(1), None, half).is_ok(), "one token back");
        assert!(gate.admit(Some(1), None, half).is_err());
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(gate.admit(Some(1), None, later).is_ok());
        }
        assert!(gate.admit(Some(1), None, later).is_err(), "capped at burst");
    }

    #[test]
    fn uid_table_is_bounded_and_keeps_drained_buckets() {
        let mut gate = Gate::new(&[], &limits(1.0, 2));
        let t0 = Instant::now();
        assert!(gate.admit(Some(0), None, t0).is_ok());
        assert!(gate.admit(Some(0), None, t0).is_ok());
        for uid in 1..=u32::try_from(MAX_UID_BUCKETS).expect("small") * 2 {
            assert!(gate.admit(Some(uid), None, t0).is_ok());
        }
        assert!(gate.buckets.len() <= MAX_UID_BUCKETS);
        assert_eq!(
            name(gate.admit(Some(0), None, t0)),
            Err(Denied::TooManyRequests),
            "new uids evict fuller buckets first"
        );
    }
}
