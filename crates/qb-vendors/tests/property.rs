//! Property: every parser, fed random byte mutations of every fixture, returns without panicking,
//! and each window it returns has a non-empty name and a utilisation in `0.0..=1.0`.

mod common;

use common::{FIXTURES, NOW, SOURCES, fixture};

/// xorshift64*: deterministic, so a failing case reproduces from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }

    fn byte(&mut self) -> u8 {
        const INTERESTING: &[u8] = b"{}[]\":,.-+eE0159 nNtf\\\xff\x00";
        if self.index(2) == 0 {
            INTERESTING[self.index(INTERESTING.len())]
        } else {
            self.next().to_le_bytes()[0]
        }
    }
}

/// One random edit: flip, replace, insert or delete a byte, truncate, or duplicate a span.
fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    if input.is_empty() {
        input.push(rng.byte());
        return;
    }
    let at = rng.index(input.len());
    match rng.index(6) {
        0 => input[at] ^= 1 << rng.index(8),
        1 => input[at] = rng.byte(),
        2 => input.insert(at, rng.byte()),
        3 => {
            input.remove(at);
        }
        4 => input.truncate(at),
        _ => {
            let end = at + rng.index(input.len() - at + 1);
            let span = input[at..end].to_vec();
            let to = rng.index(input.len() + 1);
            input.splice(to..to, span);
        }
    }
}

#[test]
fn mutated_fixtures_never_panic_and_stay_in_range() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for (name, _) in FIXTURES {
        let original = fixture(name);
        for case in 0..400 {
            let mut input = original.clone();
            for _ in 0..=rng.index(4) {
                mutate(&mut rng, &mut input);
            }
            for source in SOURCES {
                let Ok(Some(parsed)) = source.parse(&input, NOW) else {
                    continue;
                };
                for w in &parsed.windows {
                    assert!(
                        !w.name.is_empty() && (0.0..=1.0).contains(&w.utilization),
                        "{name} case {case} {source:?}: {w:?} from {}",
                        String::from_utf8_lossy(&input)
                    );
                }
            }
        }
    }
}
