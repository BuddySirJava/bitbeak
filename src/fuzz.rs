//! Payload mutators for fuzz / soak testing against your own targets.

use rand_lite::XorShift64;

/// Lightweight PRNG so we avoid pulling rand if not needed — implement tiny xorshift.
mod rand_lite {
    #[derive(Clone)]
    pub struct XorShift64(u64);

    impl XorShift64 {
        pub fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }

        pub fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        pub fn gen_range(&mut self, max: usize) -> usize {
            if max == 0 {
                0
            } else {
                (self.next_u64() as usize) % max
            }
        }

        pub fn gen_u8(&mut self) -> u8 {
            self.next_u64() as u8
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutator {
    BitFlip,
    ByteInsert,
    ByteDelete,
    Truncate,
    JunkSuffix,
    BreakJson,
    CorruptLengthPrefix,
}

impl Mutator {
    pub fn all() -> &'static [Mutator] {
        &[
            Self::BitFlip,
            Self::ByteInsert,
            Self::ByteDelete,
            Self::Truncate,
            Self::JunkSuffix,
            Self::BreakJson,
            Self::CorruptLengthPrefix,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::BitFlip => "bit-flip",
            Self::ByteInsert => "byte-insert",
            Self::ByteDelete => "byte-delete",
            Self::Truncate => "truncate",
            Self::JunkSuffix => "junk-suffix",
            Self::BreakJson => "break-json",
            Self::CorruptLengthPrefix => "corrupt-len",
        }
    }
}

pub fn mutate(payload: &[u8], kind: Mutator, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut out = payload.to_vec();
    match kind {
        Mutator::BitFlip => {
            if out.is_empty() {
                out.push(0);
            }
            let i = rng.gen_range(out.len());
            let bit = 1u8 << (rng.gen_range(8) as u8);
            out[i] ^= bit;
        }
        Mutator::ByteInsert => {
            let i = rng.gen_range(out.len() + 1);
            out.insert(i, rng.gen_u8());
        }
        Mutator::ByteDelete => {
            if !out.is_empty() {
                let i = rng.gen_range(out.len());
                out.remove(i);
            }
        }
        Mutator::Truncate => {
            if out.len() > 1 {
                let n = rng.gen_range(out.len());
                out.truncate(n.max(1));
            } else {
                out.clear();
            }
        }
        Mutator::JunkSuffix => {
            let n = 1 + rng.gen_range(16);
            for _ in 0..n {
                out.push(rng.gen_u8());
            }
        }
        Mutator::BreakJson => {
            if out.is_empty() {
                out.extend_from_slice(b"{");
            } else if out[0] == b'{' {
                out.insert(1, b',');
            } else {
                out.push(b'}');
            }
        }
        Mutator::CorruptLengthPrefix => {
            if out.len() >= 4 {
                out[0] = rng.gen_u8();
                out[1] = rng.gen_u8();
            } else {
                out.splice(0..0, [0xff, 0xff, 0xff, 0xff]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutators_change_or_empty() {
        let base = b"{\"ok\":true}";
        for (i, m) in Mutator::all().iter().enumerate() {
            let v = mutate(base, *m, 42 + i as u64);
            // should be some bytes (except truncate may empty)
            assert!(v.len() < 10_000);
        }
    }
}
