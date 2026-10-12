//! Unpredictable values a client needs: masking keys (RFC 6455 section
//! 5.3) and the handshake nonce (section 4.1).
//!
//! Keys come from SHA-1 in counter mode over a 32-byte secret seed: each
//! digest of `seed || counter` yields five masking keys. With `std`, the
//! seed is drawn from the operating system's random source through the
//! standard library's `RandomState` (whose SipHash keys are seeded from the
//! OS random number generator), mixed with the clock. Without `std`, the
//! caller supplies the seed. The purpose of masking is that a peer cannot
//! predict the keys of frames it has not seen; it is not encryption. This
//! generator moves to the owner's random-number library once that library
//! is published (see `dev/ROADMAP.md`).

use crate::sha1::Sha1;

pub(crate) struct MaskGen {
    seed: [u8; 32],
    counter: u64,
    pool: [u8; 20],
    used: usize,
}

impl MaskGen {
    pub(crate) const fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            pool: [0; 20],
            used: 20,
        }
    }

    pub(crate) fn next_key(&mut self) -> [u8; 4] {
        if self.used + 4 > self.pool.len() {
            let mut h = Sha1::new();
            h.update(&self.seed);
            h.update(&self.counter.to_le_bytes());
            self.pool = h.finish();
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let k = [
            self.pool[self.used],
            self.pool[self.used + 1],
            self.pool[self.used + 2],
            self.pool[self.used + 3],
        ];
        self.used += 4;
        k
    }
}

/// A 32-byte seed from the operating system's random source.
#[cfg(feature = "std")]
pub(crate) fn os_seed() -> [u8; 32] {
    use std::{
        collections::hash_map::RandomState,
        hash::{BuildHasher, Hasher},
        time::{SystemTime, UNIX_EPOCH},
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut seed = [0u8; 32];
    for (i, chunk) in seed.chunks_exact_mut(8).enumerate() {
        // Every `RandomState::new` has fresh keys derived from the OS RNG.
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        h.write_u128(nanos);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    seed
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_mask_keys_are_deterministic_per_seed_and_distinct() {
        let mut a = MaskGen::new([1; 32]);
        let mut b = MaskGen::new([1; 32]);
        let mut c = MaskGen::new([2; 32]);
        let mut seen = BTreeSet::new();
        for _ in 0..10_000 {
            let k = a.next_key();
            assert_eq!(k, b.next_key());
            assert_ne!(k, c.next_key());
            let _ = seen.insert(k);
        }
        // 10,000 draws from 2^32 values: collisions are possible but rare.
        assert!(seen.len() > 9_980);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_os_seeds_differ() {
        assert_ne!(os_seed(), os_seed());
    }
}
