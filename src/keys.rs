//! Unpredictable values a client needs: masking keys (RFC 6455 section
//! 5.3) and the handshake nonce (section 4.1).
//!
//! Two key sources, chosen at construction:
//!
//! - **The OS, in batches** (feature `std`, `Connection::client`): keys are
//!   read from the operating system's cryptographic random source through
//!   `mod-rand`'s OS tier (`getrandom`, `getentropy`, `BCryptGenRandom`, or
//!   `/dev/urandom`), 1 KiB (256 keys) per refill, about 1.4 ns per key on
//!   Windows x86_64. The batch lives on the heap, so an idle connection can
//!   release it. A refill that fails refuses the send; there is never a
//!   weaker fallback.
//! - **A caller seed** (`Connection::client_with_seed`, `no_std`, tests):
//!   SHA-1 in counter mode over the 32-byte secret seed, five keys per
//!   digest, deterministic for a given seed.
//!
//! The purpose of masking is that a peer cannot predict the keys of frames
//! it has not seen; it is not encryption.

#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::sha1::Sha1;

/// Keys drawn from the OS per refill: 256 keys.
#[cfg(feature = "std")]
const OS_BATCH: usize = 1024;

pub(crate) enum MaskGen {
    /// SHA-1 counter mode over a caller seed.
    Derived {
        seed: [u8; 32],
        counter: u64,
        pool: [u8; 20],
        used: usize,
    },
    /// Batches from the OS cryptographic source.
    #[cfg(feature = "std")]
    Os { pool: Vec<u8>, used: usize },
}

impl MaskGen {
    pub(crate) const fn new(seed: [u8; 32]) -> Self {
        Self::Derived {
            seed,
            counter: 0,
            pool: [0; 20],
            used: 20,
        }
    }

    /// Keys from the OS, the first batch drawn now so a failing source is
    /// reported at construction. `None` when the source fails.
    #[cfg(feature = "std")]
    pub(crate) fn from_os() -> Option<Self> {
        let mut pool = alloc::vec![0u8; OS_BATCH];
        mod_rand::tier3::fill_bytes(&mut pool).ok()?;
        Some(Self::Os { pool, used: 0 })
    }

    /// Overwrites the secret state and the unused keys with zeros.
    pub(crate) fn wipe(&mut self) {
        match self {
            Self::Derived {
                seed, pool, used, ..
            } => {
                *seed = [0; 32];
                *pool = [0; 20];
                *used = pool.len();
                let _ = core::hint::black_box(seed);
                let _ = core::hint::black_box(pool);
            }
            #[cfg(feature = "std")]
            Self::Os { pool, used } => {
                pool.iter_mut().for_each(|b| *b = 0);
                *used = pool.len();
                let _ = core::hint::black_box(pool);
            }
        }
    }

    /// Frees an OS batch; the next key refills it.
    pub(crate) fn release(&mut self) {
        #[cfg(feature = "std")]
        if let Self::Os { pool, used } = self {
            pool.iter_mut().for_each(|b| *b = 0);
            *pool = Vec::new();
            *used = 0;
        }
    }

    /// Heap bytes held.
    pub(crate) fn heap(&self) -> usize {
        match self {
            Self::Derived { .. } => 0,
            #[cfg(feature = "std")]
            Self::Os { pool, .. } => pool.capacity(),
        }
    }

    /// The next key, or `None` when the OS source fails on a refill.
    pub(crate) fn next_key(&mut self) -> Option<[u8; 4]> {
        match self {
            Self::Derived {
                seed,
                counter,
                pool,
                used,
            } => {
                if *used + 4 > pool.len() {
                    let mut h = Sha1::new();
                    h.update(seed.as_slice());
                    h.update(&counter.to_le_bytes());
                    *pool = h.finish();
                    *counter = counter.wrapping_add(1);
                    *used = 0;
                }
                let k = take4(pool, *used);
                *used += 4;
                Some(k)
            }
            #[cfg(feature = "std")]
            Self::Os { pool, used } => {
                if *used + 4 > pool.len() {
                    if pool.len() < OS_BATCH {
                        pool.resize(OS_BATCH, 0);
                    }
                    mod_rand::tier3::fill_bytes(pool).ok()?;
                    *used = 0;
                }
                let k = take4(pool, *used);
                // Each key is used once: clear it from the batch.
                if let Some(spent) = pool.get_mut(*used..*used + 4) {
                    spent.fill(0);
                }
                *used += 4;
                Some(k)
            }
        }
    }
}

fn take4(pool: &[u8], at: usize) -> [u8; 4] {
    let mut k = [0u8; 4];
    if let Some(src) = pool.get(at..at + 4) {
        k.copy_from_slice(src);
    }
    k
}

/// A 32-byte seed from the operating system's cryptographic random
/// source, or `None` when that source fails.
#[cfg(all(feature = "std", test))]
pub(crate) fn os_seed() -> Option<[u8; 32]> {
    let mut seed = [0u8; 32];
    mod_rand::tier3::fill_bytes(&mut seed).ok()?;
    Some(seed)
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_mask_keys_same_seed_deterministic_and_distinct() {
        let mut a = MaskGen::new([1; 32]);
        let mut b = MaskGen::new([1; 32]);
        let mut c = MaskGen::new([2; 32]);
        let mut seen = BTreeSet::new();
        for _ in 0..10_000 {
            let k = a.next_key().unwrap();
            assert_eq!(Some(k), b.next_key());
            assert_ne!(Some(k), c.next_key());
            let _ = seen.insert(k);
        }
        // 10,000 draws from 2^32 values: collisions are possible but rare.
        assert!(seen.len() > 9_980);
    }

    #[cfg(feature = "std")]
    #[cfg(feature = "std")]
    #[test]
    fn test_os_keys_distinct_across_refills() {
        let mut g = MaskGen::from_os().unwrap();
        let mut seen = BTreeSet::new();
        for _ in 0..2_000 {
            let _ = seen.insert(g.next_key().unwrap());
        }
        assert!(seen.len() > 1_990);
        assert_eq!(g.heap(), OS_BATCH);
        g.release();
        assert_eq!(g.heap(), 0);
        assert!(g.next_key().is_some());
        g.wipe();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_os_seed_two_draws_differ() {
        let (a, b) = (os_seed().unwrap(), os_seed().unwrap());
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
