//! SHA-1 (RFC 3174), for the `Sec-WebSocket-Accept` computation and the
//! client's masking-key generator.
//!
//! RFC 6455 fixes SHA-1 for the handshake; it is used here as the protocol
//! requires, not as a security primitive. This module is private and moves
//! to the owner's crypto library once that library is published (see
//! `dev/ROADMAP.md`).

/// Streaming SHA-1 state.
#[derive(Clone)]
pub(crate) struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

impl Sha1 {
    pub(crate) const fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            let block = self.block;
            compress(&mut self.state, &block);
            self.filled = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            compress(&mut self.state, &b);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    pub(crate) fn finish(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-1 of `data` in one call.
#[cfg(test)]
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, word) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use super::*;

    fn hex(bytes: &[u8]) -> alloc::string::String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .map(|d| char::from(DIGITS[usize::from(d)]))
            .collect()
    }

    #[test]
    fn test_sha1_rfc3174_vectors() {
        // RFC 3174 section 7.3, TEST1 to TEST4, plus the empty message.
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million_a = alloc::vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&million_a)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        let test4: Vec<u8> =
            b"0123456701234567012345670123456701234567012345670123456701234567".repeat(10);
        assert_eq!(
            hex(&sha1(&test4)),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
    }

    #[test]
    fn test_sha1_padding_boundaries() {
        // Lengths around the 55/56/64-byte padding boundaries, against
        // values computed with an independent implementation (Python hashlib).
        let cases: &[(usize, &str)] = &[
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
        ];
        for (len, digest) in cases {
            assert_eq!(
                hex(&sha1(&alloc::vec![b'a'; *len])),
                *digest,
                "length {len}"
            );
        }
    }

    proptest! {
        #[test]
        fn prop_streaming_matches_one_shot(
            data in proptest::collection::vec(any::<u8>(), 0..400),
            cuts in proptest::collection::vec(any::<usize>(), 0..6),
        ) {
            let mut points: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
            points.sort_unstable();
            let mut h = Sha1::new();
            let mut last = 0;
            for p in points {
                h.update(&data[last..p]);
                last = p;
            }
            h.update(&data[last..]);
            prop_assert_eq!(h.finish(), sha1(&data));
        }
    }
}
