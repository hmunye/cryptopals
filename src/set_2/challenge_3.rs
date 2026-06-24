use std::collections::HashSet;

use crate::bindings::{getrandom, rand};
use crate::set_1::challenge_7::{AES_BLOCK_SIZE, encrypt_aes_ecb_128};
use crate::set_2::challenge_2::encrypt_aes_cbc_128;

pub fn run() {
    let mut correct = 0;
    let input = "a".repeat(43);

    let mut set: HashSet<[u8; 16]> = HashSet::new();

    for _ in 0..100 {
        let (output, mode) = encryption_oracle(input.as_bytes());

        let (blocks, _) = output.as_chunks::<16>();
        let len = blocks.len();

        set.extend(blocks.iter());

        let guess = if len - set.len() > 0 {
            Mode::ECB
        } else {
            Mode::CBC
        };

        if guess == mode {
            correct += 1;
        }

        set.clear();
    }

    crate::print_challenge(
        3,
        "An ECB/CBC detection oracle",
        &["minimum plaintext length required: 43 bytes"],
        &[&format!(
            "detection rate: {correct} / 100 ({}%)",
            100.0 * f64::from(correct) / 100.0
        )],
    );
}

/// Returns a `KEY_SIZE`-byte, cryptographically secure random key.
#[inline]
#[must_use]
pub fn rand_key<const KEY_SIZE: usize>() -> [u8; KEY_SIZE] {
    let mut buf = [0u8; KEY_SIZE];
    unsafe {
        getrandom(buf.as_mut_ptr().cast(), KEY_SIZE, 0);
    }

    buf
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    ECB,
    CBC,
}

/// Encrypts the given plaintext using either `AES-ECB` or `AES-CBC`, returning
/// the ciphertext and mode used for encryption.
///
/// A random key/IV is generated internally per-call, with 5–10 bytes also being
/// prefixed/suffixed to the plaintext before encryption.
#[must_use]
pub fn encryption_oracle(plaintext: &[u8]) -> (Vec<u8>, Mode) {
    unsafe {
        let key = rand_key::<16>();
        #[allow(clippy::cast_sign_loss)]
        let p_count = ((rand() % 6) + 5) as usize;
        #[allow(clippy::cast_sign_loss)]
        let s_count = ((rand() % 6) + 5) as usize;

        let mut p = vec![0u8; p_count];
        getrandom(p.as_mut_ptr().cast(), p_count, 0);

        let mut s = vec![0u8; s_count];
        getrandom(s.as_mut_ptr().cast(), s_count, 0);

        let updated = p
            .iter()
            .copied()
            .chain(plaintext.iter().copied())
            .chain(s.iter().copied())
            .collect::<Vec<_>>();

        match rand() % 2 {
            0 => (encrypt_aes_ecb_128(&updated, &key), Mode::ECB),
            1 => {
                let mut iv = [0u8; AES_BLOCK_SIZE];
                getrandom(iv.as_mut_ptr().cast(), AES_BLOCK_SIZE, 0);

                (encrypt_aes_cbc_128(&updated, &key, &iv), Mode::CBC)
            }
            _ => unreachable!(),
        }
    }
}
