use std::collections::HashSet;
use std::io::{self, BufRead};
use std::{fs, mem};

use super::utils;

/// Returns the ciphertext from the provided reader which has been hex-encoded
/// and encrypted with [`AES-ECB`].
///
/// # Panics
///
/// Panics if an I/O error is encountered.
///
/// [`AES-ECB`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
#[must_use]
pub fn detect_aes_ecb(reader: io::BufReader<fs::File>) -> Vec<u8> {
    let mut cipher = Vec::new();
    let mut dups = 0;

    let mut set: HashSet<[u8; 16]> = HashSet::new();

    for line in reader.lines() {
        let line = utils::hex_to_bytes(line.unwrap().as_bytes());

        let (blocks, _) = line.as_chunks::<16>();
        let len = blocks.len();

        set.extend(blocks.iter());

        if len - set.len() > dups {
            dups = len - set.len();
            let _ = mem::replace(&mut cipher, line);
        }

        set.clear();
    }

    cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    // Challenge 1-8
    #[test]
    fn test_detect_aes_ecb_file() {
        let ciphers = fs::File::open("detect_aes_ecb.txt").unwrap();
        let reader = io::BufReader::new(ciphers);

        assert_eq!(
            utils::bytes_to_hex(&detect_aes_ecb(reader)),
            b"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
        );
    }
}
