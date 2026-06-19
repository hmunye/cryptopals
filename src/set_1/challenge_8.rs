use std::collections::HashSet;
use std::io::{self, BufRead};
use std::{fs, mem, str};

use crate::utils;

pub fn run() {
    let ciphers = fs::File::open("detect_aes_ecb.txt").unwrap();
    let reader = io::BufReader::new(ciphers);

    let meta = detect_aes_ecb(reader);
    let ciphertext = utils::bytes_to_hex(&meta.cipher);

    let output = str::from_utf8(&ciphertext).unwrap();
    assert_eq!(meta.dups, 3);
    assert_eq!(
        output,
        "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    );

    crate::print_challenge(
        8,
        "Detect AES in ECB mode",
        &["file: detect_aes_ecb.txt"],
        &[
            &format!("duplicate blocks: {}", meta.dups),
            &format!("ciphertext: {output}"),
        ],
    );
}

/// Metadata for `AES-ECB` detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub cipher: Vec<u8>,
    pub dups: usize,
}

/// Returns the [`Metadata`] of the ciphertext from the provided IO reader which
/// has been hex-encoded and encrypted with [`AES-ECB`].
///
/// # Panics
///
/// Panics if an I/O error is encountered.
///
/// [`AES-ECB`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
#[must_use]
pub fn detect_aes_ecb(reader: io::BufReader<fs::File>) -> Metadata {
    let mut meta = Metadata::default();
    let mut set: HashSet<[u8; 16]> = HashSet::new();

    for line in reader.lines() {
        let line = utils::hex_to_bytes(line.unwrap().as_bytes());

        let (blocks, _) = line.as_chunks::<16>();
        let len = blocks.len();

        set.extend(blocks.iter());

        if len - set.len() > meta.dups {
            meta.dups = len - set.len();
            let _ = mem::replace(&mut meta.cipher, line);
        }

        set.clear();
    }

    meta
}
