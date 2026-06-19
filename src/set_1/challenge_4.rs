use std::io::{self, BufRead};
use std::{fs, str};

use crate::set_1::challenge_3::{Metadata, decrypt_xor_cipher};
use crate::utils;

pub fn run() {
    let file = fs::File::open("encrypted_single_xor.txt").unwrap();
    let reader = io::BufReader::new(file);

    let mut c: (Metadata, Vec<u8>) = Default::default();

    for line in reader.lines() {
        let line = line.unwrap();
        let len = line.len();

        let (mut meta, plaintext) =
            decrypt_xor_cipher(&utils::hex_to_bytes(line.as_bytes())).unwrap();

        // Normalize the score for the given hex-encoded bytes, so longer
        // sequences are not weighted more than shorter ones.
        meta.score /= (len / 2) as i32;

        if meta.score > c.0.score {
            c = (meta, plaintext);
        }
    }

    assert_eq!(c.0.key, b'5');
    assert_eq!(c.1, b"Now that the party is jumping\n");

    crate::print_challenge(
        4,
        "Detect single-character XOR",
        &["file: encrypted_single_xor.txt"],
        &[
            &format!("key: {:?}", c.0.key as char),
            &format!("plaintext: {}", str::from_utf8(&c.1).unwrap()),
        ],
    );
}
