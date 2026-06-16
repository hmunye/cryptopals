use super::utils;

/// Table mapping bytes to their corresponding weighted score.
///
/// Control character (0-31, 127) are treated as a penalty, contributing -1 to
/// the score. Characters "etaoin shrdlu" are weighted in descending order
/// (14-2) based on most-frequent. All other printable ASCII characters
/// contribute 1 to the score.
const W_SCORE_TABLE: [i32; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 12, 1, 1, 4, 14, 1, 1, 6, 10, 1, 1, 3, 1, 9, 11, 1, 1, 5,
    7, 13, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
];

/// Decryption metadata for `single-key XOR`.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub key: char,
    pub score: i32,
}

/// Decrypts the given hex-encoded cipher, which has been XOR'd against a single
/// byte, returning a [`Metadata`] and plaintext pair.
///
/// A brute-force approach is used, enumerating the full keyspace `0x00..=0xFF`,
/// and scoring each candidate key based on the frequency of characters.
///
/// Returns `None` for `Metadata` when a key could not be found (e.g., empty
/// input).
///
/// # Panics
///
/// Panics if `input.len()` is not divisible by 2.
#[inline]
#[must_use]
pub fn decrypt_hex_xor_cipher(input: &[u8]) -> (Option<Metadata>, String) {
    let (chunks, remainder) = input.as_chunks::<2>();
    assert!(remainder.is_empty());

    let bytes: Vec<u8> = chunks
        .iter()
        .map(|nibbles| utils::decode_hex(*nibbles))
        .collect();

    decrypt_xor_cipher(&bytes)
}

/// Decrypts the given encrypted cipher, which has been XOR'd against a single
/// byte, returning a [`Metadata`] and plaintext pair.
///
/// A brute-force approach is used, enumerating the full keyspace `0x00..=0xFF`,
/// and scoring each candidate key based on the frequency of characters.
///
/// Returns `None` for `Metadata` when a key could not be found (e.g., empty
/// input).
#[must_use]
pub fn decrypt_xor_cipher(input: &[u8]) -> (Option<Metadata>, String) {
    let mut out = String::new();
    if input.is_empty() {
        return (None, out);
    }

    if let Some(meta) = find_candidate_key(input) {
        let key = meta.key as u8;

        for &b in input {
            out.push((b ^ key) as char);
        }

        (Some(meta), out)
    } else {
        (None, out)
    }
}

fn find_candidate_key(bytes: &[u8]) -> Option<Metadata> {
    let mut meta: Option<Metadata> = None;
    let keyspace = 0x00..=0xFF;

    for k in keyspace {
        let mut key_score: i32 = 0;

        for b in bytes {
            let i = b ^ k;

            if i as usize >= W_SCORE_TABLE.len() {
                // Penalize index not in the ASCII range (0-127).
                key_score -= 1;
            } else {
                key_score += W_SCORE_TABLE[i as usize];
            }
        }

        let m = meta.get_or_insert_default();

        if key_score > m.score {
            m.score = key_score;
            m.key = k as char;
        }
    }

    meta
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, BufRead};

    use super::*;

    #[test]
    fn test_decrypt_xor_cipher_empty() {
        let (meta, plaintext) = decrypt_xor_cipher(b"");

        assert_eq!(meta, None);
        assert_eq!(plaintext, "");
    }

    #[test]
    fn test_decrypt_xor_cipher_basic() {
        let (meta, plaintext) = decrypt_hex_xor_cipher(
            b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        );

        assert_eq!(meta.unwrap().key, 'X');
        assert_eq!(plaintext, "Cooking MC's like a pound of bacon");
    }

    // Challenge 1-4
    #[test]
    fn test_decrypt_xor_cipher_file() {
        let file = fs::File::open("encrypted_single_xor.txt").unwrap();
        let reader = io::BufReader::new(file);

        let mut candidate: Option<(Metadata, String)> = None;

        for line in reader.lines() {
            let line = line.unwrap();
            let bytes = line.as_bytes();

            let (metadata, plaintext) = decrypt_hex_xor_cipher(bytes);
            if let Some(mut meta) = metadata {
                // Normalize the score for the given bytes, so longer sequences
                // are not weighted more than shorter ones.
                meta.score /= (bytes.len() / 2) as i32;

                let c = candidate.get_or_insert_default();
                if meta.score > c.0.score {
                    *c = (meta, plaintext);
                }
            }
        }

        let candidate = candidate.unwrap();

        assert_eq!(candidate.0.key, '5');
        assert_eq!(candidate.1, "Now that the party is jumping\n");
    }
}
