use super::utils;

/// Table mapping bytes to their corresponding weighted score.
///
/// Control character (0-31, 127) are penalized, contributing -1 to the score.
/// Characters "etaoin shrdlu" are weighted in descending order (14-2) based on
/// frequency. All other printable ASCII characters contribute 1 to the score.
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
    pub key: u8,
    pub score: i32,
}

/// Decrypts the given hex-encoded ciphertext, which has been XOR'd against a
/// single byte, returning a [`Metadata`] and plaintext pair, or `None` if a key
/// could not be found (e.g., empty input).
///
/// Brute-force approach is used, enumerating the full keyspace `0x00..=0xFF`,
/// and scoring each candidate key based on the frequency of characters.
#[inline]
#[must_use]
pub fn decrypt_hex_xor_cipher(hex: &[u8]) -> Option<(Metadata, Vec<u8>)> {
    decrypt_xor_cipher(&utils::hex_to_bytes(hex))
}

/// Decrypts the given ciphertext, which has been XOR'd against a single byte,
/// returning a [`Metadata`] and plaintext pair, or `None` if a key could not be
/// found (e.g., empty input).
///
/// Brute-force approach is used, enumerating the full keyspace `0x00..=0xFF`,
/// and scoring each candidate key based on the frequency of characters.
#[must_use]
pub fn decrypt_xor_cipher(ciphertext: &[u8]) -> Option<(Metadata, Vec<u8>)> {
    if ciphertext.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(ciphertext.len());

    find_candidate_metadata(ciphertext).map(|meta| {
        for &b in ciphertext {
            out.push(b ^ meta.key);
        }

        (meta, out)
    })
}

fn find_candidate_metadata(ciphertext: &[u8]) -> Option<Metadata> {
    let mut meta: Option<Metadata> = None;
    let keyspace = 0x00..=0xFF;

    for k in keyspace {
        let mut key_score: i32 = 0;

        for b in ciphertext {
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
            m.key = k;
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
        assert!(decrypt_xor_cipher(b"").is_none());
    }

    // Challenge 1-3
    #[test]
    fn test_decrypt_xor_cipher_basic() {
        let (meta, plaintext) = decrypt_hex_xor_cipher(
            b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        )
        .unwrap();

        assert_eq!(meta.key, b'X');
        assert_eq!(plaintext, b"Cooking MC's like a pound of bacon");
    }

    // Challenge 1-4
    #[test]
    fn test_decrypt_xor_cipher_file() {
        let file = fs::File::open("encrypted_single_xor.txt").unwrap();
        let reader = io::BufReader::new(file);

        let mut candidate: Option<(Metadata, Vec<u8>)> = None;

        for line in reader.lines() {
            let line = line.unwrap();
            let bytes = line.as_bytes();

            let (mut meta, plaintext) = decrypt_hex_xor_cipher(bytes).unwrap();

            // Normalize the score for the given bytes, so longer sequences are
            // not weighted more than shorter ones.
            meta.score /= (bytes.len() / 2) as i32;

            let c = candidate.get_or_insert_default();
            if meta.score > c.0.score {
                *c = (meta, plaintext);
            }
        }

        let candidate = candidate.unwrap();

        assert_eq!(candidate.0.key, b'5');
        assert_eq!(candidate.1, b"Now that the party is jumping\n");
    }
}
