use super::utils;

/// Table mapping bytes to their corresponding score.
///
/// Control character (0-31, 127) are treated as a penalty, contributing -1 to
/// the score. Characters "etaoin shrdlu" are weighted in descending order
/// (14-2) based on frequency. All other printable ASCII characters contribute
/// 1 to the score.
const SCORE_TABLE: [i32; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 12, 1, 1, 4, 14, 1, 1, 6, 10, 1, 1, 3, 1, 9, 11, 1, 1, 5,
    7, 13, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
];

/// Decrypts the given cipher (hexadecimal), which has been XOR'd against a
/// single ASCII character, returning the key and plaintext pair. '\0' as the
/// key indicates it could not be found (e.g., empty input).
#[inline]
#[must_use]
pub fn decrypt_xor_cipher(input: &[u8]) -> (char, String) {
    let mut out = String::new();
    let mut final_key = b'\0';
    let mut final_score: i32 = 0;

    if input.is_empty() {
        return (final_key as char, out);
    }

    let (chunks, _) = input.as_chunks::<2>();

    for key in (b'a'..=b'z').chain(b'A'..=b'Z') {
        let mut key_score: i32 = 0;

        for &[x, y] in chunks {
            let byte = (utils::decode_hex(x) << 4) | utils::decode_hex(y);
            let i = byte ^ key;

            key_score += SCORE_TABLE[i as usize];
        }

        if key_score > final_score {
            final_score = key_score;
            final_key = key;
        }
    }

    for &[x, y] in chunks {
        let byte = (utils::decode_hex(x) << 4) | utils::decode_hex(y);
        out.push((byte ^ final_key) as char);
    }

    (final_key as char, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_xor_cipher_empty() {
        let (key, plaintext) = decrypt_xor_cipher(b"");

        assert_eq!(key, '\0');
        assert_eq!(plaintext, "");
    }

    #[test]
    fn test_decrypt_xor_cipher_basic() {
        let (key, plaintext) = decrypt_xor_cipher(
            b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        );

        assert_eq!(key, 'X');
        assert_eq!(plaintext, "Cooking MC's like a pound of bacon");
    }
}
