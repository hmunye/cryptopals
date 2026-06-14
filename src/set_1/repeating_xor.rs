use super::utils;

/// Encrypts the plaintext with the provided key using `repeating-key XOR`,
/// returning its hexadecimal string representation.
///
/// In `repeating-key XOR`, each byte of the key is sequentially applied; the
/// first byte of plaintext will be XOR'd against `key[0]`, the next `key[1]`,
/// etc., wrapping around to `key[0]` if required.
#[inline]
#[must_use]
pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> String {
    let mut out = Vec::new();

    let mut k = 0;
    for &byte in plaintext {
        out.push(byte ^ key[k]);
        k = (k + 1) % key.len();
    }

    utils::encode_to_hex_string(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repeating_xor_basic() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        assert_eq!(
            repeating_xor(plaintext.as_bytes(), b"ICE"),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
