/// Encrypts the given plaintext with the provided key using `repeating-key XOR`,
/// returning its raw byte vector representation.
///
/// In `repeating-key XOR`, each byte of the key is sequentially applied; the
/// first byte of plaintext will be XOR'd against `key[0]`, the next `key[1]`,
/// etc., wrapping around to `key[0]` if necessary.
#[inline]
#[must_use]
pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len());

    let mut k = 0;
    for &byte in plaintext {
        out.push(byte ^ key[k]);
        k = (k + 1) % key.len();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{super::utils, *};

    // Challenge 1-5
    #[test]
    fn test_repeating_xor_basic() {
        assert_eq!(
            utils::bytes_to_hex(&repeating_xor(
                b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
                b"ICE",
            )),
            b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
