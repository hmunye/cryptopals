use super::utils;

/// Table listing the characters used for each numeric value, per [RFC 4648].
///
/// [RFC 4648]: https://datatracker.ietf.org/doc/html/rfc4648#section-4
const LOOKUP_TABLE: &[char; 64] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

/// Converts the given hexadecimal byte slice to a [`base64`] encoded string. To
/// indicate padding, `=` bytes are appended to the output string.
///
/// `base64` is a binary-to-text encoding scheme that uses 64 printable
/// characters to represent each 6-bit segment of a sequence of byte values.
///
/// [`base64`]: https://en.wikipedia.org/wiki/Base64
#[inline]
#[must_use]
pub fn hex_to_b64(input: &[u8]) -> String {
    let mut out = String::with_capacity(4 * input.len().div_ceil(6));
    let mut rem = 0;
    let mut bits = 0;

    let (chunks, remainder) = input.as_chunks::<2>();

    for &[x, y] in chunks {
        let byte = (utils::decode_hex(x) << 4) | utils::decode_hex(y);

        let seq = if bits == 0 {
            rem = byte & 0x03;
            bits = 2;

            (byte & (0xFF << 2)) >> 2
        } else {
            let n = 6 - bits;

            if n == 0 {
                out.push(LOOKUP_TABLE[rem as usize]);
                rem = byte & 0x03;
                bits = 2;

                (byte & (0xFF << 2)) >> 2
            } else {
                let curr = byte >> (u8::BITS - n);
                let s = curr | (rem << n);

                rem = (byte << n) >> n;
                bits = u8::BITS - n;

                s
            }
        };

        out.push(LOOKUP_TABLE[seq as usize]);
    }

    if rem != 0 {
        let byte = rem << (6 - bits);
        out.push(LOOKUP_TABLE[byte as usize]);
    }

    for &r in remainder {
        out.push(LOOKUP_TABLE[utils::decode_hex(r) as usize]);
    }

    let padding = input.len() % 3;
    out.push_str(&"=".repeat(padding));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_empty() {
        assert_eq!(hex_to_b64(b""), "");
    }

    #[test]
    fn test_hex_sentence() {
        let input = b"5468697320697320612074657374";
        assert_eq!(hex_to_b64(input), "VGhpcyBpcyBhIHRlc3Q=");
    }

    #[test]
    fn test_hex_all_bytes_sequence() {
        let input = b"00010203040506070809";
        assert_eq!(hex_to_b64(input), "AAECAwQFBgcICQ==");
    }

    #[test]
    fn test_hex_no_padding() {
        let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(
            hex_to_b64(input),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_hex_one_byte() {
        assert_eq!(hex_to_b64(b"66"), "Zg==");
    }

    #[test]
    fn test_hex_two_bytes() {
        assert_eq!(hex_to_b64(b"666f"), "Zm8=");
    }

    #[test]
    fn test_hex_three_bytes() {
        assert_eq!(hex_to_b64(b"666f6f"), "Zm9v");
    }

    #[test]
    fn test_hex_four_bytes() {
        assert_eq!(hex_to_b64(b"666f6f66"), "Zm9vZg==");
    }
}
