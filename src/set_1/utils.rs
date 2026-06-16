/// Table listing the characters used for each `Base64` numeric value, per
/// [RFC 4648].
///
/// [RFC 4648]: https://datatracker.ietf.org/doc/html/rfc4648#section-4
const B64_TABLE: &[char; 64] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

/// Converts the given hex-encoded byte slice to a [`Base64`]-encoded string. To
/// indicate padding, `'='` bytes are appended to the output string.
///
/// `Base64` is a binary-to-text encoding scheme that uses 64 printable
/// characters to represent each 6-bit segment of a sequence of byte values.
///
/// [`Base64`]: https://en.wikipedia.org/wiki/Base64
#[must_use]
pub fn hex_to_b64(input: &[u8]) -> String {
    let mut out = String::with_capacity(4 * input.len().div_ceil(6));
    let mut rem = 0;
    let mut bits = 0;

    let (chunks, remainder) = input.as_chunks::<2>();

    for nibbles in chunks {
        let byte = decode_hex(*nibbles);

        let seq = if bits == 0 {
            rem = byte & 0x03;
            bits = 2;

            (byte & (0xFF << 2)) >> 2
        } else {
            let n = 6 - bits;

            if n == 0 {
                out.push(B64_TABLE[rem as usize]);
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

        out.push(B64_TABLE[seq as usize]);
    }

    if rem != 0 {
        let byte = rem << (6 - bits);
        out.push(B64_TABLE[byte as usize]);
    }

    for &r in remainder {
        out.push(B64_TABLE[decode_hex([0, r]) as usize]);
    }

    let padding = input.len() % 3;
    out.push_str(&"=".repeat(padding));

    out
}

/// Converts the given [`Base64`]-encoded input to a decoded raw byte vector.
///
/// [`Base64`]: https://en.wikipedia.org/wiki/Base64
#[must_use]
pub fn b64_to_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * (input.len() / 4));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    let (chunks, _) = input.as_chunks::<4>();

    for chunk in chunks {
        for &b in chunk {
            let seq = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                // Includes b'='.
                _ => continue,
            };

            buffer = (buffer << 6) | u32::from(seq);
            bits += 6;
        }

        while bits >= 8 {
            let shift = bits - 8;
            let byte = ((buffer >> shift) & 0xFF) as u8;

            buffer &= (1 << shift) - 1;
            bits -= 8;

            out.push(byte);
        }
    }

    out
}

/// Encodes the given byte slice into a hexadecimal string representation.
#[inline]
#[must_use]
pub fn bytes_to_hex(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);

    for &byte in input {
        let hex = encode_hex(byte);

        out.push(hex[0] as char);
        out.push(hex[1] as char);
    }

    out
}

/// Decodes the given hex-encoded byte array into its byte representation.
#[inline]
#[must_use]
pub const fn decode_hex(nibbles: [u8; 2]) -> u8 {
    const fn decode(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => unreachable!(),
        }
    }

    (decode(nibbles[0]) << 4) | decode(nibbles[1])
}

/// Encodes the given byte into a hex-encoded byte array.
#[inline]
#[must_use]
pub const fn encode_hex(byte: u8) -> [u8; 2] {
    const fn encode(b: u8) -> u8 {
        match b {
            0..=9 => b + b'0',
            10..=15 => b + b'a' - 10,
            _ => unreachable!(),
        }
    }

    [encode((byte & 0xF0) >> 4), encode(byte & 0xF)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_b64_empty() {
        assert_eq!(hex_to_b64(b""), "");
    }

    #[test]
    fn test_b64_to_hex_empty() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"")), "");
    }

    #[test]
    fn test_hex_to_b64_sentence() {
        let input = b"5468697320697320612074657374";
        assert_eq!(hex_to_b64(input), "VGhpcyBpcyBhIHRlc3Q=");
    }

    #[test]
    fn test_b64_to_hex_sentence() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(b"VGhpcyBpcyBhIHRlc3Q=")),
            "5468697320697320612074657374"
        );
    }

    #[test]
    fn test_hex_to_b64_all_bytes_sequence() {
        let input = b"00010203040506070809";
        assert_eq!(hex_to_b64(input), "AAECAwQFBgcICQ==");
    }

    #[test]
    fn test_b64_to_hex_all_bytes_sequence() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(b"AAECAwQFBgcICQ==")),
            "00010203040506070809"
        );
    }

    #[test]
    fn test_hex_to_b64_no_padding() {
        let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(
            hex_to_b64(input),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_b64_to_hex_no_padding() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(
                b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            )),
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        );
    }

    #[test]
    fn test_hex_to_b64_one_byte() {
        assert_eq!(hex_to_b64(b"66"), "Zg==");
    }

    #[test]
    fn test_b64_to_hex_one_byte() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zg==")), "66");
    }

    #[test]
    fn test_hex_to_b64_two_bytes() {
        assert_eq!(hex_to_b64(b"666f"), "Zm8=");
    }

    #[test]
    fn test_b64_to_hex_two_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm8=")), "666f");
    }

    #[test]
    fn test_hex_to_b64_three_bytes() {
        assert_eq!(hex_to_b64(b"666f6f"), "Zm9v");
    }

    #[test]
    fn test_b64_to_hex_three_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm9v")), "666f6f");
    }

    #[test]
    fn test_hex_to_b64_four_bytes() {
        assert_eq!(hex_to_b64(b"666f6f66"), "Zm9vZg==");
    }

    #[test]
    fn test_b64_to_hex_four_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm9vZg==")), "666f6f66");
    }
}
