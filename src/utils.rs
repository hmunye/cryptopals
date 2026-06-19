/// Table containing the bytes used for each `Base64` numeric value, per
/// [RFC 4648].
///
/// [RFC 4648]: https://datatracker.ietf.org/doc/html/rfc4648#section-4
const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes the given byte slice into a [`Base64`] byte vector. For padding,
/// `'='` bytes are appended to the output.
///
/// `Base64` is a binary-to-text encoding scheme that uses 64 printable
/// characters to represent each 6-bit segment of a sequence of byte values.
///
/// [`Base64`]: https://en.wikipedia.org/wiki/Base64
#[must_use]
pub fn bytes_to_b64(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * input.len().div_ceil(3));
    let mut rem = 0;
    let mut bits = 0;

    for byte in input {
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

    let padding = match input.len() % 3 {
        0 => 0,
        1 => 2,
        2 => 1,
        _ => unreachable!(),
    };
    out.extend(std::iter::repeat_n(b'=', padding));

    out
}

/// Decodes the given [`Base64`] byte slice into a raw byte vector.
///
/// [`Base64`]: https://en.wikipedia.org/wiki/Base64
#[must_use]
pub fn b64_to_bytes(b64: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * (b64.len() / 4));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    let (chunks, _) = b64.as_chunks::<4>();

    for chunk in chunks {
        for &b in chunk {
            let seq = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                // Includes padding (b'=').
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

/// Encodes the given byte slice into a hexadecimal byte vector representation.
#[inline]
#[must_use]
pub fn bytes_to_hex(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);

    for &byte in input {
        let hex = encode_hex(byte);

        out.push(hex[0]);
        out.push(hex[1]);
    }

    out
}

/// Encodes the given byte into a hexadecimal byte array representation.
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

/// Decodes the given hexadecimal byte slice into a raw byte vector.
///
/// # Panics
///
/// Panics if input length is not a multiple of 2.
#[inline]
#[must_use]
pub fn hex_to_bytes(hex: &[u8]) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));

    let mut out = Vec::with_capacity(hex.len() / 2);

    let (chunks, _) = hex.as_chunks::<2>();

    for &[x, y] in chunks {
        out.push(decode_hex([x, y]));
    }

    out
}

/// Decodes the given hexadecimal byte array into a byte representation.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_b64_empty() {
        assert_eq!(bytes_to_b64(b""), b"");
    }

    #[test]
    fn test_b64_to_hex_empty() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"")), b"");
    }

    #[test]
    fn test_hex_to_b64_sentence() {
        let input = b"5468697320697320612074657374";
        assert_eq!(bytes_to_b64(&hex_to_bytes(input)), b"VGhpcyBpcyBhIHRlc3Q=");
    }

    #[test]
    fn test_b64_to_hex_sentence() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(b"VGhpcyBpcyBhIHRlc3Q=")),
            b"5468697320697320612074657374"
        );
    }

    #[test]
    fn test_hex_to_b64_all_bytes_sequence() {
        let input = b"00010203040506070809";
        assert_eq!(bytes_to_b64(&hex_to_bytes(input)), b"AAECAwQFBgcICQ==");
    }

    #[test]
    fn test_b64_to_hex_all_bytes_sequence() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(b"AAECAwQFBgcICQ==")),
            b"00010203040506070809"
        );
    }

    #[test]
    fn test_hex_to_b64_no_padding() {
        let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(
            bytes_to_b64(&hex_to_bytes(input)),
            b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_b64_to_hex_no_padding() {
        assert_eq!(
            bytes_to_hex(&b64_to_bytes(
                b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            )),
            b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        );
    }

    #[test]
    fn test_hex_to_b64_one_byte() {
        assert_eq!(bytes_to_b64(&hex_to_bytes(b"66")), b"Zg==");
    }

    #[test]
    fn test_b64_to_hex_one_byte() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zg==")), b"66");
    }

    #[test]
    fn test_hex_to_b64_two_bytes() {
        assert_eq!(bytes_to_b64(&hex_to_bytes(b"666f")), b"Zm8=");
    }

    #[test]
    fn test_b64_to_hex_two_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm8=")), b"666f");
    }

    #[test]
    fn test_hex_to_b64_three_bytes() {
        assert_eq!(bytes_to_b64(&hex_to_bytes(b"666f6f")), b"Zm9v");
    }

    #[test]
    fn test_b64_to_hex_three_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm9v")), b"666f6f");
    }

    #[test]
    fn test_hex_to_b64_four_bytes() {
        assert_eq!(bytes_to_b64(&hex_to_bytes(b"666f6f66")), b"Zm9vZg==");
    }

    #[test]
    fn test_b64_to_hex_four_bytes() {
        assert_eq!(bytes_to_hex(&b64_to_bytes(b"Zm9vZg==")), b"666f6f66");
    }
}
