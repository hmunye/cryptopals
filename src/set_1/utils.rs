/// Decodes the given hex-encoded array into its byte representation.
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

/// Encodes the given byte into a hex-encoded array representation.
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

/// Encodes the given byte slice into a hexadecimal string representation.
#[inline]
#[must_use]
pub fn encode_to_hex_string(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);

    for &byte in input {
        let hex = encode_hex(byte);

        out.push(hex[0] as char);
        out.push(hex[1] as char);
    }

    out
}
