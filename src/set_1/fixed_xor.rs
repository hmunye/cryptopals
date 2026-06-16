use super::utils;

/// Computes the `XOR` combination of the provided hex-encoded byte arrays,
/// returning its hexadecimal string representation.
#[inline]
#[must_use]
pub fn fixed_xor<const N: usize>(x: &[u8; N], y: &[u8; N]) -> String {
    if N == 0 {
        return String::new();
    }

    let mut out = Vec::with_capacity(N / 2);

    for i in (0..N - 1).step_by(2) {
        let byte_x = utils::decode_hex([x[i], x[i + 1]]);
        let byte_y = utils::decode_hex([y[i], y[i + 1]]);

        out.push(byte_x ^ byte_y);
    }

    utils::bytes_to_hex(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_xor_empty() {
        assert_eq!(fixed_xor(b"", b""), "");
    }

    #[test]
    fn test_fixed_xor_basic() {
        assert_eq!(
            fixed_xor(
                b"1c0111001f010100061a024b53535009181c",
                b"686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
