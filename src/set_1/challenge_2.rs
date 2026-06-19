use std::str;

use crate::utils;

pub fn run() {
    let x = b"1c0111001f010100061a024b53535009181c";
    let y = b"686974207468652062756c6c277320657965";
    let xor = fixed_xor(x, y);

    let output = str::from_utf8(&xor).unwrap();
    assert_eq!(output, "746865206b696420646f6e277420706c6179");

    crate::print_challenge(
        2,
        "Fixed XOR",
        &[str::from_utf8(x).unwrap(), str::from_utf8(y).unwrap()],
        &[output],
    );
}

/// Computes the `XOR` combination of the given hex-encoded byte arrays,
/// returning a hexadecimal byte vector representation.
#[inline]
#[must_use]
pub fn fixed_xor<const N: usize>(x: &[u8; N], y: &[u8; N]) -> Vec<u8> {
    let mut out = Vec::with_capacity(N / 2);
    if N == 0 {
        return out;
    }

    for i in (0..N - 1).step_by(2) {
        let byte_x = utils::decode_hex([x[i], x[i + 1]]);
        let byte_y = utils::decode_hex([y[i], y[i + 1]]);

        out.push(byte_x ^ byte_y);
    }

    utils::bytes_to_hex(&out)
}
