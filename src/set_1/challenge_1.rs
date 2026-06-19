use std::str;

use crate::utils;

pub fn run() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = utils::bytes_to_b64(&utils::hex_to_bytes(input.as_bytes()));

    let output = str::from_utf8(&b64).unwrap();
    assert_eq!(
        output,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    crate::print_challenge(1, "Convert hex to base64", &[input], &[output]);
}
