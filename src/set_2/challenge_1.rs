use std::str;

use crate::utils;

pub fn run() {
    let input = "YELLOW SUBMARINE";
    let padded = utils::with_pkcs7_padding::<20>(input.as_bytes());

    let output = str::from_utf8(&padded).unwrap();
    assert_eq!(output, "YELLOW SUBMARINE\x04\x04\x04\x04");

    crate::print_challenge(
        1,
        "Implement PKCS#7 padding",
        &[input],
        &[&output.escape_debug().to_string()],
    );
}
