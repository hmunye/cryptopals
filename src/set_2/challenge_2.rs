use std::arch::x86_64::{
    _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};
use std::{fs, str};

use crate::set_1::challenge_7::{AES_BLOCK_SIZE, aes_key_schedule_128};
use crate::utils;

pub fn run() {
    let encrypted = fs::read("encrypted_aes_cbc.txt").unwrap();
    let iv = [0x00; 16];

    let plaintext = decrypt_aes_cbc_128(&utils::b64_to_bytes(&encrypted), b"YELLOW SUBMARINE", &iv);

    let output = str::from_utf8(&plaintext).unwrap();
    assert_eq!(
        output,
        "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
    );

    crate::print_challenge(
        2,
        "Implement CBC mode",
        &["file: encrypted_aes_cbc.txt"],
        &[output],
    );
}

/// Encrypts the given plaintext using [`AES-CBC`] with the provided 128-bit
/// key and IV, returning the ciphertext.
///
/// Padding bytes are added using the [`PKCS#7`] scheme.
///
/// [`AES-CBC`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [`PKCS#7`]: https://en.wikipedia.org/wiki/PKCS_7
#[must_use]
#[allow(unused)]
pub fn encrypt_aes_cbc_128(plaintext: &[u8], key: &[u8; 16], iv: &[u8; AES_BLOCK_SIZE]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(((plaintext.len() / 16) + 1) * 16);
    let mut buffer = *iv;

    let round_keys = aes_key_schedule_128(key);

    let mut encrypt_block = |block: &[u8; 16]| unsafe {
        let v = _mm_loadu_si128(block.as_ptr().cast());
        // XOR with the previously encrypted block (or with IV).
        let v = _mm_xor_si128(v, _mm_loadu_si128(buffer.as_ptr().cast()));

        // `AddRoundKey`: XOR-based key whitening (initially mixes plaintext
        // with key to add dependency).
        let mut w = _mm_xor_si128(round_keys[0], v);

        for &r in &round_keys[1..10] {
            // `ShiftRows` + `SubBytes` + `MixColumns` + `AddRoundKey` (single
            // `AESENC` instruction).
            w = _mm_aesenc_si128(w, r);
        }

        _mm_storeu_si128(
            buffer.as_mut_ptr().cast(),
            // `ShiftRows` + `SubBytes` + `AddRoundKey` (single `AESENCLAST`
            // instruction).
            _mm_aesenclast_si128(w, round_keys[10]),
        );

        ciphertext.extend(buffer);
    };

    // `AES` logically treats each block as a 4x4 matrix (column-major) instead
    // of a contiguous 16-byte array. `AES-NI` just operates on `XMM` registers.
    //
    // ```
    // [b00, b04, b08, b12]
    // [b01, b05, b09, b13]
    // [b02, b06, b10, b14]
    // [b03, b07, b11, b15]
    // ```
    let (blocks, remainder) = plaintext.as_chunks::<{ AES_BLOCK_SIZE }>();
    for block in blocks {
        encrypt_block(block);
    }

    encrypt_block(&utils::with_pkcs7_padding::<{ AES_BLOCK_SIZE }>(remainder));

    ciphertext
}

/// Decrypts the given ciphertext encrypted with [`AES-CBC`] using the
/// provided 128-bit key and IV, returning the plaintext.
///
/// Padding bytes are truncated following the [`PKCS#7`] scheme.
///
/// [`AES-CBC`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [`PKCS#7`]: https://en.wikipedia.org/wiki/PKCS_7
#[must_use]
pub fn decrypt_aes_cbc_128(
    ciphertext: &[u8],
    key: &[u8; 16],
    iv: &[u8; AES_BLOCK_SIZE],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(((ciphertext.len() / 16) + 1) * 16);
    let mut buffer = [0u8; AES_BLOCK_SIZE];
    let mut prev = unsafe { _mm_loadu_si128(iv.as_ptr().cast()) };

    let round_keys = aes_key_schedule_128(key);

    let mut decrypt_block = |block: &[u8; 16]| unsafe {
        let v = _mm_loadu_si128(block.as_ptr().cast());

        // `AddRoundKey`: reverses final `AddRoundKey` step from encryption.
        let mut w = _mm_xor_si128(round_keys[10], v);

        for i in (1..10).rev() {
            // `InvShiftRows` + `InvSubBytes` + `InvMixColumns` + `AddRoundKey`
            // (single `AESDEC` instruction).
            //
            // Apply `InvMixColumns` on round keys 1-9 since `AESDEC` applies
            // `InvMixColumns` to the state, ensuring the math cancels out.
            w = _mm_aesdec_si128(w, _mm_aesimc_si128(round_keys[i]));
        }

        _mm_storeu_si128(
            buffer.as_mut_ptr().cast(),
            // XOR with the previously encrypted block (or with IV).
            //
            // `InvShiftRows` + `InvSubBytes` + `AddRoundKey` (single
            // `AESDECLAST` instruction).
            _mm_xor_si128(prev, _mm_aesdeclast_si128(w, round_keys[0])),
        );

        _mm_storeu_si128(&raw mut prev, v);

        plaintext.extend(buffer);
    };

    let (blocks, _) = ciphertext.as_chunks::<{ AES_BLOCK_SIZE }>();
    for block in blocks {
        decrypt_block(block);
    }

    // Truncate any padding bytes added following `PKCS#7`.
    plaintext.truncate(plaintext.len() - plaintext[plaintext.len() - 1] as usize);
    plaintext
}
