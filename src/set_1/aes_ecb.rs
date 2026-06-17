use core::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_aeskeygenassist_si128, _mm_loadu_si128, _mm_shuffle_epi32,
    _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
};
use core::mem::{self, MaybeUninit};

/// Table of precomputed `rcon` constants for [`AES-128`] key schedule algorithm
/// (10 rounds).
///
/// [`AES-128`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
const RCON_TABLE: [i32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// [`AES-128`] block size in bytes.
///
/// [`AES-128`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
const BLOCK_SIZE: usize = 16;

/// Expands a 128-bit [`AES`] round key to the next round key using `AES-NI` key
/// schedule assist.
///
/// [`AES`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
macro_rules! aes_round_key {
    ($key:expr, $round:expr) => {{
        unsafe {
            // Only the upper 32-bits of assist are used for `AES-128` key
            // schedule.
            //
            // Intel Intrinsics Guide (_mm_aeskeygenassist_si128):
            //
            // ```
            // assist[0..=31]   = SubWord($key[32..=63])
            // assist[32..=63]  = RotWord(SubWord($key[32..=63])) XOR RCON
            // assist[64..=95]  = SubWord($key[96..=127])
            // assist[96..=127] = RotWord(SubWord($key[96..=127])) XOR RCON
            // ```
            let assist = _mm_aeskeygenassist_si128::<{ RCON_TABLE[$round] }>($key);

            // Both shifts transform the given round key (previous) so that only
            // a single XOR with `assist` is required to produce the next round
            // key.
            let mut t = _mm_xor_si128($key, _mm_slli_si128::<4>($key));
            t = _mm_xor_si128(t, _mm_slli_si128::<8>(t));

            // Broadcast the top 32-bits of `assist` using the selector mask
            // 0xFF, which is XORed with the transformed round key.
            _mm_xor_si128(t, _mm_shuffle_epi32::<0xFF>(assist))
        }
    }};
}

/// Encrypts the given plaintext using [`AES-ECB`] and the provided 128-bit key,
/// returning the ciphertext.
///
/// Padding bytes are added using the [`PKCS#7`] scheme.
///
/// [`AES-ECB`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [`PKCS#7`]: https://en.wikipedia.org/wiki/PKCS_7
#[must_use]
pub fn encrypt_aes_ecb_128(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(((plaintext.len() / 16) + 1) * 16);
    let mut buffer = [0u8; 16];

    let round_keys = key_schedule_128(key);

    let mut encrypt_block = |block: &[u8; 16]| unsafe {
        let v = _mm_loadu_si128(block.as_ptr().cast());

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
    let (blocks, remainder) = plaintext.as_chunks::<{ BLOCK_SIZE }>();
    let padding = BLOCK_SIZE - remainder.len();

    for block in blocks {
        encrypt_block(block);
    }

    let mut final_block = [padding as u8; 16];
    final_block[..remainder.len()].copy_from_slice(remainder);

    encrypt_block(&final_block);

    ciphertext
}

/// Decrypts the given ciphertext, encrypted with [`AES-ECB`], using the
/// provided 128-bit key, returning the plaintext.
///
/// Padding bytes are truncated following the [`PKCS#7`] scheme.
///
/// [`AES-ECB`]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [`PKCS#7`]: https://en.wikipedia.org/wiki/PKCS_7
#[must_use]
pub fn decrypt_aes_ecb_128(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(((ciphertext.len() / 16) + 1) * 16);
    let mut buffer = [0u8; 16];

    let round_keys = key_schedule_128(key);

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
            // `InvShiftRows` + `InvSubBytes` + `AddRoundKey` (single
            // `AESDECLAST` instruction).
            _mm_aesdeclast_si128(w, round_keys[0]),
        );

        plaintext.extend(buffer);
    };

    let (blocks, _) = ciphertext.as_chunks::<{ BLOCK_SIZE }>();

    for block in blocks {
        decrypt_block(block);
    }

    // Truncate any padding bytes added using `PKCS#7`.
    plaintext.truncate(plaintext.len() - plaintext[plaintext.len() - 1] as usize);

    plaintext
}

fn key_schedule_128(key: &[u8; 16]) -> [__m128i; 11] {
    let mut round_keys = [const { MaybeUninit::<__m128i>::uninit() }; 11];

    round_keys[0] = unsafe { MaybeUninit::new(_mm_loadu_si128(key.as_ptr().cast())) };
    round_keys[1] = MaybeUninit::new(aes_round_key!(round_keys[0].assume_init(), 0));
    round_keys[2] = MaybeUninit::new(aes_round_key!(round_keys[1].assume_init(), 1));
    round_keys[3] = MaybeUninit::new(aes_round_key!(round_keys[2].assume_init(), 2));
    round_keys[4] = MaybeUninit::new(aes_round_key!(round_keys[3].assume_init(), 3));
    round_keys[5] = MaybeUninit::new(aes_round_key!(round_keys[4].assume_init(), 4));
    round_keys[6] = MaybeUninit::new(aes_round_key!(round_keys[5].assume_init(), 5));
    round_keys[7] = MaybeUninit::new(aes_round_key!(round_keys[6].assume_init(), 6));
    round_keys[8] = MaybeUninit::new(aes_round_key!(round_keys[7].assume_init(), 7));
    round_keys[9] = MaybeUninit::new(aes_round_key!(round_keys[8].assume_init(), 8));
    round_keys[10] = MaybeUninit::new(aes_round_key!(round_keys[9].assume_init(), 9));

    // SAFETY: `round_keys` has the same size and memory-layout as the return
    // type. Each slot is initialized prior to returning from this function.
    unsafe { mem::transmute(round_keys) }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::fs;

    use super::{super::utils, *};

    #[test]
    fn test_encrypt_aes_ecb_test_vector_1() {
        let key = utils::hex_to_bytes(b"2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();

        let ciphertext = encrypt_aes_ecb_128(
            &utils::hex_to_bytes(b"6bc1bee22e409f96e93d7e117393172a"),
            &key,
        );

        assert_eq!(
            utils::bytes_to_hex(&ciphertext[..16]),
            b"3ad77bb40d7a3660a89ecaf32466ef97"
        );
    }

    #[test]
    fn test_encrypt_aes_ecb_test_vector_2() {
        let key = utils::hex_to_bytes(b"2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();

        let ciphertext = encrypt_aes_ecb_128(
            &utils::hex_to_bytes(b"ae2d8a571e03ac9c9eb76fac45af8e51"),
            &key,
        );

        assert_eq!(
            utils::bytes_to_hex(&ciphertext[..16]),
            b"f5d3d58503b9699de785895a96fdbaaf"
        );
    }

    #[test]
    fn test_encrypt_aes_ecb_test_vector_3() {
        let key = utils::hex_to_bytes(b"2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();

        let ciphertext = encrypt_aes_ecb_128(
            &utils::hex_to_bytes(b"30c81c46a35ce411e5fbc1191a0a52ef"),
            &key,
        );

        assert_eq!(
            utils::bytes_to_hex(&ciphertext[..16]),
            b"43b1cd7f598ece23881b00e3ed030688"
        );
    }

    #[test]
    fn test_encrypt_aes_ecb_test_vector_4() {
        let key = utils::hex_to_bytes(b"2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();

        let ciphertext = encrypt_aes_ecb_128(
            &utils::hex_to_bytes(b"f69f2445df4f9b17ad2b417be66c3710"),
            &key,
        );

        assert_eq!(
            utils::bytes_to_hex(&ciphertext[..16]),
            b"7b0c785e27e8ad3f8223207104725dd4"
        );
    }

    // Challenge 1-7
    #[test]
    fn test_decrypt_aes_ecb_file() {
        let encrypted = fs::read("encrypted_aes_ecb.txt").unwrap();
        let plaintext = decrypt_aes_ecb_128(&utils::b64_to_bytes(&encrypted), b"YELLOW SUBMARINE");

        assert_eq!(
            plaintext,
            b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
        );
    }
}
