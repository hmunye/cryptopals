use std::{fs, str};

use crate::set_1::challenge_3::decrypt_xor_cipher;
use crate::set_1::challenge_5::repeating_xor;
use crate::utils;

pub fn run() {
    let encrypted = fs::read("encrypted_repeating_xor.txt").unwrap();

    let (meta, plaintext) = decrypt_repeating_xor(&utils::b64_to_bytes(&encrypted)).unwrap();
    assert_eq!(meta.key, b"Terminator X: Bring the noise");
    assert_eq!(
            plaintext,
            b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
        );

    crate::print_challenge(
        6,
        "Break repeating-key XOR",
        &["file: encrypted_repeating_xor.txt"],
        &[
            &format!("key: {:?}", str::from_utf8(&meta.key).unwrap()),
            &format!("plaintext: {}", str::from_utf8(&plaintext).unwrap()),
        ],
    );
}

/// Decryption metadata for `repeating-key XOR`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub key: Vec<u8>,
}

/// Decrypts the given ciphertext, which has been encrypted with
/// `repeating-key XOR`, returning a [`Metadata`] and plaintext pair.
///
/// Returns `None` if a key could not be found (e.g., empty input).
///
/// [`Base64`]: https://en.wikipedia.org/wiki/Base64
#[must_use]
pub fn decrypt_repeating_xor(ciphertext: &[u8]) -> Option<(Metadata, Vec<u8>)> {
    if ciphertext.is_empty() {
        return None;
    }

    let k = find_candidate_keysize(ciphertext);
    let blocks = ciphertext.len() / k;

    // Blocks are transposed so each byte XORed with a given byte from the key
    // appear in the same block. Each block can then be decrypted for it's
    // single-key XOR.
    let mut transposed: Vec<Vec<u8>> = Vec::with_capacity(k);

    for i in 0..k {
        let mut v = Vec::with_capacity(blocks);

        for j in 0..blocks {
            v.push(ciphertext[j * k + i]);
        }

        transposed.push(v);
    }

    let mut key = Vec::with_capacity(transposed.len());

    for block in transposed {
        if let Some((meta, _)) = decrypt_xor_cipher(&block) {
            // Each decrypted single-key XOR is concatenated.
            key.push(meta.key);
        }
    }

    let plaintext = repeating_xor(ciphertext, &key);

    Some((Metadata { key }, plaintext))
}

#[inline]
fn find_candidate_keysize(ciphertext: &[u8]) -> usize {
    let mut keysize = 0;
    let mut min_dist = usize::MAX;

    let keyspace = 2usize..=40;

    for k in keyspace {
        let n = 10;

        // More blocks = less noise but more computation
        let blocks: Vec<_> = ciphertext.chunks_exact(k).take(n).collect();

        let mut total_dist = 0;

        // Hamming distance is computed between all unique pairs (pairwise).
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                total_dist += hamming_distance(blocks[i], blocks[j]);
            }
        }

        // Average and normalize total distance for the given `k`, so smaller
        // `k`s are not biased (larger blocks will generally have a greater
        // hamming distance).
        let dist = total_dist / ((n * (n - 1) / 2) * k);

        if dist < min_dist {
            min_dist = dist;
            keysize = k;
        }
    }

    keysize
}

/// Returns the number of differing bits between the provided byte slices.
///
/// # Panics
///
/// Panics if the lengths of both byte slices differ.
#[inline]
const fn hamming_distance(x: &[u8], y: &[u8]) -> usize {
    assert!(x.len() == y.len());

    let mut ones = 0;
    let mut i = 0;

    while i < x.len() {
        ones += (x[i] ^ y[i]).count_ones();
        i += 1;
    }

    ones as usize
}
