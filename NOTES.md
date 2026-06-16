# Real World Cryptography

## Cryptography

__Cryptography__ is the practice of designing mathematical algorithms and protocols 
to secure information and communications against adversaries.

__Protocols__ are sets of rules or procedures that one or more entities follow to 
achieve a specific goal. 

__Primitives__ are the fundamental building blocks of cryptography, often used with 
other primitives to form a cryptographic algorithm or protocol.

__Constructions__ are the methods or processes used for building cryptographic 
objects (e.g., algorithms, protocols) from primitives.

## Symmetric Cryptography

Class of cryptographic algorithms which requires the sharing of a __secret key__. 

__Symmetric encryption__ uses a single, shared, secret key for both encryption 
and decryption of data. 

Encryption takes __plaintext__ data and a secret key, and produces __ciphertext__, 
data that is unintelligible without the key. Decryption does the inverse, taking the 
same secret key and ciphertext to recover the original plaintext. 

### AES

Advanced Encryption Standard (`AES`) is an instance of a symmetric encryption 
algorithm (cryptographic primitive).

Offers three versions differing on key length: `AES-128`, `AES-192`, and `AES-256`.
Longer keysize correlates to more __bit security__ (describes an upper bound, e.g., 
brute-force attack over 2^128 operations).

Encryption accepts a variable-length key and plaintext of 128-bit fixed-size, and 
produces ciphertext of 128-bit fixed-size (referred to as a __block cipher__ since 
plaintext is fixed-size). Decryption accepts the same key, ciphertext of 128-bit 
fixed-size, and produces plaintext of 128-bit fixed-size (deterministic process).

Block cipher with the corresponding key can be seen as a __permutation__: mapping 
all the possible plaintexts to all the possible ciphertexts under a given key.
AES behaves like a permutation randomized by key (__pseudorandom permutation__).

During encryption, the state of the plaintext is viewed as a 4x4 matrix of bytes.
A __round function__ (consisting of multiple sub-functions) is used iteratively 
starting with the plaintext to transform the state and produce the ciphertext. 
Each iteration uses a different __round key__ which is derived from the main key 
(during a __key schedule__).

Padding and a __mode of operation__ (defines how a block cipher is applied 
iteratively to encrypt larger data) are used to encrypt plaintext that is not 
128-bits in length. 

`PKCS#7` padding is a popular mechanism which specifies the value of each padding 
byte must be the length of the padding required.

Electronic Code Book (`ECB`) mode of operation is a naive scheme which divides 
plaintext into blocks of 16 bytes with possible padding, and processes each block 
individually. This scheme is flawed in that the resulting ciphertext may have 
repeating patterns; the structural information of the plaintext is leaked, given 
that the same block of plaintext produces the same ciphertext.

Cipher Block Chaining (`CBC`) mode of operation is more safe in that it "randomizes"
the encryption. It uses a random initialization vector (IV) which is XORed with the
first block of plaintext before encrypting. That resulting ciphertext is then XORed
with the next block of plaintext before encrypting, etc. During decryption, the IV 
is transmitted, which is fine since its randomness ensures no information about the
plaintext is leaked.

Counter (`CTR`) mode of operation works by using AES to encrypt a __nonce__ (number 
used once) concatenated with a plain number (starting at 1) instead of plaintext. 
The nonce serves the same purpose as an IV: allows randomization in encryption. The 
nonce is required to be unique but not unpredictable. The resulting encrypted 
16-byte block is referred to as a __keystream__, which is then XORed with the 
plaintext to produce the ciphertext. It provides the property that no padding is 
required as it turns a block cipher into a __stream cipher__.


## Asymmetric Cryptography

Due to the difficulty in implementing secure __key distribution__ for symmetric
cryptography, another useful class of cryptographic algorithms emerged, 
__asymmetric (public key) cryptography__.

Makes use of different keys for different functions rather than a single, shared
key.

__Asymmetric encryption__ uses a __public key__ and __private key__ pair; anyone 
can encrypt data with the public key but only the owner of the associated private 
key can decrypt that data.

### Diffie-Hellman (`DH`)

Instance of an asymmetric cryptographic primitive, used for __key exchange__.

Key exchange algorithms establish a common secret between two parties, which can be
used for different purposes (e.g., key to symmetric encryption primitive). 

Each party first agrees to a set of common, public parameters, then generate their 
own private keys (never shared). Each private key is combined with the common 
parameters to produce public keys (always shared). Public keys are then exchanged, 
allowing for each party to combine the others public key with their private key to 
produce the final shared secret.

Vulnerable to a __man-in-the-middle__ (`MITM`) attack. Each party accepts any 
public key received as being generated by the other, without verification.

### RSA

Algorithm named after Ron Rivest, Adi Shamir, and Leonard Adleman (`RSA`).

Consists of two different primitives: public key encryption algorithm 
(asymmetric encryption) and a (digital) signature scheme.

## Digital Signatures

Cryptographic primitive used to ensure the integrity and authenticity of data, 
and to provide __non-repudiation__ in communication between parties.

Messages are __signed__ using a private key to generate a __signature__. Any party
can then verify the message by combining it with the signature and the associated 
public key. If the signature is valid, the message has authenticity, integrity, and 
non-repudiation.

## Kerckhoffs’s Principle

A cryptographic algorithm/protocol must be secure without relying on the secrecy 
of the implementation (key always remains secret). Security through obscurity, 
however, relies on hiding system details in order to remain secure, but provides 
no mathematical guarantees of security or ability to robustly audit and test.

## Hash Functions

Function which transforms input data to a fixed-length unique sequence of bytes 
(__digest__). The same input produces the same sequence of bytes.

Provides partial integrity and authenticity for data communicated between parties: 
comparing the computed digest to that which is shared by the other party can ensure 
the data received was indeed the data expected. Receiver must trust that the 
provided digest is authentic through the trust mechanism used to receive the data 
and digest (e.g., `HTTPS`).

Cryptographic hash functions provide three main security properties:

- __Pre-image resistance__: Input cannot be derived from the digest alone, given
  a sufficiently large input space

- __Second pre-image resistance__: Digest derived from some input cannot be produced 
  through hashing a different input (one input is fixed)

- __Collision Resistance__: Two separate inputs cannot be hashed to produce the 
  same digest (both inputs are unfixed)


### SHA-2

__Secure Hash Algorithm__ (`SHA-2`) is the most widely adopted hash function, 
providing four versions which differ on output space; 224, 256, 384, and 512 bits.

`SHA-512/224` and `SHA-512/256` versions are derived from truncating the result of 
`SHA-512`.

Uses a __compression function__: accepts two input arguments of length X and Y, and 
returns an output of length X or Y. 

__Davies-Meyer__ used as the compression algorithm for SHA-2 which relies on a 
block cipher (cipher that encrypts a fixed-size block of data). The first input 
(block) is used as the key to a block cipher. The second input (intermediate) is 
the data to be encrypted by the block cipher. The output block is the result of 
XORing the intermediate with the output of the block cipher.

Uses the __Merkle-Damgard__ construction: hashes the data by iteratively invoking 
the compression function. Padding may be added to the input before being chunked 
into block sizes supported by the compression algorithm (e.g., `SHA-256` requires a
block size of 512-bits). The compression function is then iteratively applied to
the blocks, with its previous output used as the second argument. The initial
second argument is usually fixed and standardized.

Vulnerable to a __length-extension attack__ if used to hash secrets: exploits the
internals of Merkle-Damgard constructions, where the final digest also acts as 
intermediate state. Given a digest, an adversary can concatenate arbitrary 
additional data without knowing the original input. The compression function is
re-invoked using the known digest as a starting state.

### SHA-3

Secure Hash Algorithm (`SHA-3`) was standardized due to the breaking of `MD5` and 
`SHA-1`, which both used the __Merkle-Damgard__ construction, as well as SHA-2s 
vulnerability to length-extension attacks.

In addition to the security properties provided by cryptographic hash functions and
the security properties of SHA-2, SHA-3 is also able to hash secrets. Provides the 
same variants of SHA-2, with a different naming scheme.

Uses the __sponge__ construction, built on top of the `keccak-f` permutation: 
function that maps an input to an output of the same size (unique and reversible).

Input must be arbitrarily divided into a __rate__ and __capacity__. Capacity is 
intended to be treated like a secret (larger = more secure). The input is XORed with 
the rate of the permutation input (initially all 0-bits). Input may be padded to 
evenly divide into rate-sized blocks. The permutation is called iteratively while 
XORing each block with the input of a permutation and permuting the __state__ 
(intermediate output from previous operation) after each block is XORed. Ingesting 
the input is referred to as __absorbing__ and producing the digest is referred to 
as __squeezing__.

## Message Authentication Code (`MAC`)

Cryptographic primitive aimed at protecting the integrity of data 
(__secret-key algorithm__).

Accepts an input and secret key to produces an __authentication tag__. MAC is 
deterministic: the same input and secret key pair produce the same authentication 
tag. Without the secret key, it should be impossible to reproduce the same 
authentication tag for a given input.

The main security property of MACs are __existential unforgeability__: an adversary
who has observed arbitrarily many input-tag pairs should still be unable to produce
a valid authentication tag for new inputs. They gain no computational advantage in
producing valid tags without the secret key.

Collisions occur when different inputs, using the same secret key, produce the same
authentication tag. 128-bit authentication tags are generally used as they provide 
enough collision resistance and require __online__ computation (since tags must be 
requested).

Vulnerable to __replay attacks__: adversary intercepts a valid message between 
parties to be retransmitted at a later time, which is excepted by the recipient as
a new valid message.

### Hash-based Message Authentication Code (`HMAC`)

MAC constructed using a hash function (e.g., SHA-2). Two keys are first created from 
the secret key; `k1 = k ^ ipad` and `k2 = k ^ opad`, where `ipad` (inner padding) 
and `opad` (outer padding) are constants. The input is concatenated with a key, 
`k1`, to produce a digest, which is then concatenated with a key, `k2`, to produce 
the final digest (authentication tag).

### KMAC

`KMAC` makes use of the cSHAKE `XOF`, unambiguously encoding the MAC key, input, and
requested output space to be absorbed by cSHAKE.

### GMAC

MAC constructed from a keyed hash (`GHASH`). GHASH can be referred to as a 
__difference unpredictable function__ (`DUF`). This function need not be collision
resistant, making it significantly faster than other hash functions. A digest is
produced from processing input in 16-byte blocks in a process similar to CBC mode.
It can only be used as a __one-time MAC__, but in combination with `AES-CTR` and 
a different key, can be used many times for producing authentication tags.

### SipHash

`SipHash` is a MAC construction used primarily with __hash tables__. If a service 
exposes a hash table which makes use of a non-cryptographic hash function, an 
adversary can launch a denial-of-service (`DOS`) attack. Since the buckets a key 
maps to are deterministic and public, an adversary with knowledge of the hash 
function and control over the key can craft arbitrarily many inputs that collide, 
degrading performance from O(1) amortized to O(N). SipHash with a random key is 
used in place of the non-cryptographic hash function to add unpredictability in
input collision.

## Authenticated Encryption

__Encryption algorithms__ (ciphers) provide confidentiality for one or more parties.

Constructions which combine a secret key and plaintext to produce ciphertext. 
__Decryption algorithms__ combine the ciphertext with the same secret key to 
retrieve the original plaintext (symmetric encryption).

Encryption algorithms (e.g., `AES-CBC`) lack the integrity mechanisms that prevent
modification of the ciphertext and its parameters in-transit by adversaries. MACs
can be used (e.g., `AES-CBC-HMAC`) to provide integrity by encrypting then producing
the authentication tag over that ciphertext and its parameters. It is best practice 
to use different keys for different cryptographic constructions.

Modern authenticated encryption uses all-in-one constructions, or 
__authenticated encryption with associated data__ (`AEAD`). `AES-GCM` 
(__Galois/Counter Mode__) is the most widely used AEAD which uses `AES-CTR` with a 
GMAC for highly performant encryption/decryption.

`ChaCha20-Poly1305` is another AEAD which combines the `ChaCha20` stream cipher and
`Poly1305` MAC.
