# Real World Cryptography

## Cryptography

__Cryptography__ is the study and practice of designing mathematical algorithms 
and protocols that secure information and communications in the presence of 
adversaries.

__Protocols__ are sets of rules or procedures followed by one or more parties to
achieve a security goal (e.g., confidentiality, authentication, integrity).

__Primitives__ are the fundamental building blocks of cryptography, often used 
with other primitives to form a cryptographic algorithm/protocol.

__Constructions__ are methods or processes used for building cryptographic 
objects (e.g., algorithms, protocols) from primitives.

## Symmetric Cryptography

Class of cryptographic algorithms which requires a shared __secret key__. 

__Symmetric encryption__ uses the same secret key for both encryption and 
decryption. 

Encryption takes __plaintext__ and a secret key, and produces __ciphertext__, 
which is unintelligible without the key. Decryption use the same secret key and 
ciphertext to recover the original plaintext. 

### AES

The Advanced Encryption Standard (`AES`) is an instance of a symmetric 
encryption primitive.

Offers three variants based on key size: `AES-128`, `AES-192`, and `AES-256`. 
Larger key size correlates to more __bit security__ (describes an upper bound, 
e.g., brute-force attack over 2^128 operations for AES-128).

Encryption accepts a secret key and a 128-bit fixed-size block of plaintext, and 
produces a 128-bit fixed-size block of ciphertext. Decryption accepts the same 
secret key and 128-bit ciphertext, and recovers the 128-bit plaintext. Since 
input/output block sizes are fixed, AES is referred to as a __block cipher__.

Block cipher under a fixed key behaves like a __permutation__ over all possible 
128-bit blocks. AES is designed to behave like a pseudorandom permutation 
(`PRP`).

AES represents blocks as a 4×4 matrix of bytes (column-major). A 
__round function__ is applied iteratively to transform the internal state. Each 
round uses a different round key, derived from the secret key via a 
__key schedule algorithm__.

Since AES only operates on fixed-size blocks, padding and __modes of operation__ 
are used to encrypt arbitrary-length plaintext.

#### Padding and Modes of Operation

`PKCS#7` padding scheme is a widely used standard which specifies setting each 
padding byte to the number of padding bytes added. If the plaintext is already a 
multiple of 16 bytes, a full padding block is appended.

Electronic Code Book (`ECB`) mode of operation is a naive scheme which encrypts 
each 128-bit block individually (including padding). It is insecure because the 
resulting ciphertext may have repeating patterns; the structural information of 
the plaintext is leaked, since the same block of plaintext produces the same 
ciphertext.

Cipher Block Chaining (`CBC`) mode of operation is more secure in that it 
"randomizes" the encryption of blocks. It uses a random initialization vector 
(`IV`) which is XORed with the first block of plaintext before encrypting. That 
resulting ciphertext is then XORed with the next block of plaintext, and so on. 
The IV must be unique (and ideally random) but does not need to be secret.

Counter (`CTR`) mode of operation works by encrypting a __nonce__ (number used 
once) concatenated with an incrementing counter (starting at 1) using AES. The 
nonce serves the same purpose as an IV: allows randomization in the encryption 
of blocks. The nonce is required to be unique per-key but not unpredictable. The 
resulting encrypted 128-bit block is referred to as a __keystream__, which is 
then XORed with the plaintext to produce ciphertext. No padding is required as 
CTR turns a block cipher into a __stream cipher__.

## Asymmetric Cryptography

Due to the difficulty of designing secure __key distribution__ in symmetric
cryptography, __asymmetric (public key) cryptography__ emerged.

__Asymmetric encryption__ uses a __public key__ and __private key__ pair; anyone 
can encrypt using the public key but only the owner of the associated private 
key can decrypt.

### Diffie-Hellman (DH)

Instance of an asymmetric cryptographic primitive, used for __key exchange__.

Key exchange algorithms establish a common secret between two parties over an 
insecure channel, which can be used for different purposes (e.g., key to a 
symmetric encryption primitive). 

`DH` is based on __group theory, where a group is a set with a binary operation 
satisfying:

- __Closure__: operation on any two elements produces an element within the same 
  group

- __Associativity__: grouping of elements within an operation does not affect 
  the result

- __Identity Element__: an element that does not change other elements under the 
  operation

- __Inverse Element__: each element within a group has a corresponding inverse

DH operates in a __multiplicative group__ modulo a prime (a finite cyclic 
group), typically the integers `{1, 2, ..., p − 1}` under multiplication mod 
`p`.

Security relies on the __discrete logarithm problem__: given `g`, `p`, and 
`g^x mod p`, it is computationally infeasible to recover `x` for sufficiently 
large `p`.

Each party first agrees to a set of common public parameters (`p` and `g`), then 
generate their own private keys (alice: `x`, bob: `y`). Each private key is 
combined with the common parameters (`g^x mod p`) to produce their associated 
public keys. Public keys are then exchanged, allowing each party to combine 
the other public key with their private key (`(g^y)^x mod p = g^(xy) mod p`) to 
produce the final shared secret.

DH is vulnerable to a __man-in-the-middle__ (`MITM`) attack since public keys 
are not authenticated: each party accepts any public key received as being 
generated by the other.

### Elliptic Curve Diffie-Hellman (ECDH)

Uses groups formed from __elliptic curves__, where points (`x`, `y`) satisfy an
equation (commonly the __short Weierstrass form__).

Properties needed include: an elliptic curve equation that defines a set of 
valid points, group addition operation over points, and an imaginary point or 
identity element (__point of infinity__).

Common standardized curves include `P-256`, `P-521`, `Curve25519`, and 
`Curve448`. The combination of `Curve25519` with `ECDH` is known as `X25519`.

ECDH provides the same functionality as DH but with smaller keys and improved 
efficiency due to elliptic curve structure.

### RSA

Algorithm named after Ron Rivest, Adi Shamir, and Leonard Adleman.

RSA supports both public-key encryption and digital signatures.

For key generation: two large prime numbers (`p` and `q`) are generated, a 
public exponent (`e`) is chosen. A public key is derived from the exponent and 
public modulus (`N` = `p * q`), and the private key is derived from 
(`d = e⁻¹ mod φ(N), where φ(N) = (p − 1)(q − 1)`).

For asymmetric encryption, plaintext is encrypted using the public key 
(`plaintext^e mod N`), and decrypted using the private key and public modulus 
(`ciphertext^d mod N`).

Security relies on the difficulty the __factorization problem__: without knowing 
`p` and `q`, computing `φ(N)` (and thus `d`) is infeasible.

### RSA-OAEP

__Textbook RSA__ is insecure in practice due to structural and deterministic 
properties, and is vulnerable to attacks such as the __million message attack__ 
when used with weak padding schemes like `PKCS#1 v1.5`.

`OAEP` (Optimal Asymmetric Encryption Padding) is a standardized padding scheme 
that adds randomness before `RSA` encryption, making RSA semantically secure 
under standard assumptions.

## Kerckhoffs’s Principle

A cryptographic system should remain secure even if everything about the system 
is assumed public knowledge (except the secret key).

Security must not depend on hiding the algorithm, implementation details, or 
protocol design. This contrasts with __security through obscurity__, where 
secrecy relies on hiding system details rather than mathematical guarantees. 
Such systems are fragile because hidden assumptions cannot be reliably audited, 
reviewed, or tested.

## Hash Functions

Cryptographic __hash function__ maps arbitrary-length input data to a 
fixed-length output called a __digest__. The same input always produces the same 
digest.

Hash functions are used for integrity checks: if two parties share a trusted 
digest of data, the receiver can verify that received data has not been altered. 
This requires the digest itself to be received through a trusted channel (e.g., 
`HTTPS`).

Cryptographic hash functions are expected to satisfy three properties:

- __Pre-image resistance__: Input cannot be derived from its digest alone, given
  a sufficiently large input space

- __Second pre-image resistance__: Digest derived from some input cannot be 
  produced through hashing a different input (control over one input)

- __Collision Resistance__: Two distinct inputs cannot be hashed to produce the 
  same digest (no control over both inputs)

### SHA-2

The __Secure Hash Algorithm__ (`SHA-2`) is the most widely adopted family of 
hash functions, providing variants producing 224, 256, 384, and 512 bit digests.

`SHA-512/224` and `SHA-512/256` are derived from truncating the digest of 
`SHA-512`.

SHA-2 is built using a __Merkle–Damgård__ construction, which processes input in 
fixed-size blocks using a __compression function__ and iteratively updates an 
internal state.

SHA-2’s compression function is built from a __Davies–Meyer__ construction, 
where a block cipher is used internally: the message block is used as the key, 
and the chaining value (intermediate) is encrypted and combined with XOR.

Vulnerable to a __length-extension attack__ (if used to hash secrets): exploits 
the internals of the Merkle–Damgård structure, where the final digest also acts 
as intermediate state. Given a digest, an adversary can concatenate arbitrary 
additional data without knowledge of the original input. The compression 
function is re-invoked using the known digest as a starting state.

### SHA-3

`SHA-3` was standardized as an alternative design after weaknesses were found in 
older hash functions like `MD5` and `SHA-1`, and to avoid structural issues 
present in Merkle–Damgård constructions.

Input is processed using a __sponge__ construction, where the internal state is 
divided into a __rate__ and a __capacity__. The capacity contributes to the 
security of the construction, with a larger capacity providing higher security 
strength. During the absorbing phase, the input is split into rate-sized blocks 
and each block is XORed into the rate portion of the current state, after which 
a fixed permutation (`Keccak`) is applied to the entire state. This process is 
repeated for all input blocks. After absorption is complete, the squeezing phase 
begins, where output is read from the rate portion of the state, with additional 
applications of the permutation if more output is required.

SHA-3 avoids length-extension attacks due to its sponge construction and 
internal state design.

## Message Authentication Code (`MAC`)

Cryptographic primitive aimed at ensuring integrity and authenticity 
(__secret-key algorithm__).

A MAC takes an input message and a secret key and produces an 
__authentication tag__. The computation is deterministic: the same key and 
message always produce the same tag. Without the secret key, it should be 
computationally infeasible to generate a valid tag for any message.

MACs provide the property of  __existential unforgeability__ under 
chosen-message attack (`EUF-CMA`): even if an attacker can obtain valid tags for 
arbitrarily many messages, they still cannot produce a valid tag for any new 
message they have not queried.

The main security property of MACs are __existential unforgeability__: an adversary
who has observed arbitrarily many input-tag pairs should still be unable to produce
a valid authentication tag for new inputs. They gain no computational advantage in
producing valid tags without the secret key.

Collision refers to two different inputs producing the same tag under the same 
key. While collisions exist in theory, secure MACs are designed so that finding 
them is computationally infeasible.

Vulnerable to __replay attacks__: adversary intercepts a valid message between 
parties to be retransmitted at a later time, which is accepted by the recipient 
as a new, valid, message.

### Hash-based Message Authentication Code (`HMAC`)

MAC constructed using a hash function (e.g., SHA-2). 

Two keys are first created from the secret key; `k1 = k ^ ipad` and 
`k2 = k ^ opad`, where `ipad` (inner padding) and `opad` (outer padding) are 
constants. The message is concatenated with a key, `k1`, to produce a digest, 
which is then concatenated with a key, `k2`, to produce the final digest or 
authentication tag (`HMAC(k, m) = H(k2 || H(k1 || message))`).

### KMAC

`KMAC` is a MAC built from the `cSHAKE` extendable-output function (`XOF`). It
securely encodes the key, message, and customization parameters into the input 
domain of cSHAKE, producing a variable-length authentication tag.

### GMAC

`GMAC` is a MAC derived from the __Galois/Counter Mode__ (`GCM`) construction, 
using the `GHASH` function. GHASH is a polynomial-based function over a finite 
field and is not collision-resistant by itself. It is efficient and works over 
128-bit blocks.

GMAC requires a unique nonce per key and is typically used with `AES-CTR` 
encryption. Reusing a nonce with the same key is catastrophic for security.

### SipHash

`SipHash` is a keyed MAC designed for fast hashing in hash tables.

Non-cryptographic hash tables are vulnerable to denial-of-service attacks where
an adversary can force many hash collisions, degrading performance from 
average O(1) to O(N).

SipHash mitigates this by using a secret random key, making hash outputs 
unpredictable and preventing an attacker from constructing collision-heavy 
inputs.

## Authenticated Encryption

Encryption algorithms (e.g., `AES-CBC`) lack the integrity mechanisms that 
prevents modification of ciphertext and its parameters in-transit by 
adversaries. MACs can be used (e.g., `AES-CBC-HMAC`) to provide integrity by 
encrypting then producing an authentication tag over that ciphertext and its 
parameters. It is best practice to use different keys for different 
cryptographic constructions.

Modern systems use integrated constructions called 
__authenticated encryption with associated data__ (`AEAD`), which provide both 
confidentiality and integrity in a single primitive.

`AES-GCM` (Galois/Counter Mode) is a widely used AEAD scheme that combines 
`AES-CTR` for encryption with `GMAC` for authentication.

`ChaCha20-Poly1305` is another AEAD construction that combines the `ChaCha20` 
stream cipher with the `Poly1305` MAC, offering strong performance and security 
in software implementations.

### ChaCha20

`ChaCha20` is a high-performance stream cipher designed by Daniel J. Bernstein. 
It generates a pseudorandom keystream from a secret key, nonce, and counter.

Encryption is performed by XORing the keystream with plaintext, and decryption 
uses the same process (XOR symmetry). It is widely used in software because it 
is fast, constant-time in typical implementations, and does not rely on hardware 
acceleration like AES.

### Poly1305

`Poly1305` is a message authentication code (MAC) designed for high-speed 
authentication of data. It computes a tag by treating the message as a 
polynomial evaluated over a finite field using a one-time secret key derived 
from the cipher. The resulting tag is used to verify integrity and authenticity 
of the message.

Poly1305 is secure when each key is used only once, which is why it is typically 
paired with a stream cipher that provides per-message key material.

## Asymmetric/Hybrid Encryption

Asymmetric encryption relies on a __key generation algorithm__ and defined 
security parameters to produce a public/private key pair. 

Can also be used for key establishment via a __key encapsulation mechanism__ 
(`KEM`). In a KEM, one party generates a random symmetric key and encrypts 
(encapsulates) it using the recipient’s public key. The recipient then decrypts 
it using their private key to recover the shared symmetric key (e.g., RSA used 
in legacy constructions).

Because asymmetric encryption is inefficient and limited in the size of data it 
can process, real-world systems use __hybrid encryption__, combining asymmetric 
techniques for key exchange with efficient symmetric authenticated encryption 
for data transfer.

### ECIES

The __Elliptic Curve Integrated Encryption Scheme__ (`ECIES`) is a widely used 
hybrid encryption scheme based on ephemeral ECDH. It derives a shared secret 
using elliptic curve Diffie-Hellman and then uses symmetric encryption and MACs 
to provide confidentiality and integrity.

## Signatures and Zero-knowledge Proofs

Digital signatures are used to verify the authenticity and integrity of 
messages.

Signature schemes consists of three algorithms: key generation, signing, and 
verification.

Web __Public Key Infrastructure__ (`PKI`) relies on a chain of trust. 
Certificate authorities sign certificates binding domain names to public keys, 
and browsers verify these signatures to establish trust in a server’s identity.

### Zero-Knowledge Proofs

Interactive zero-knowledge proof protocol consist of a __witness__ (secret known
to the `prover`), a __commitment__ (derived from the witness with randomness), 
a __challenge__ (randomness injected by `verifier`), and a __response__ proving 
knowledge of the witness without revealing it. The verifier’s challenge ensures 
the `prover` cannot rely on precomputed responses 
(e.g., __Schnorr identification protocol__).

The __Fiat-Shamir heuristic__ removes interaction by replacing the verifier’s 
challenge with a deterministic value derived from hashing the protocol 
__transcript__. This allows conversion of interactive proofs into 
non-interactive ones, typically in the __random oracle__ model.

Digital signatures can be viewed as non-interactive zero-knowledge-like 
constructions derived from interactive identification protocols 
(e.g., __Schnorr signature scheme__).

### Elliptic Curve Digital Signature Algorithm (ECDSA)

`ECDSA` is a widely used digital signature scheme based on elliptic curve 
cryptography. It operates over an elliptic curve group with a private key `d` 
and public key `Q = dG`, where `G` is a generator point.

Signing a message involves: computing a hash of the message, generating a fresh 
random nonce `k`, and producing a signature pair (`r`, `s`) derived from 
elliptic curve operations involving `k`, the hash, and the private key.

Verification uses the public key to check that the signature was correctly 
formed without revealing the private key.

ECDSA security depends critically on the secrecy and uniqueness of the nonce 
`k`. Reusing or leaking `k` can reveal the private key.

### Edwards-curve Digital Signature Algorithm (EdDSA)

`EdDSA` is a modern elliptic-curve signature scheme designed to be more robust 
and deterministic than ECDSA, typically used with Edwards curves such as 
`Ed25519`.

Unlike ECDSA, EdDSA does not rely on a per-signature random nonce. Instead, the 
nonce is deterministically derived from hashing the private key and the message, 
eliminating risks from bad randomness.

Signing produces a signature pair (`R`, `S`) using deterministic scalar 
operations over the curve, and verification checks consistency using the public 
key and curve equations.

## Randomness and Secrets

Cryptographic randomness must be unpredictable and follow a 
__uniform distribution__ (each output value is equally likely).

Operating systems gather __entropy__ from physical and system events such as 
hardware interrupts, timing variations, and disk activity. These entropy sources 
are combined to generate randomness, often with the help of 
__true random number generators__ (`TRNG`s) from hardware. To reduce bias and 
noise, __randomness extractors__ (e.g., hash functions) are used to distill 
multiple entropy inputs into uniform random output.

__Pseudorandom number generators__ (`PRNG`s) are used to efficiently generate 
long sequences of random-looking values from an initial secret value called a 
__seed__.

Cryptographically secure PRNGs, also called 
__deterministic random bit generators__ (`DRBG`s), typically satisfy: 

- Deterministic Behavior: using the same seed produces the same sequence of 
  random numbers

- Indistinguishability from randomness: observing the random outputs alone 
  should not allow an adversary to recover the internal state of the PRNG

Some PRNG designs provide __forward secrecy__: compromise of internal state does 
not reveal past outputs, and __backward secrecy__ (recovery resistance): 
compromise does not allow prediction of future outputs, especially when fresh 
entropy is periodically re-injected.

__Verifiable random functions__ (`VRF`s) produce outputs that appear random but 
can be publicly verified as correctly generated. They are typically built using 
public-key cryptography. For example, signature schemes with uniqueness 
properties (e.g., `BLS`) can sign a seed, and the resulting signature is hashed 
to produce a verifiable random value. Anyone can verify correctness using the 
public key.

__Decentralized randomness beacons__ generate publicly verifiable randomness in 
a distributed way, even if some participants are offline or malicious. They 
typically rely on __threshold cryptography__, where a group collectively 
contributes to generating randomness without any single trusted party 
(e.g., `drand`).

__Key derivation__ is the process of generating multiple cryptographic keys from 
a single secret. Unlike PRNGs, key derivation functions assume the input may 
have partial entropy rather than being fully random, and they are designed for 
reproducible outputs across systems rather than continuous randomness 
generation. 

Shamir’s Secret Sharing splits a secret into multiple shares distributed among 
participants.

A trusted dealer generates the secret, divides it into shares, distributes them, 
and deletes the original. A threshold number of shares is required to 
reconstruct the secret.

__Shamir's Secret Sharing__ (`SSS`) decentralizes the issue of key management: a 
trusted __dealer__ generates the secret key, splits it into partial keys, then 
distributes partial keys to participants before deleting the full key. A 
threshold number of shares is required to reconstruct the secret.

__Distributed Key Generation__ (`DKG`) removes the need for a trusted dealer. 
Instead, participants jointly generate a public/private key pair such that no 
single party ever knows the full private key. This eliminates the single point 
of failure present in Shamir’s Secret Sharing.

### HMAC-based key derivation function (HKDF)

`HKDF` is a lightweight key derivation function built on HMAC (commonly using 
SHA-2).

It operates in two stages:

- `HKDF-Extract`: takes input keying material and a __salt__, and produces a 
  pseudorandom key (`PRK`), removing bias and weak entropy structure

- `HKDF-Expand`: expands the PRK into multiple cryptographic keys using 
  context-specific information (`info`)

HKDF is widely used in protocols to derive multiple independent keys from a 
single shared secret.
