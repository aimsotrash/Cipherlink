# Security model

This document states precisely what Cipherlink does cryptographically, what
properties follow, and where those properties stop. Claims here are scoped to
the implementation in this repository and the threat model in
[THREAT_MODEL.md](THREAT_MODEL.md).

**This code has not been audited.** It has a test suite that demonstrates its
central claims (`tests/security/`), which is not the same thing as having been
attacked by competent people.

---

## Algorithms and key sizes

### Messaging (MLS, RFC 9420)

Ciphersuite 3: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.

| Function | Algorithm | Parameters |
| --- | --- | --- |
| Key agreement | X25519 within HPKE DHKEM | 256-bit keys, ~128-bit classical security |
| Signatures | Ed25519 | 256-bit keys, ~128-bit classical security |
| AEAD | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce, 128-bit tag |
| KDF | HKDF-SHA-256 | 256-bit output |
| Hash | SHA-256 | — |

### Everything else

| Function | Algorithm | Parameters |
| --- | --- | --- |
| Attachment encryption | AES-256-GCM (WebCrypto) | 256-bit key, 96-bit random nonce, 128-bit tag |
| Local record encryption | AES-256-GCM (WebCrypto) | 256-bit key, 96-bit random nonce, record key as AAD |
| Vault key wrapping | AES-256-GCM (WebCrypto) | 256-bit key |
| Passphrase stretching | Argon2id (`@noble/hashes`) | 64 MiB, t=3, p=1, 32-byte output |
| Server-side proof hashing | Argon2id (`@noble/hashes`) | 32 MiB, t=2, p=1, per-account salt |
| Vault subkey derivation | HKDF-SHA-256 (WebCrypto) | Distinct `info` per purpose |
| Safety numbers | PBKDF2-HMAC-SHA-512 (WebCrypto) | 5200 iterations, 30-byte output per party |
| Device server-auth signatures | Ed25519 (`@noble/curves`) | 256-bit keys |
| Randomness | Platform CSPRNG | `crypto.getRandomValues` |

### On "256-bit"

Do not describe this application as "256-bit encrypted". The AEAD keys are 256
bits, but the security of the system as a whole is bounded by the elliptic-curve
parameters: **X25519 and Ed25519 both provide roughly 128 bits of classical
security.** The "128" in the MLS ciphersuite name refers to exactly that.

There is no post-quantum protection. A future adversary with a
cryptographically relevant quantum computer could break X25519 key agreement,
including against traffic recorded today ("harvest now, decrypt later"). MLS
supports post-quantum ciphersuites in principle; this deployment does not use
one.

### Why not implement anything ourselves

No cryptographic primitive, and no part of the messaging protocol, is
implemented in this repository. AES, ChaCha20, X25519, Ed25519, HKDF, Argon2id,
PBKDF2, SHA-2 and the MLS key schedule are all delegated to established
implementations (`@wireapp/core-crypto`, WebCrypto, `@noble/*`).

---

## Why MLS

The requirement was to use an established secure-messaging protocol rather than
design one. The realistic candidates for a browser-capable TypeScript client
were:

| Option | Verdict |
| --- | --- |
| **MLS via `@wireapp/core-crypto`** | **Chosen.** IETF standard (RFC 9420) with substantial formal analysis of its key schedule. Rust implementation with matching WASM and Node builds, actively maintained. Provides forward secrecy, post-compromise security, and native multi-device/multi-member semantics. |
| `@signalapp/libsignal-client` | Signal's own implementation, and an excellent one — but it ships **Node/Electron native bindings only**, with no WASM build. A browser client cannot use it. |
| `libsignal-protocol-javascript` | Signal's old JS port. Unmaintained and deprecated. Using abandoned cryptography to avoid writing our own is not an improvement. |
| `@matrix-org/olm` | Audited Double Ratchet implementation, but deprecated upstream in favour of vodozemac. |
| Noise Protocol Framework | Mature and audited, and gives authenticated key exchange with forward secrecy — but no ratchet, so no post-compromise security. Would have required building the ratchet ourselves, which is precisely what the brief forbids. |
| Hand-rolled X3DH + Double Ratchet | Explicitly ruled out. |

The deciding factor was that core-crypto's browser and Node builds are
generated from the same Rust source by uniffi and expose an identical API. The
protocol code exercised by the test suite in Node is therefore the same code
the browser runs — the tests are not testing a stand-in.

---

## Protocol properties

### Authentication

Every MLS message is signed by the sending device's Ed25519 credential and
authenticated by the AEAD tag. A message that fails either check is rejected by
core-crypto before this application sees any content.

Group membership is authenticated by the MLS tree: only current members hold
the epoch secrets, so a non-member cannot produce a message that decrypts.

**Where authentication is incomplete:** MLS Basic credentials bind a signature
key to a client identifier with no external attestation. The binding this
application relies on comes from the key-package directory, which the server
operates. A hostile server can substitute its own key package. This is detected
only by safety-number verification.

### Confidentiality

Message content is encrypted on the sender's device and decrypted on the
recipient's. The server holds no group secret for any conversation. This is
demonstrated adversarially in `tests/security/serverBlindness.test.ts`, which
gives a simulated hostile operator its full database, an archive of every
relayed frame, and the ability to tamper, forge, replay and swap blobs.

### Forward secrecy

MLS derives per-message keys from an epoch secret tree and deletes them after
use. Compromising a device does not reveal earlier messages, *except* those
still present in that device's local message database — which is the normal
trade-off for a chat app that shows you your history. Deleting messages, or
using the "erase local data" control, removes them.

### Post-compromise security

An MLS commit replaces the group's keying material and advances the epoch. An
attacker holding epoch *N*'s secrets cannot read epoch *N+1*. Commits are
issued automatically after 100 messages or 24 hours, and on demand from the
conversation header.

### Replay protection

Three independent layers:

1. **MLS** rejects a repeated application message: per-message keys are
   consumed, and generation counters are tracked.
2. **Application-level de-duplication** rejects a message id already seen in
   the session, and a sender sequence number that does not advance.
3. **Relay envelopes** are deleted on acknowledgement.

Server auth challenges are single-use: the challenge row is deleted *before*
the signature is verified, so a nonce is spent whether or not the attempt
succeeded.

### Integrity

Any modification to a ciphertext fails the AEAD tag or the signature. The
application never displays or stores a message that failed to authenticate; a
rejected frame produces a log line with an error code and nothing else.

Attachments additionally carry a SHA-256 digest of the ciphertext inside the
authenticated message, so a relay substituting a different blob is detected
before decryption.

### Session establishment and termination

Establishment is described in [ARCHITECTURE.md](ARCHITECTURE.md#session-establishment).

Termination removes this device from the group (telling the peer the session is
over) and then wipes the conversation's local key material, so the epoch
secrets are gone from the device. Re-establishment is a fresh group with fresh
key packages.

### Key rotation

Covered above under post-compromise security. Additionally, one-time key
packages are consumed on claim and never reissued, and the client republishes
when its published supply falls below a low-water mark.

---

## Server trust assumptions

**The server is not trusted with message content, and the design does not
require it to be.** It is trusted for availability, and for the correctness of
introductions *unless users verify safety numbers*.

The server **cannot**:

- read message content, attachment content, filenames or MIME types;
- forge a message that a client will accept;
- undetectably modify a message in transit;
- replay a message usefully;
- recover a private identity key, session key or attachment key, from the
  database or from anything transmitted to it.

The server **can**:

- refuse service, drop messages, or delay them;
- see who exchanges messages with whom, when, and roughly how much;
- see IP addresses, SDP and ICE candidates;
- substitute a key package during an introduction, attempting a
  man-in-the-middle — **detected by safety-number verification, and only by
  that**;
- learn that an account exists, and enumerate an account's devices.

A compromise of the server database yields: usernames, doubly-Argon2id-hashed
password proofs, device public keys, public key packages, undelivered
ciphertext envelopes with routing metadata, and encrypted attachment blobs. It
does not yield anything that decrypts a message.

---

## Local storage security

Described in [ARCHITECTURE.md](ARCHITECTURE.md#local-storage). In summary:

- Private identity keys, session keys and message keys are **never** written in
  plaintext. The MLS store is encrypted with a vault-derived key; application
  records are individually AEAD-sealed.
- The Argon2id parameters (64 MiB, t=3) are what stand between an attacker with
  a copy of the browser profile and an offline passphrase search.
- The vault locks on idle and zeroes the master key.

Limitations, stated rather than glossed:

- **No OS keychain in a browser.** The master key is in JavaScript memory while
  unlocked.
- **Zeroing is best-effort.** JavaScript engines copy during garbage collection
  and strings are immutable; `wipe()` shortens the window, it does not close it.
- **IndexedDB is not tamper-proof storage.** Record-key AAD binding detects a
  moved record, but an attacker with write access can still delete data.

---

## Logging

The logger redacts by field name and never renders binary — byte arrays become
`<bytes:N>`. Message bodies are not passed to the logger at all; redaction is a
backstop, not the primary control. `tests/security/logging.test.ts` asserts
both the unit behaviour and that a real end-to-end exchange leaves no plaintext
in client or server logs.

The server logs route patterns rather than URLs, so path parameters (usernames,
blob ids) do not reach an access log, and never logs request bodies.

---

## Reporting

This is a reference implementation without a deployment, so there is no
security contact or disclosure process. If you are building on it, establish
one before you have users.
