# Threat model

## Scope

This document describes who might attack Cipherlink, what they can do, and what
happens. It is written to be useful rather than reassuring: the sections on
what is *not* defended are longer than the sections on what is, because that is
the honest shape of the problem.

**Cipherlink is not anonymity software.** It protects the *content* of your
messages. It does not hide that you are using it, who you talk to, or where you
are connecting from. If you need those properties, you need a different tool —
or this one layered underneath something like Tor, which is outside what this
implementation provides.

---

## Assets

| Asset | Sensitivity |
| --- | --- |
| Message content and attachments | Highest — the point of the system |
| MLS signature private keys | Highest — compromise permits impersonation |
| Group epoch secrets | Highest — compromise permits decryption |
| Vault master key / passphrase | Highest — unlocks everything on a device |
| Device server-auth private key | Moderate — permits acting as the device on the signaling layer only |
| Social graph, timing, volume | Moderate — exposed to the server by design |
| Account existence, usernames | Low — public by construction |

---

## Adversaries

### A1. Compromised signaling server

**Capability:** full control of the server: reads and modifies its database,
observes and alters everything in transit, replays anything, and lies to
clients.

| Attack | Outcome |
| --- | --- |
| Read stored envelopes | **Defended.** Frames are MLS ciphertext; the server holds no group secret. |
| Read attachment blobs | **Defended.** AES-256-GCM with a key that only travels inside MLS ciphertext. Filename and MIME type never reach the server either. |
| Modify a message in transit | **Defended.** AEAD tag and signature fail; the client drops it silently rather than displaying it. |
| Forge a message | **Defended.** No group secret, no signature key. |
| Replay an envelope | **Defended.** MLS rejects duplicates; the application de-duplicates by message id and sequence number. |
| Swap an attachment blob | **Defended.** The ciphertext digest is carried inside the authenticated message. |
| Recover private keys from its database | **Defended.** It only ever receives public keys and public key packages. |
| **Substitute a key package to sit in the middle** | **Detected only by safety-number verification.** Before verification, this attack succeeds. This is the single most important limitation of the system. |
| Deny service | **Not defended.** It can drop or delay anything. |
| Learn the social graph | **Not defended.** See metadata below. |

All of the "defended" rows above are exercised in
`tests/security/serverBlindness.test.ts` against a simulated hostile operator.

### A2. Compromised relay / TURN server

Weaker than A1 for content — it sees the same opaque frames — but on the media
path for a TURN-relayed connection, so it sees packet timing and volume. The
application labels such connections "Direct (via TURN)" rather than "Direct",
and users who want to refuse them can enable "Require a direct connection".

### A3. Passive network observer

Sees TLS-protected traffic to the server, and — on a direct connection — a
DTLS-protected peer-to-peer flow. Learns endpoints, timing and volume. Message
content is protected twice over (MLS inside DTLS/TLS), but **traffic analysis
is not defended**: message sizes and timing are not padded or delayed.

### A4. Active network attacker

Can drop, delay, reorder, replay and inject. Cannot forge or read messages:
every frame is authenticated end-to-end. Injecting garbage causes a dropped
frame and a log line. Replays are rejected. The practical effect is denial of
service and timing manipulation.

### A5. Malicious peer

Someone you are actually in a conversation with. They can read what you send
them — that is what a conversation is — and can screenshot, forward, or retain
it. Nothing in a messaging protocol prevents this, and any product claiming
otherwise is misleading you. Read receipts and typing indicators are off by
default so you do not leak more than the messages themselves.

### A6. Attacker with a stolen device

| Situation | Outcome |
| --- | --- |
| Vault locked | Messages and keys are encrypted; the attacker faces an offline Argon2id (64 MiB, t=3) search against the passphrase. Strength depends entirely on the passphrase. |
| Vault unlocked | **Everything is readable.** Auto-lock limits the window; it does not eliminate it. |
| After the fact | Rotating keys in an ongoing conversation locks the attacker out of future messages (post-compromise security) but not past ones they already hold. |

### A7. Attacker who steals the server database

Gets usernames, doubly-Argon2id-hashed password proofs, device *public* keys,
public key packages, undelivered ciphertext, and encrypted blobs — plus the
metadata below. No message content, no keys that decrypt anything.

### A8. Malicious or compromised client build

**Not defended, and not defensible from inside the application.** Code that
runs in the client can read the plaintext, exfiltrate the vault key, or lie
about the safety number. A strict Content-Security-Policy and same-origin WASM
loading raise the bar against injection, but a hostile build or a supply-chain
compromise defeats the entire model. Users must obtain the client from a source
they trust, and reproducible builds plus binary transparency would be
prerequisites for a real deployment.

---

## Metadata the server can observe

Even with perfect message encryption, operating the server reveals:

- **IP addresses** of every connecting device, and therefore approximate
  location and ISP.
- **Account identifiers and usernames**, and which devices belong to which
  account.
- **Connection times**, session durations, and online/offline transitions.
- **The social graph:** which account claims key packages for which other
  account, and which device relays envelopes to which device.
- **Timing and approximate volume** of relayed messages.
- **Attachment sizes** and upload times.
- **SDP and ICE candidates**, including local and public IP addresses of both
  peers during negotiation.
- **Account existence.** The KDF-parameters endpoint must answer before
  authentication; it returns stable decoy parameters for unknown usernames so
  the response shape does not differ, but timing and other endpoints still make
  enumeration feasible.

Direct P2P connections remove message timing and volume from the server's view,
but reveal your IP address to your contact instead. There is no configuration
in which nobody learns anything.

---

## Threats this application cannot address

Stated explicitly, because a security document that omits them is doing its
readers a disservice:

- **Malware on the device.** A keylogger or screen scraper sees plaintext
  before encryption and after decryption. Encryption is irrelevant to it.
- **A compromised operating system.** Owns the process, the memory and the
  keys.
- **Screenshots and photographs.** Both by the recipient and by anyone near
  either screen.
- **Keyboard logging**, including malicious IMEs and predictive keyboards.
- **A compromised client build or dependency.** See A8.
- **Traffic analysis.** No padding, no cover traffic, no mixing.
- **IP address exposure.** Visible to the server always, and to your peer on a
  direct connection.
- **Account takeover.** Someone with your passphrase can register a new device.
  Your contacts *will* see a new safety number for that device — which is
  exactly why unexplained security-code changes must be taken seriously.
- **Social engineering.** Persuading you to accept a changed security code, or
  to send a message to the wrong person, defeats cryptography entirely.
- **Coercion.** Legal or physical compulsion to unlock a device.
- **Endpoint retention.** Your contact keeps their copy. Deleting yours does
  not delete theirs.
- **Availability.** The operator can silently stop delivering your messages.

---

## Assumptions

The security claims hold only if all of these are true:

1. The client build is genuine and its dependencies are not backdoored.
2. The device and operating system are not compromised.
3. The platform CSPRNG is sound.
4. X25519, Ed25519, ChaCha20-Poly1305, AES-GCM, SHA-2, HKDF and Argon2id are
   not broken, and no cryptographically relevant quantum computer exists.
5. `@wireapp/core-crypto` correctly implements RFC 9420.
6. TLS to the server is correctly configured and validated.
7. **Users actually compare safety numbers.** Without this, a hostile server
   can man-in-the-middle a conversation and nothing will detect it.

Assumption 7 is the one most likely to fail in practice. The interface is built
to push against that — unverified conversations say so, key changes block
sending — but it remains a human step that cryptography cannot take for you.
