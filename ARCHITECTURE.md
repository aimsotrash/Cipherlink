# Architecture

## Design principles

1. **The server is infrastructure, not a party.** It routes, stores and
   introduces. It is never given anything it could use to read a message.
2. **No custom cryptography.** Every primitive and the messaging protocol
   itself come from established implementations. This repository contains
   protocol *plumbing*, not protocol *design*.
3. **Fail closed.** A message that does not authenticate is dropped, not shown
   with a warning. An identity that changes blocks sending until a human looks
   at it. A missing WebCrypto implementation is a hard error, not a fallback.
4. **Say what is true.** The interface distinguishes "encrypted" from
   "verified", and "direct" from "relayed", because conflating them is how
   users end up with a false sense of what they have.

---

## Components

```
┌──────────────────────────────────── client ─────────────────────────────────┐
│                                                                             │
│  ui/            React: conversations, chat, verification, settings          │
│      │                                                                      │
│  app/session    assembles everything from a passphrase                      │
│      │                                                                      │
│  messaging/     message lifecycle, receipts, rotation policy, trust checks   │
│      │                                                                      │
│  ├── crypto/    MLS engine (core-crypto), attachment AEAD, RNG              │
│  ├── identity/  device auth key, safety numbers, trust store                │
│  ├── storage/   vault (Argon2id → HKDF), encrypted records, repositories    │
│  └── p2p/       WebRTC channel, peer link state machine, signaling, REST    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                        HTTPS + WebSocket (TLS)
                                     │
┌──────────────────────────────────── server ─────────────────────────────────┐
│                                                                             │
│  identity/registry   accounts, devices, Ed25519 challenge auth,             │
│                      key package directory                                  │
│  signaling/hub       WebSocket: auth, SDP/ICE routing, presence,            │
│                      relay delivery                                         │
│  relay/queue         store-and-forward queue of opaque frames               │
│  relay/blobs         encrypted attachment blobs + upload rate limiting      │
│  db                  SQLite; schema has nowhere to put plaintext            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Three identities, deliberately separate

The brief requires — and the security model depends on — not collapsing these
into one credential.

| Layer | What it is | Where the private half lives | What compromise costs |
| --- | --- | --- | --- |
| **Account** | username + passphrase-derived proof | Nowhere; only a doubly-hashed proof is stored server-side | An attacker can register *new devices* on the account. They cannot read existing conversations or impersonate an existing device. |
| **Device (server auth)** | Ed25519 keypair generated on the device | In the encrypted vault, never transmitted | An attacker can talk to the signaling server as that device: send/receive relayed ciphertext, read presence. They cannot decrypt anything. |
| **Device (messaging)** | MLS Ed25519 signature credential | Inside core-crypto's encrypted store, never exported, no API to export it | An attacker can impersonate the device in MLS groups it is a member of. This is the identity safety numbers verify. |

The account passphrase gates *device registration only*. After that, a device
authenticates by signing a server nonce with a key it holds locally, so a
stolen password does not by itself yield a working session.

Multi-device works without ever sharing a private key: each device generates
its own MLS credential and publishes its own key packages, and a conversation
adds every device as a separate MLS member. Contacts see — and can verify — a
distinct safety number per device.

---

## Session establishment

```
Alice                          Server                            Bob
  │                              │                                │
  │                              │◄── publish key packages ───────┤   (ahead of time)
  │                              │                                │
  ├── lookup "bob" ─────────────►│                                │
  │◄── userId + device list ─────┤                                │
  ├── claim key packages ───────►│                                │
  │◄── one per device (consumed)─┤                                │
  │                              │                                │
  │  create MLS group                                             │
  │  add Bob's key packages  ──► produces Commit + Welcome        │
  │                              │                                │
  ├── Welcome (opaque) ─────────►│─── relay or DataChannel ──────►│
  │                              │                                │  process Welcome
  │                              │                                │  → joined, epoch 1
  │◄═══════════ application messages, both directions ═══════════►│
```

A key package is the MLS analogue of a prekey bundle: a credential, a signature
public key and a one-time HPKE init key. The server hands out each exactly once
and deletes it.

**The trust gap, stated plainly.** The server chooses which key package to hand
over, and MLS Basic credentials carry no external attestation. A hostile server
can therefore offer its own key package and sit in the middle. Nothing in the
protocol detects this. Safety-number verification does, and it is the only
thing that does — which is why the UI refuses to describe an unverified
conversation as anything more than encrypted.

---

## Message lifecycle

### Outbound

```
User writes a message
        ↓
messaging/ builds an AppPayload
    { kind: 'text', id, sentAt, seq, body, attachments? }
        ↓
JSON → UTF-8 bytes
        ↓
MlsEngine.encrypt(conversationId, bytes)
    · derives a per-message key from the epoch secret tree
    · AEAD-encrypts with ChaCha20-Poly1305
    · signs with the device's Ed25519 credential
        ↓
Ciphertext (opaque)
        ↓
TransportFrame { v, type: 'mls-app', conversationId, payload: base64 }
        ↓
TransportManager → PeerLink
        ↓
   ┌────────────────────┴────────────────────┐
   │                                         │
WebRTC DataChannel                    Server relay
(direct, or via TURN)                 (store-and-forward)
   │                                         │
   └────────────────────┬────────────────────┘
                        ↓
                      Peer
```

### Inbound

```
TransportFrame arrives (DataChannel or relay)
        ↓
Schema validation — malformed frames are dropped, never salvaged
        ↓
MlsEngine.decrypt(conversationId, ciphertext)
    · verifies the sender's signature
    · verifies the AEAD tag
    · rejects replays and out-of-epoch messages
        ↓                              ↓
    authenticated                  rejected → logged by code only,
        ↓                                     nothing shown to the user
Sender's signature-key thumbprint checked against the trust store
    · unchanged  → continue
    · changed    → recorded as `changed`, surfaced to the user,
                   outgoing messages held
        ↓
AppPayload schema validation (authenticated, but still untrusted structure)
        ↓
Duplicate suppression: message id seen? sequence number regressed?
        ↓
Stored via the encrypted repository (AES-256-GCM at rest)
        ↓
Displayed, and a delivery receipt sent back through the same encrypted channel
```

Note the ordering: **authentication happens before anything is stored, parsed
as an application payload, or shown.** Content is never rendered on the basis
of an unverified frame.

### Attachments

```
sender                                    relay                    recipient
──────                                    ─────                    ─────────
file bytes
  │ fresh random AES-256 key
  │ fresh random 96-bit nonce
  │ filename + MIME bound in as AAD
  ▼
ciphertext ─────── upload ──────────────► stores opaque blob
  │                                        (no name, no type,
  │                                         no owner recorded)
  │
  │ descriptor { blobId, key, iv, digest,
  │              filename, mimeType, size }
  │ placed inside an MLS application message
  ▼
────────────── encrypted channel ─────────────────────────────────► descriptor
                                                                      │
                                          download ◄─────────────────┤
                                                                      │
                                          verify SHA-256 of ciphertext
                                          against the digest
                                                                      ▼
                                                              AES-256-GCM open
                                                                   → file bytes
```

Each attachment gets its own key, used once, so GCM nonce reuse across
attachments is impossible by construction. The digest binds the blob to the
message, so a relay that serves different bytes is caught before decryption is
attempted rather than surfacing as a confusing AEAD failure.

---

## P2P and relay behaviour

`PeerLink` is a state machine per peer device:

```
        idle
          │ connect()
          ▼
     connecting ──── success ────► connected (p2p-direct | p2p-turn)
          │                             │
      failure                    channel drops
          │                             │
          ▼                             ▼
   relay-only ◄──────────────────── reconnecting
     │     ▲                            │
     │     └──── retry with backoff ────┘
     │
     └── periodic upgrade attempt ──► connecting
```

- **Direct first.** Every link tries WebRTC before anything else, and keeps
  trying to upgrade while it is on the relay.
- **Glare avoidance.** The peer whose address sorts lower sends the offer, so
  two devices connecting simultaneously do not deadlock.
- **Fallback changes nothing about confidentiality.** Frames handed to the
  transport are already MLS ciphertext. Falling back to the relay is a privacy
  and latency downgrade — the server learns timing and volume, and holds the
  envelope until collection — never a confidentiality one.
- **TURN is reported honestly.** A connection routed through TURN is shown as
  "Direct (via TURN)", not "Direct", because the operator is on the media path.
- **The user can refuse both.** "Require a direct connection" rejects TURN
  candidates; disabling relay fallback makes messages fail rather than be
  relayed.

Relay envelopes are deleted the moment the recipient device acknowledges them,
and expire after seven days regardless. Acknowledgement is scoped to the
addressed device, so one account cannot delete another's queue.

---

## Key rotation

Group keys advance in two ways:

- **Automatically**, after 100 outbound messages or 24 hours, whichever comes
  first (`REKEY_AFTER_MESSAGES` / `REKEY_AFTER_MS`).
- **Manually**, from the ⟳ button in the conversation header.

Both issue an MLS self-update commit, which advances the epoch and replaces the
group's keying material. This is what provides post-compromise security: an
attacker who obtained epoch *N*'s secrets cannot read epoch *N+1*.

Forward secrecy in the other direction comes from the MLS key schedule itself —
per-message keys are derived from a secret tree and deleted after use, so
compromising a device today does not reveal yesterday's messages that are no
longer in local storage.

---

## Local storage

```
passphrase
    │ Argon2id (64 MiB, t=3, unique salt)
    ▼
wrapping key ──AES-256-GCM──► [wrapped master key]   (stored in the clear)
                                        │
                                   master key        (memory only, zeroed on lock)
                                        │ HKDF-SHA-256
              ┌─────────────────────────┼─────────────────────────┐
              ▼                         ▼                         ▼
     MLS database key           records key              device auth key
     (core-crypto store:        (messages, contacts,     (Ed25519 private key
      private signature key,     trust state, settings)   for server auth)
      group secrets)
```

Records are sealed individually with their own key name as GCM additional
authenticated data, so a valid encrypted record cannot be moved from one slot
to another — an attacker with database write access cannot, for example, swap
one contact's verified identity onto another contact.

The vault locks on demand and after a configurable idle period, zeroing the
master key.

**Honest limitation:** a browser has no OS keychain and no secure enclave. The
master key lives in JavaScript memory while unlocked and is readable by anything
with code execution in the origin. A packaged desktop or mobile build should
wrap the master key with the platform keychain. See
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## What the server stores

| Table | Contents | Why it exists |
| --- | --- | --- |
| `accounts` | username, doubly-hashed password proof, public KDF parameters | Account recovery of *device registration* only |
| `devices` | device id, label, **Ed25519 public** auth key, timestamps | Authenticating devices |
| `key_packages` | public MLS key packages | Introducing users; each consumed once |
| `auth_challenges` | nonce, expiry | One-shot challenge/response |
| `auth_tokens` | SHA-256 of the token, expiry | Session lookup without storing a usable token |
| `relay_envelopes` | opaque frame, addresses, timestamps | Store-and-forward when P2P fails |
| `blobs` | opaque ciphertext, size, expiry | Encrypted attachments |
| `blob_quota` | per-account bytes in a rolling window | Rate limiting **without** linking a blob to an uploader |

There is no column anywhere that could hold message text, a private key, a
session secret, a filename, or a MIME type. `blob_quota` is a counter rather
than an ownership ledger specifically so that no row associates an account with
a stored attachment.

What the server nonetheless observes is documented in
[THREAT_MODEL.md](THREAT_MODEL.md#metadata-the-server-can-observe).
