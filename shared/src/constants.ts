/** Wire protocol version. Bumped on any breaking change to frames or envelopes. */
export const PROTOCOL_VERSION = 1;

/**
 * MLS ciphersuite used by every client in this deployment.
 *
 * 3 = MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (RFC 9420 §17.1)
 *   - Key agreement:   X25519 (HPKE DHKEM)
 *   - Signatures:      Ed25519
 *   - AEAD:            ChaCha20-Poly1305 (256-bit key, 96-bit nonce)
 *   - KDF / hash:      HKDF-SHA-256
 *
 * Note on naming: the "128" refers to the ciphersuite's target security level
 * (X25519 offers roughly 128-bit classical security), NOT the AEAD key size.
 * See SECURITY.md for the full breakdown; do not describe this as "256-bit".
 */
export const MLS_CIPHERSUITE = 3;

/** Domain component of the MLS client identifier (`<user>:<device>@<domain>`). */
export const MLS_DOMAIN = 'p2pchat.local';

/** Maximum size of a single decrypted application payload (1 MiB). */
export const MAX_APP_PAYLOAD_BYTES = 1024 * 1024;

/** Maximum size of an encrypted attachment blob accepted by the relay (32 MiB). */
export const MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024;

/** Maximum size of a single transport frame on the wire (2 MiB, base64 inflated). */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024;

/** How many key packages a client tries to keep published on the directory. */
export const TARGET_KEY_PACKAGE_COUNT = 20;

/** Refill key packages when the server-side count drops below this. */
export const KEY_PACKAGE_LOW_WATERMARK = 5;

/**
 * Re-key the MLS group (self-update commit, advancing the epoch) after this many
 * outbound application messages, or after this much wall-clock time — whichever
 * comes first. Advancing the epoch gives post-compromise security.
 */
export const REKEY_AFTER_MESSAGES = 100;
export const REKEY_AFTER_MS = 24 * 60 * 60 * 1000;

/** Server-issued auth challenges expire quickly to limit replay windows. */
export const AUTH_CHALLENGE_TTL_MS = 60_000;

/** Session tokens issued after a successful device-key challenge. */
export const AUTH_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

/** How long the relay retains an undelivered ciphertext envelope. */
export const RELAY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

/** How long the relay retains an encrypted attachment blob. */
export const BLOB_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** Maximum queued relay envelopes per recipient device. */
export const RELAY_MAX_QUEUE_PER_DEVICE = 5000;
