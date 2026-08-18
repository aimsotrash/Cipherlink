/**
 * Authenticated encryption for data that lives *outside* the MLS channel:
 * attachment blobs and the local storage vault.
 *
 * Algorithm: AES-256-GCM via WebCrypto (`SubtleCrypto`), i.e. the platform's
 * audited implementation (BoringSSL / NSS / OpenSSL depending on the runtime).
 * We do not implement AES or GCM.
 *
 * Nonce policy — GCM is catastrophically broken by nonce reuse under the same
 * key, so this module makes reuse structurally hard:
 *   - `encrypt` always generates a fresh 96-bit random nonce itself; callers
 *     cannot supply one.
 *   - Attachment keys are single-use (one random key per attachment).
 *   - The vault key is long-lived, but with random 96-bit nonces the birthday
 *     bound only becomes a concern after ~2^32 records; `VaultCipher` tracks
 *     usage and refuses to exceed a conservative fraction of that.
 */
import { constantTimeEqual } from '@p2pchat/shared';
import { randomBytes } from './random.js';

export const AES_KEY_BYTES = 32; // AES-256
export const GCM_NONCE_BYTES = 12; // 96-bit, the only size GCM is proven at
export const GCM_TAG_BITS = 128;

/**
 * Encrypted blob. `nonce` and `ciphertext` are safe to store in the clear;
 * the key never is.
 */
export interface SealedBytes {
  readonly nonce: Uint8Array;
  /** Ciphertext with the 16-byte GCM tag appended (WebCrypto's layout). */
  readonly ciphertext: Uint8Array;
}

function subtle(): SubtleCrypto {
  const c = globalThis.crypto?.subtle;
  if (!c) throw new Error('SubtleCrypto is unavailable; cannot perform authenticated encryption');
  return c;
}

export async function importAesKey(
  keyBytes: Uint8Array,
  usages: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> {
  if (keyBytes.length !== AES_KEY_BYTES) {
    throw new RangeError(`AES-256-GCM requires a ${AES_KEY_BYTES}-byte key`);
  }
  return subtle().importKey('raw', keyBytes as BufferSource, { name: 'AES-GCM' }, false, usages);
}

export function generateAesKey(): Uint8Array {
  return randomBytes(AES_KEY_BYTES);
}

/**
 * Encrypt with a fresh random nonce.
 *
 * `additionalData` is authenticated but not encrypted; use it to bind the
 * ciphertext to its context (record id, blob id) so a valid ciphertext cannot
 * be moved somewhere it does not belong.
 */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData?: Uint8Array,
): Promise<SealedBytes> {
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: nonce as BufferSource,
    tagLength: GCM_TAG_BITS,
  };
  if (additionalData) params.additionalData = additionalData as BufferSource;
  const ciphertext = new Uint8Array(
    await subtle().encrypt(params, key, plaintext as BufferSource),
  );
  return { nonce, ciphertext };
}

/**
 * Decrypt and verify.
 *
 * Throws {@link AuthenticationError} if the tag does not verify — which is the
 * only signal that matters for tampering. The error deliberately carries no
 * detail about *why* verification failed.
 */
export async function open(
  key: CryptoKey,
  sealed: SealedBytes,
  additionalData?: Uint8Array,
): Promise<Uint8Array> {
  if (sealed.nonce.length !== GCM_NONCE_BYTES) {
    throw new AuthenticationError('malformed nonce');
  }
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: sealed.nonce as BufferSource,
    tagLength: GCM_TAG_BITS,
  };
  if (additionalData) params.additionalData = additionalData as BufferSource;
  try {
    return new Uint8Array(await subtle().decrypt(params, key, sealed.ciphertext as BufferSource));
  } catch {
    throw new AuthenticationError('authenticated decryption failed');
  }
}

/** Raised whenever an AEAD tag fails to verify. Never carries plaintext. */
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', bytes as BufferSource));
}

/** Compare two digests without leaking how far they matched. */
export function digestsEqual(a: Uint8Array, b: Uint8Array): boolean {
  return constantTimeEqual(a, b);
}
