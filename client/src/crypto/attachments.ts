/**
 * Client-side attachment encryption.
 *
 * Attachments never reach the relay in the clear. The flow is:
 *
 *   sender:   file bytes
 *             -> fresh random AES-256 key + fresh random 96-bit nonce
 *             -> AES-256-GCM  ->  opaque blob  ->  uploaded to the relay
 *             -> {blobId, key, nonce, ciphertextDigest} placed in an MLS
 *                application message (so the key travels only inside the
 *                authenticated, end-to-end encrypted channel)
 *
 *   receiver: download blob -> verify SHA-256 digest against the descriptor
 *             -> AES-256-GCM open -> file bytes
 *
 * The relay stores a blob it cannot name, read, or associate with a filename;
 * it learns the ciphertext length and the uploading account. See SECURITY.md.
 *
 * Each attachment gets its own key, used exactly once, so GCM nonce reuse
 * across attachments is impossible by construction.
 */
import {
  fromBase64,
  toBase64,
  utf8Encode,
  type AttachmentDescriptor,
  MAX_ATTACHMENT_BYTES,
} from '@p2pchat/shared';
import {
  AuthenticationError,
  digestsEqual,
  generateAesKey,
  importAesKey,
  open,
  seal,
  sha256,
} from './aead.js';
import { wipe } from './random.js';

export interface EncryptedAttachment {
  /** Opaque bytes to upload. Safe for an untrusted relay to hold. */
  readonly ciphertext: Uint8Array;
  /**
   * Everything the recipient needs, minus the blob id (assigned by the relay
   * on upload). Must only ever be sent inside an MLS application message.
   */
  readonly secrets: Omit<AttachmentDescriptor, 'blobId'>;
}

export interface AttachmentMetadata {
  readonly filename: string;
  readonly mimeType: string;
}

/**
 * Reduce a peer-supplied filename to a safe basename.
 *
 * The descriptor is authenticated, so this is not defending against the relay
 * — it is defending against a *peer* who names a file `../../.bashrc` or
 * embeds control characters. Applied on display and on save, never before
 * encryption, so it cannot change the AAD the sender committed to.
 */
export function safeFilename(filename: string, fallback = 'attachment'): string {
  const basename = filename.split(/[/\\]/).pop() ?? '';
  const cleaned = basename
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 200);
  return cleaned.length > 0 ? cleaned : fallback;
}

/**
 * Bind the ciphertext to its metadata via GCM additional authenticated data,
 * so a relay cannot swap the blob for another one this user uploaded and have
 * it decrypt cleanly under a re-used descriptor.
 */
function attachmentAad(metadata: AttachmentMetadata, plaintextSize: number): Uint8Array {
  return utf8Encode(
    JSON.stringify({
      v: 1,
      filename: metadata.filename,
      mimeType: metadata.mimeType,
      size: plaintextSize,
    }),
  );
}

export async function encryptAttachment(
  plaintext: Uint8Array,
  metadata: AttachmentMetadata,
): Promise<EncryptedAttachment> {
  if (plaintext.length > MAX_ATTACHMENT_BYTES) {
    throw new RangeError(
      `attachment is ${plaintext.length} bytes, limit is ${MAX_ATTACHMENT_BYTES}`,
    );
  }

  const keyBytes = generateAesKey();
  try {
    const key = await importAesKey(keyBytes, ['encrypt']);
    const aad = attachmentAad(metadata, plaintext.length);
    const sealed = await seal(key, plaintext, aad);
    const digest = await sha256(sealed.ciphertext);

    return {
      ciphertext: sealed.ciphertext,
      secrets: {
        key: toBase64(keyBytes),
        iv: toBase64(sealed.nonce),
        ciphertextDigest: toBase64(digest),
        filename: metadata.filename,
        mimeType: metadata.mimeType,
        size: plaintext.length,
      },
    };
  } finally {
    // The key now lives only in the descriptor that goes into MLS ciphertext.
    wipe(keyBytes);
  }
}

export async function decryptAttachment(
  ciphertext: Uint8Array,
  descriptor: AttachmentDescriptor,
): Promise<Uint8Array> {
  const expectedDigest = fromBase64(descriptor.ciphertextDigest);
  const actualDigest = await sha256(ciphertext);
  if (!digestsEqual(actualDigest, expectedDigest)) {
    // The relay served bytes other than the ones the sender uploaded.
    throw new AuthenticationError('attachment blob does not match the digest in the message');
  }

  const keyBytes = fromBase64(descriptor.key);
  try {
    const key = await importAesKey(keyBytes, ['decrypt']);
    const aad = attachmentAad(
      { filename: descriptor.filename, mimeType: descriptor.mimeType },
      descriptor.size,
    );
    const plaintext = await open(key, { nonce: fromBase64(descriptor.iv), ciphertext }, aad);
    if (plaintext.length !== descriptor.size) {
      throw new AuthenticationError('attachment size does not match the message descriptor');
    }
    return plaintext;
  } finally {
    wipe(keyBytes);
  }
}
