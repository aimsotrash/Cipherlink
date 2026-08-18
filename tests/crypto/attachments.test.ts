import { describe, expect, it } from 'vitest';
import { toBase64, fromBase64, type AttachmentDescriptor } from '@p2pchat/shared';
import {
  decryptAttachment,
  encryptAttachment,
  safeFilename,
} from '../../client/src/crypto/attachments.js';
import { AuthenticationError, generateAesKey } from '../../client/src/crypto/aead.js';
import { flipBitAt } from '../helpers/tamper.js';

const META = { filename: 'notes.txt', mimeType: 'text/plain' };
const CONTENT = new TextEncoder().encode('classified: the cake is a lie');

function descriptorFor(
  secrets: Omit<AttachmentDescriptor, 'blobId'>,
  blobId = 'blob-1',
): AttachmentDescriptor {
  return { ...secrets, blobId };
}

describe('attachment encryption', () => {
  it('round-trips a file', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const plaintext = await decryptAttachment(
      encrypted.ciphertext,
      descriptorFor(encrypted.secrets),
    );
    expect(new TextDecoder().decode(plaintext)).toBe('classified: the cake is a lie');
  });

  it('produces ciphertext containing neither the content nor the filename', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const haystack = Buffer.from(encrypted.ciphertext);
    expect(haystack.includes(Buffer.from('cake is a lie'))).toBe(false);
    expect(haystack.includes(Buffer.from('notes.txt'))).toBe(false);
  });

  it('uses a fresh key and nonce for every attachment', async () => {
    const first = await encryptAttachment(CONTENT, META);
    const second = await encryptAttachment(CONTENT, META);

    expect(first.secrets.key).not.toBe(second.secrets.key);
    expect(first.secrets.iv).not.toBe(second.secrets.iv);
    // Identical plaintext must not produce identical ciphertext.
    expect(Buffer.from(first.ciphertext)).not.toEqual(Buffer.from(second.ciphertext));
    expect(fromBase64(first.secrets.key)).toHaveLength(32);
    expect(fromBase64(first.secrets.iv)).toHaveLength(12);
  });

  it('rejects ciphertext that was modified', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const tampered = flipBitAt(encrypted.ciphertext, 0, 0xff);

    await expect(
      decryptAttachment(tampered, descriptorFor(encrypted.secrets)),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects a blob whose digest does not match the descriptor', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const other = await encryptAttachment(new TextEncoder().encode('different'), META);

    // The relay serves a blob that is valid in itself, but not the one the
    // message referred to.
    await expect(
      decryptAttachment(other.ciphertext, descriptorFor(encrypted.secrets)),
    ).rejects.toThrow(/does not match the digest/);
  });

  it('rejects a descriptor whose metadata was altered', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const swapped = descriptorFor({ ...encrypted.secrets, filename: 'innocent.txt' });

    // Filename and MIME type are bound in as GCM additional authenticated
    // data, so renaming the file breaks decryption rather than succeeding.
    await expect(decryptAttachment(encrypted.ciphertext, swapped)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('rejects the wrong key', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const wrongKey = descriptorFor({ ...encrypted.secrets, key: toBase64(generateAesKey()) });
    await expect(decryptAttachment(encrypted.ciphertext, wrongKey)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('rejects a malformed nonce rather than guessing', async () => {
    const encrypted = await encryptAttachment(CONTENT, META);
    const shortNonce = descriptorFor({ ...encrypted.secrets, iv: toBase64(new Uint8Array(8)) });
    await expect(decryptAttachment(encrypted.ciphertext, shortNonce)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('handles an empty file', async () => {
    const encrypted = await encryptAttachment(new Uint8Array(0), META);
    const plaintext = await decryptAttachment(
      encrypted.ciphertext,
      descriptorFor(encrypted.secrets),
    );
    expect(plaintext).toHaveLength(0);
  });

  it('refuses an attachment over the size limit', async () => {
    const huge = new Uint8Array(33 * 1024 * 1024);
    await expect(encryptAttachment(huge, META)).rejects.toThrow(/limit is/);
  });
});

describe('filename sanitisation', () => {
  it('strips path components from a peer-supplied name', () => {
    expect(safeFilename('../../.bashrc')).toBe('bashrc');
    expect(safeFilename('/etc/passwd')).toBe('passwd');
    expect(safeFilename('C:\\Windows\\system32\\drivers\\etc\\hosts')).toBe('hosts');
  });

  it('strips control characters used to disguise an extension', () => {
    expect(safeFilename('invoice\u202e' + 'gpj.exe')).not.toContain('\u0000');
    expect(safeFilename('report\u0000.pdf')).toBe('report.pdf');
    expect(safeFilename('a\u001fb.txt')).toBe('ab.txt');
  });

  it('falls back rather than producing an empty name', () => {
    expect(safeFilename('')).toBe('attachment');
    expect(safeFilename('...')).toBe('attachment');
    expect(safeFilename('/')).toBe('attachment');
  });

  it('caps absurdly long names', () => {
    expect(safeFilename('x'.repeat(5000)).length).toBe(200);
  });

  it('leaves an ordinary name untouched', () => {
    expect(safeFilename('Quarterly Report (final).pdf')).toBe('Quarterly Report (final).pdf');
  });
});
