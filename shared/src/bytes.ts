/**
 * Isomorphic byte/string helpers shared by client and server.
 *
 * These are encoding utilities only. Nothing here is a cryptographic primitive:
 * all cryptography lives in the client's crypto layer and is delegated to
 * audited libraries (core-crypto / WebCrypto / @noble).
 */

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 encoding of a byte array. */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64_CHARS[b0 >> 2];
    out += B64_CHARS[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? '=' : B64_CHARS[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? '=' : B64_CHARS[b2 & 0x3f];
  }
  return out;
}

/** Decode standard or URL-safe base64 (padding optional) into bytes. */
export function fromBase64(text: string): Uint8Array {
  const normalised = text.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array(Math.floor((normalised.length * 3) / 4));
  let outIndex = 0;
  let acc = 0;
  let accBits = 0;
  for (const ch of normalised) {
    const value = B64_CHARS.indexOf(ch);
    if (value < 0) continue;
    acc = (acc << 6) | value;
    accBits += 6;
    if (accBits >= 8) {
      accBits -= 8;
      out[outIndex++] = (acc >> accBits) & 0xff;
    }
  }
  return out.subarray(0, outIndex);
}

/** URL-safe, unpadded base64. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const fromBase64Url = fromBase64;

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/**
 * Length-independent, content-constant-time equality.
 *
 * Used for comparing authentication tags, digests and fingerprints so that
 * comparison time does not leak how many leading bytes matched.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
