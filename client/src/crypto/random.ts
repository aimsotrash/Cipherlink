/**
 * Randomness.
 *
 * Every random value in this application comes from the platform CSPRNG
 * (`crypto.getRandomValues`, backed by the OS entropy source). We never
 * implement a generator, never seed one ourselves, and never fall back to
 * `Math.random()` — a missing WebCrypto implementation is a hard failure.
 */

function subtleCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'A Web Crypto implementation is required. Refusing to fall back to a non-cryptographic RNG.',
    );
  }
  return c;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 65536) {
    throw new RangeError(`invalid random length: ${length}`);
  }
  const out = new Uint8Array(length);
  subtleCrypto().getRandomValues(out);
  return out;
}

/** RFC 4122 v4 identifier from the platform CSPRNG. */
export function randomId(): string {
  const c = subtleCrypto();
  if (typeof c.randomUUID === 'function') return c.randomUUID();
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Best-effort scrub of a secret buffer.
 *
 * JavaScript cannot guarantee a secret is gone — the engine may have copied it
 * during GC, and strings are immutable — but zeroing the buffer we control
 * shortens the window in which it sits in a heap snapshot.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
