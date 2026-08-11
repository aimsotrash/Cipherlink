/**
 * Encrypted record store.
 *
 * Wraps a {@link KeyValueStore} so that every value written is AES-256-GCM
 * sealed under a vault-derived key before it touches disk, and every value
 * read is authenticated on the way back.
 *
 * The record's own key name is passed as GCM additional authenticated data.
 * That binds each ciphertext to its slot: an attacker with write access to
 * IndexedDB cannot move a valid encrypted record from one key to another (for
 * instance, replacing a contact's verified identity with a different contact's
 * record) without the tag failing.
 *
 * Note what this protects and what it does not. It protects data at rest
 * against someone who reads the browser profile while the app is locked. It
 * does not protect against code running in the origin while unlocked.
 */
import { AuthenticationError, open, seal } from '../crypto/aead.js';
import { utf8Encode, type Logger, silentLogger } from '@p2pchat/shared';
import type { KeyValueStore } from './kv.js';

const RECORD_VERSION = 1;

/**
 * On-disk layout: [version:1][nonce:12][ciphertext‖tag].
 * Framing is fixed-width so parsing cannot be ambiguous.
 */
function encodeRecord(nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + nonce.length + ciphertext.length);
  out[0] = RECORD_VERSION;
  out.set(nonce, 1);
  out.set(ciphertext, 1 + nonce.length);
  return out;
}

function decodeRecord(bytes: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
  if (bytes.length < 1 + 12 + 16) throw new AuthenticationError('record is truncated');
  if (bytes[0] !== RECORD_VERSION) throw new AuthenticationError('unsupported record version');
  return { nonce: bytes.subarray(1, 13), ciphertext: bytes.subarray(13) };
}

export class EncryptedStore {
  private readonly logger: Logger;

  constructor(
    private readonly backend: KeyValueStore,
    private readonly key: CryptoKey,
    logger: Logger = silentLogger,
  ) {
    this.logger = logger.child('storage');
  }

  async putRaw(recordKey: string, plaintext: Uint8Array): Promise<void> {
    const sealed = await seal(this.key, plaintext, utf8Encode(recordKey));
    await this.backend.set(recordKey, encodeRecord(sealed.nonce, sealed.ciphertext));
  }

  async getRaw(recordKey: string): Promise<Uint8Array | undefined> {
    const stored = await this.backend.get(recordKey);
    if (!stored) return undefined;
    const { nonce, ciphertext } = decodeRecord(stored);
    return open(this.key, { nonce, ciphertext }, utf8Encode(recordKey));
  }

  async put<T>(recordKey: string, value: T): Promise<void> {
    await this.putRaw(recordKey, utf8Encode(JSON.stringify(value)));
  }

  /**
   * Read and parse a record.
   *
   * A record that fails authentication is reported (by key name only — never
   * by content) and treated as absent rather than throwing, so one tampered or
   * corrupt row cannot make the whole app unopenable. Callers that need to
   * distinguish the two cases should use {@link getRaw}.
   */
  async get<T>(recordKey: string): Promise<T | undefined> {
    let plaintext: Uint8Array | undefined;
    try {
      plaintext = await this.getRaw(recordKey);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        this.logger.error('stored record failed authentication', { recordKey });
        return undefined;
      }
      throw error;
    }
    if (!plaintext) return undefined;
    try {
      return JSON.parse(new TextDecoder().decode(plaintext)) as T;
    } catch {
      this.logger.error('stored record is not valid JSON', { recordKey });
      return undefined;
    }
  }

  async delete(recordKey: string): Promise<void> {
    await this.backend.delete(recordKey);
  }

  async keys(prefix: string): Promise<string[]> {
    return this.backend.keys(prefix);
  }

  async list<T>(prefix: string): Promise<T[]> {
    const keys = await this.keys(prefix);
    const out: T[] = [];
    for (const key of keys) {
      const value = await this.get<T>(key);
      if (value !== undefined) out.push(value);
    }
    return out;
  }

  async clear(): Promise<void> {
    await this.backend.clear();
  }
}
