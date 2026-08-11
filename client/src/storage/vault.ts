/**
 * Local key vault.
 *
 * Everything sensitive this client persists — the MLS key store (which holds
 * the device's private signature key and all group secrets), the device
 * authentication key, the message database — is encrypted under keys derived
 * from a single master key that only exists while the app is unlocked.
 *
 *   passphrase --Argon2id--> wrapping key --AES-256-GCM--> [wrapped master key]
 *   master key --HKDF-SHA-256--> per-purpose subkeys
 *
 * What is stored in the clear, necessarily: the Argon2id salt and parameters,
 * and the wrapped master key. Those reveal nothing without the passphrase, but
 * they do let an attacker with disk access run an offline guessing attack —
 * which is exactly what the Argon2id cost parameters are there to slow down.
 *
 * Honest limitation: in a browser there is no OS keychain and no secure
 * enclave to bind this to. The master key lives in JavaScript memory while
 * unlocked and can be read by anything with code execution in the origin. A
 * packaged desktop/mobile build should wrap the master key with the platform
 * keychain instead of (or in addition to) a passphrase. See SECURITY.md.
 *
 * Argon2id comes from @noble/hashes; HKDF and AES-GCM from WebCrypto. No
 * primitive is implemented here.
 */
import { argon2id } from '@noble/hashes/argon2';
import { fromBase64, toBase64, utf8Encode } from '@p2pchat/shared';
import { AuthenticationError, importAesKey, open, seal } from '../crypto/aead.js';
import { randomBytes, wipe } from '../crypto/random.js';

export interface Argon2Params {
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
}

/**
 * Defaults chosen above OWASP's Argon2id floor (19 MiB / t=2). The pure-JS
 * implementation is ~10x slower than native, so this costs a couple of
 * seconds on unlock — a price paid once per session, deliberately.
 */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
};

/**
 * Reduced cost for automated tests only. Never used at runtime.
 *
 * Still at the protocol's minimum accepted strength (8 MiB / t=1) rather than
 * below it, so tests exercise the same validation path real clients do.
 */
export const TEST_ARGON2_PARAMS: Argon2Params = {
  memoryKiB: 8192,
  iterations: 1,
  parallelism: 1,
};

export const MASTER_KEY_BYTES = 32;
const VAULT_VERSION = 1;

/** Persisted, unencrypted vault header. Safe to store, useless without the passphrase. */
export interface VaultHeader {
  readonly version: number;
  readonly salt: string;
  readonly kdf: Argon2Params;
  readonly wrappedMasterKey: { readonly nonce: string; readonly ciphertext: string };
}

/** Purpose labels for HKDF. Each subkey is independent of the others. */
export const KEY_PURPOSE = {
  /** Encrypts core-crypto's own store (MLS private keys and group state). */
  mlsDatabase: 'p2pchat/v1/mls-database',
  /** Encrypts application records: messages, contacts, trust state. */
  records: 'p2pchat/v1/records',
  /** Encrypts the stored device authentication private key. */
  deviceAuth: 'p2pchat/v1/device-auth',
} as const;

export type KeyPurpose = (typeof KEY_PURPOSE)[keyof typeof KEY_PURPOSE];

function subtle(): SubtleCrypto {
  const c = globalThis.crypto?.subtle;
  if (!c) throw new Error('SubtleCrypto is unavailable; cannot open the vault');
  return c;
}

function deriveWrappingKey(passphrase: string, salt: Uint8Array, params: Argon2Params): Uint8Array {
  if (passphrase.length === 0) throw new Error('passphrase must not be empty');
  return argon2id(utf8Encode(passphrase), salt, {
    t: params.iterations,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: MASTER_KEY_BYTES,
  });
}

/** Create a brand-new vault protected by `passphrase`. */
export async function createVault(
  passphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<{ header: VaultHeader; vault: UnlockedVault }> {
  const salt = randomBytes(16);
  const masterKey = randomBytes(MASTER_KEY_BYTES);
  const wrappingKeyBytes = deriveWrappingKey(passphrase, salt, params);

  try {
    const wrappingKey = await importAesKey(wrappingKeyBytes, ['encrypt']);
    const sealed = await seal(wrappingKey, masterKey, utf8Encode('p2pchat/v1/vault'));
    const header: VaultHeader = {
      version: VAULT_VERSION,
      salt: toBase64(salt),
      kdf: params,
      wrappedMasterKey: {
        nonce: toBase64(sealed.nonce),
        ciphertext: toBase64(sealed.ciphertext),
      },
    };
    return { header, vault: new UnlockedVault(masterKey) };
  } finally {
    wipe(wrappingKeyBytes);
  }
}

/**
 * Unlock an existing vault.
 *
 * Throws {@link AuthenticationError} on a wrong passphrase — indistinguishable
 * from a corrupted header by design, so the error does not tell an attacker
 * which of the two they hit.
 */
export async function unlockVault(header: VaultHeader, passphrase: string): Promise<UnlockedVault> {
  if (header.version !== VAULT_VERSION) {
    throw new Error(`unsupported vault version ${header.version}`);
  }
  const salt = fromBase64(header.salt);
  const wrappingKeyBytes = deriveWrappingKey(passphrase, salt, header.kdf);
  try {
    const wrappingKey = await importAesKey(wrappingKeyBytes, ['decrypt']);
    const masterKey = await open(
      wrappingKey,
      {
        nonce: fromBase64(header.wrappedMasterKey.nonce),
        ciphertext: fromBase64(header.wrappedMasterKey.ciphertext),
      },
      utf8Encode('p2pchat/v1/vault'),
    );
    if (masterKey.length !== MASTER_KEY_BYTES) {
      throw new AuthenticationError('vault is corrupt');
    }
    return new UnlockedVault(masterKey);
  } finally {
    wipe(wrappingKeyBytes);
  }
}

/** Re-wrap an existing master key under a new passphrase (change passphrase). */
export async function rewrapVault(
  vault: UnlockedVault,
  newPassphrase: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<VaultHeader> {
  const salt = randomBytes(16);
  const wrappingKeyBytes = deriveWrappingKey(newPassphrase, salt, params);
  try {
    const wrappingKey = await importAesKey(wrappingKeyBytes, ['encrypt']);
    const sealed = await seal(wrappingKey, vault.exportMasterKey(), utf8Encode('p2pchat/v1/vault'));
    return {
      version: VAULT_VERSION,
      salt: toBase64(salt),
      kdf: params,
      wrappedMasterKey: {
        nonce: toBase64(sealed.nonce),
        ciphertext: toBase64(sealed.ciphertext),
      },
    };
  } finally {
    wipe(wrappingKeyBytes);
  }
}

/**
 * A vault that is currently unlocked. Holds the master key in memory and
 * derives purpose-specific subkeys on demand.
 */
export class UnlockedVault {
  private masterKey: Uint8Array | null;

  constructor(masterKey: Uint8Array) {
    this.masterKey = masterKey;
  }

  get locked(): boolean {
    return this.masterKey === null;
  }

  private requireKey(): Uint8Array {
    if (!this.masterKey) throw new Error('vault is locked');
    return this.masterKey;
  }

  /**
   * HKDF-SHA-256 subkey for one purpose.
   *
   * Distinct `info` strings mean compromise of, say, the records key does not
   * reveal the MLS database key.
   */
  async deriveKey(purpose: KeyPurpose, length = 32): Promise<Uint8Array> {
    const base = await subtle().importKey('raw', this.requireKey() as BufferSource, 'HKDF', false, [
      'deriveBits',
    ]);
    const bits = await subtle().deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0) as BufferSource,
        info: utf8Encode(purpose) as BufferSource,
      },
      base,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  async deriveAesKey(purpose: KeyPurpose): Promise<CryptoKey> {
    const raw = await this.deriveKey(purpose, 32);
    try {
      return await importAesKey(raw);
    } finally {
      wipe(raw);
    }
  }

  /** Only for re-wrapping. Callers must not persist the result. */
  exportMasterKey(): Uint8Array {
    return this.requireKey();
  }

  /** Zero the master key. Subsequent operations throw until unlocked again. */
  lock(): void {
    if (this.masterKey) {
      wipe(this.masterKey);
      this.masterKey = null;
    }
  }
}
