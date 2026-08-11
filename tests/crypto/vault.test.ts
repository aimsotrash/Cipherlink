import { describe, expect, it } from 'vitest';
import { AuthenticationError } from '../../client/src/crypto/aead.js';
import {
  KEY_PURPOSE,
  TEST_ARGON2_PARAMS,
  createVault,
  rewrapVault,
  unlockVault,
} from '../../client/src/storage/vault.js';
import { EncryptedStore } from '../../client/src/storage/encryptedStore.js';
import { MemoryKeyValueStore } from '../../client/src/storage/kv.js';
import { flipBufferBit } from '../helpers/tamper.js';

const PASSPHRASE = 'correct horse battery staple';

describe('vault', () => {
  it('unlocks with the right passphrase and derives a stable master key', async () => {
    const { header, vault } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const first = await vault.deriveKey(KEY_PURPOSE.records, 32);

    const reopened = await unlockVault(header, PASSPHRASE);
    const second = await reopened.deriveKey(KEY_PURPOSE.records, 32);

    expect(Buffer.from(second)).toEqual(Buffer.from(first));
  });

  it('rejects the wrong passphrase', async () => {
    const { header } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    await expect(unlockVault(header, 'wrong passphrase')).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('rejects a tampered wrapped key', async () => {
    const { header } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const bytes = flipBufferBit(Buffer.from(header.wrappedMasterKey.ciphertext, 'base64'));
    const tampered = {
      ...header,
      wrappedMasterKey: { ...header.wrappedMasterKey, ciphertext: bytes.toString('base64') },
    };
    await expect(unlockVault(tampered, PASSPHRASE)).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('derives independent keys for different purposes', async () => {
    const { vault } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const records = await vault.deriveKey(KEY_PURPOSE.records, 32);
    const mls = await vault.deriveKey(KEY_PURPOSE.mlsDatabase, 32);
    const deviceAuth = await vault.deriveKey(KEY_PURPOSE.deviceAuth, 32);

    expect(Buffer.from(records)).not.toEqual(Buffer.from(mls));
    expect(Buffer.from(records)).not.toEqual(Buffer.from(deviceAuth));
    expect(Buffer.from(mls)).not.toEqual(Buffer.from(deviceAuth));
  });

  it('uses a distinct salt per vault, so identical passphrases differ', async () => {
    const a = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const b = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    expect(a.header.salt).not.toBe(b.header.salt);
    expect(Buffer.from(await a.vault.deriveKey(KEY_PURPOSE.records, 32))).not.toEqual(
      Buffer.from(await b.vault.deriveKey(KEY_PURPOSE.records, 32)),
    );
  });

  it('re-wraps under a new passphrase without changing derived keys', async () => {
    const { header, vault } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const before = await vault.deriveKey(KEY_PURPOSE.records, 32);

    const newHeader = await rewrapVault(vault, 'a brand new passphrase', TEST_ARGON2_PARAMS);
    const reopened = await unlockVault(newHeader, 'a brand new passphrase');
    const after = await reopened.deriveKey(KEY_PURPOSE.records, 32);

    expect(Buffer.from(after)).toEqual(Buffer.from(before));
    // The old passphrase no longer opens the new header.
    await expect(unlockVault(newHeader, PASSPHRASE)).rejects.toBeInstanceOf(AuthenticationError);
    // ...and the old header is unchanged, so it still opens with the old one.
    await expect(unlockVault(header, PASSPHRASE)).resolves.toBeDefined();
  });

  it('zeroes the master key on lock and refuses further use', async () => {
    const { vault } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    vault.lock();
    expect(vault.locked).toBe(true);
    await expect(vault.deriveKey(KEY_PURPOSE.records, 32)).rejects.toThrow(/locked/);
  });

  it('refuses an empty passphrase', async () => {
    await expect(createVault('', TEST_ARGON2_PARAMS)).rejects.toThrow(/must not be empty/);
  });
});

describe('encrypted record store', () => {
  async function store(): Promise<{ store: EncryptedStore; backend: MemoryKeyValueStore }> {
    const { vault } = await createVault(PASSPHRASE, TEST_ARGON2_PARAMS);
    const backend = new MemoryKeyValueStore();
    return { store: new EncryptedStore(backend, await vault.deriveAesKey(KEY_PURPOSE.records)), backend };
  }

  it('persists values as ciphertext, not plaintext', async () => {
    const { store: encrypted, backend } = await store();
    await encrypted.put('contact/alice', { username: 'alice', note: 'my accountant' });

    const raw = await backend.get('contact/alice');
    expect(raw).toBeDefined();
    expect(Buffer.from(raw!).includes(Buffer.from('accountant'))).toBe(false);
    expect(Buffer.from(raw!).includes(Buffer.from('alice'))).toBe(false);

    expect(await encrypted.get('contact/alice')).toEqual({
      username: 'alice',
      note: 'my accountant',
    });
  });

  it('binds a record to its key, so a valid record cannot be moved', async () => {
    const { store: encrypted, backend } = await store();
    await encrypted.put('contact/alice', { username: 'alice' });
    await encrypted.put('contact/bob', { username: 'bob' });

    // An attacker with database write access swaps the two rows.
    const aliceRow = await backend.get('contact/alice');
    await backend.set('contact/bob', aliceRow!);

    // The moved record fails authentication and is reported as absent rather
    // than being read back under the wrong identity.
    expect(await encrypted.get('contact/bob')).toBeUndefined();
  });

  it('treats a truncated record as missing rather than throwing', async () => {
    const { store: encrypted, backend } = await store();
    await encrypted.put('k', { a: 1 });
    await backend.set('k', new Uint8Array([1, 2, 3]));
    expect(await encrypted.get('k')).toBeUndefined();
  });

  it('lists records in key order', async () => {
    const { store: encrypted } = await store();
    await encrypted.put('msg/c/003/x', { n: 3 });
    await encrypted.put('msg/c/001/x', { n: 1 });
    await encrypted.put('msg/c/002/x', { n: 2 });
    expect(await encrypted.list<{ n: number }>('msg/c/')).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }]);
  });
});
