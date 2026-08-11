import { beforeEach, describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { AUTH_CHALLENGE_CONTEXT } from '@p2pchat/shared';
import { openDatabase, type Db } from '../../server/src/db.js';
import { Registry, RegistryError } from '../../server/src/identity/registry.js';

const KDF_PARAMS = {
  algorithm: 'argon2id' as const,
  salt: Buffer.alloc(16, 7).toString('base64'),
  memoryKiB: 8192,
  iterations: 1,
  parallelism: 1,
};

function challengeMessage(userId: string, deviceId: string, nonce: Buffer): Uint8Array {
  return Buffer.concat([
    Buffer.from(`${AUTH_CHALLENGE_CONTEXT}\n${userId}\n${deviceId}\n`, 'utf8'),
    nonce,
  ]);
}

describe('Registry', () => {
  let db: Db;
  let registry: Registry;
  let devicePrivateKey: Uint8Array;
  let devicePublicKey: Uint8Array;

  beforeEach(() => {
    db = openDatabase(':memory:');
    registry = new Registry(db);
    devicePrivateKey = ed25519.utils.randomPrivateKey();
    devicePublicKey = ed25519.getPublicKey(devicePrivateKey);
  });

  function register(username = 'alice'): { userId: string; deviceId: string } {
    return registry.registerAccount({
      username,
      clientProof: new Uint8Array(32).fill(1),
      kdfParams: KDF_PARAMS,
      deviceAuthPublicKey: devicePublicKey,
      deviceLabel: 'laptop',
    });
  }

  it('registers an account and rejects a duplicate username', () => {
    const account = register();
    expect(account.userId).toMatch(/^[0-9a-f-]{36}$/);
    expect(account.deviceId).toMatch(/^[0-9a-f]+$/);
    expect(() => register()).toThrow(RegistryError);
  });

  it('authenticates a device by signed challenge', () => {
    const account = register();
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const signature = ed25519.sign(
      challengeMessage(account.userId, account.deviceId, challenge.nonce),
      devicePrivateKey,
    );

    const session = registry.verifyChallenge(challenge.challengeId, signature);
    expect(session.userId).toBe(account.userId);
    expect(registry.authenticate(session.token)).toEqual({
      userId: account.userId,
      deviceId: account.deviceId,
    });
  });

  it('rejects a challenge signed by the wrong key', () => {
    const account = register();
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const attackerKey = ed25519.utils.randomPrivateKey();
    const signature = ed25519.sign(
      challengeMessage(account.userId, account.deviceId, challenge.nonce),
      attackerKey,
    );
    expect(() => registry.verifyChallenge(challenge.challengeId, signature)).toThrow(RegistryError);
  });

  it('spends a challenge exactly once, even on a failed attempt', () => {
    const account = register();
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const message = challengeMessage(account.userId, account.deviceId, challenge.nonce);

    // A wrong signature still consumes the nonce.
    expect(() =>
      registry.verifyChallenge(challenge.challengeId, new Uint8Array(64)),
    ).toThrow(RegistryError);

    const goodSignature = ed25519.sign(message, devicePrivateKey);
    expect(() => registry.verifyChallenge(challenge.challengeId, goodSignature)).toThrow(
      /unknown or spent/,
    );
  });

  it('rejects an expired challenge', () => {
    let clock = 1_000_000;
    const timed = new Registry(db, () => clock);
    const account = timed.registerAccount({
      username: 'bob',
      clientProof: new Uint8Array(32).fill(2),
      kdfParams: KDF_PARAMS,
      deviceAuthPublicKey: devicePublicKey,
      deviceLabel: 'phone',
    });
    const challenge = timed.createChallenge(account.userId, account.deviceId);
    const signature = ed25519.sign(
      challengeMessage(account.userId, account.deviceId, challenge.nonce),
      devicePrivateKey,
    );
    clock += 10 * 60 * 1000;
    expect(() => timed.verifyChallenge(challenge.challengeId, signature)).toThrow(/expired/);
  });

  it('rejects an unexpired token only after it expires', () => {
    let clock = 5_000_000;
    const timed = new Registry(db, () => clock);
    const account = timed.registerAccount({
      username: 'carol',
      clientProof: new Uint8Array(32).fill(3),
      kdfParams: KDF_PARAMS,
      deviceAuthPublicKey: devicePublicKey,
      deviceLabel: 'desktop',
    });
    const challenge = timed.createChallenge(account.userId, account.deviceId);
    const session = timed.verifyChallenge(
      challenge.challengeId,
      ed25519.sign(
        challengeMessage(account.userId, account.deviceId, challenge.nonce),
        devicePrivateKey,
      ),
    );
    expect(timed.authenticate(session.token)).not.toBeNull();
    clock += 24 * 60 * 60 * 1000;
    expect(timed.authenticate(session.token)).toBeNull();
  });

  it('registers a second device only with the correct password proof', () => {
    const account = register();
    const secondKey = ed25519.utils.randomPrivateKey();

    expect(() =>
      registry.registerDevice({
        username: 'alice',
        clientProof: new Uint8Array(32).fill(9),
        deviceAuthPublicKey: ed25519.getPublicKey(secondKey),
        deviceLabel: 'phone',
      }),
    ).toThrow(/invalid credentials/);

    const second = registry.registerDevice({
      username: 'alice',
      clientProof: new Uint8Array(32).fill(1),
      deviceAuthPublicKey: ed25519.getPublicKey(secondKey),
      deviceLabel: 'phone',
    });
    expect(second.userId).toBe(account.userId);
    expect(second.deviceId).not.toBe(account.deviceId);
    expect(registry.listDevices(account.userId)).toHaveLength(2);
  });

  it('hands out each key package exactly once', () => {
    const account = register();
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const session = registry.verifyChallenge(
      challenge.challengeId,
      ed25519.sign(
        challengeMessage(account.userId, account.deviceId, challenge.nonce),
        devicePrivateKey,
      ),
    );
    const device = registry.authenticate(session.token)!;

    registry.publishKeyPackages(device, [new Uint8Array([1, 1]), new Uint8Array([2, 2])]);
    expect(registry.countKeyPackages(device)).toBe(2);

    const first = registry.claimKeyPackages(account.userId);
    const second = registry.claimKeyPackages(account.userId);
    const third = registry.claimKeyPackages(account.userId);

    expect(first[0]!.keyPackage).toEqual(Buffer.from([1, 1]));
    expect(second[0]!.keyPackage).toEqual(Buffer.from([2, 2]));
    expect(third).toHaveLength(0);
    expect(registry.countKeyPackages(device)).toBe(0);
  });

  it('returns stable decoy KDF parameters for an unknown username', () => {
    const first = registry.passwordKdfParams('does-not-exist');
    const second = registry.passwordKdfParams('does-not-exist');
    expect(first).toEqual(second);
    expect(first.algorithm).toBe('argon2id');
  });

  it('revoking a device removes its tokens and key packages', () => {
    const account = register();
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const session = registry.verifyChallenge(
      challenge.challengeId,
      ed25519.sign(
        challengeMessage(account.userId, account.deviceId, challenge.nonce),
        devicePrivateKey,
      ),
    );
    const device = registry.authenticate(session.token)!;
    registry.publishKeyPackages(device, [new Uint8Array([5])]);

    registry.removeDevice(account.userId, account.deviceId);

    expect(registry.authenticate(session.token)).toBeNull();
    expect(registry.listDevices(account.userId)).toHaveLength(0);
    expect(registry.claimKeyPackages(account.userId)).toHaveLength(0);
  });
});
