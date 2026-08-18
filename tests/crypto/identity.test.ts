import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { AUTH_CHALLENGE_CONTEXT } from '@p2pchat/shared';
import {
  buildChallengeMessage,
  generateDeviceAuthKey,
  signChallenge,
  verifyChallenge,
} from '../../client/src/identity/deviceKey.js';
import {
  deriveSafetyNumber,
  normaliseTypedSafetyNumber,
  qrPayloadMatches,
  safetyNumberMatches,
} from '../../client/src/identity/safetyNumber.js';
import {
  InMemoryTrustPersistence,
  TrustStore,
  type IdentityChangeEvent,
} from '../../client/src/identity/trustStore.js';
import type { MlsMemberIdentity } from '../../client/src/crypto/mls.js';

const ALICE = { userId: 'aaaaaaaa-0000-4000-8000-000000000001', deviceId: '0000000000000001' };
const BOB = { userId: 'bbbbbbbb-0000-4000-8000-000000000002', deviceId: '0000000000000002' };

const aliceIdentity: MlsMemberIdentity = { address: ALICE, thumbprint: 'thumb-alice-aaaa' };
const bobIdentity: MlsMemberIdentity = { address: BOB, thumbprint: 'thumb-bob-bbbb' };

describe('device authentication key', () => {
  it('signs and verifies a challenge', () => {
    const pair = generateDeviceAuthKey();
    const message = buildChallengeMessage({
      context: AUTH_CHALLENGE_CONTEXT,
      userId: ALICE.userId,
      deviceId: ALICE.deviceId,
      nonce: new Uint8Array(32).fill(9),
    });
    const signature = signChallenge(pair.privateKey, message);
    expect(verifyChallenge(pair.publicKey, message, signature)).toBe(true);
  });

  it('binds a signature to its user, device and purpose', () => {
    const pair = generateDeviceAuthKey();
    const nonce = new Uint8Array(32).fill(9);
    const signature = signChallenge(
      pair.privateKey,
      buildChallengeMessage({
        context: AUTH_CHALLENGE_CONTEXT,
        userId: ALICE.userId,
        deviceId: ALICE.deviceId,
        nonce,
      }),
    );

    // Same nonce, different account: must not verify.
    const otherUser = buildChallengeMessage({
      context: AUTH_CHALLENGE_CONTEXT,
      userId: BOB.userId,
      deviceId: ALICE.deviceId,
      nonce,
    });
    expect(verifyChallenge(pair.publicKey, otherUser, signature)).toBe(false);

    // Same everything, different purpose: must not verify.
    const otherContext = buildChallengeMessage({
      context: 'p2pchat/v1/some-other-purpose',
      userId: ALICE.userId,
      deviceId: ALICE.deviceId,
      nonce,
    });
    expect(verifyChallenge(pair.publicKey, otherContext, signature)).toBe(false);
  });

  it('returns false rather than throwing on a malformed signature or key', () => {
    const pair = generateDeviceAuthKey();
    const message = new Uint8Array([1, 2, 3]);
    expect(verifyChallenge(pair.publicKey, message, new Uint8Array(10))).toBe(false);
    expect(verifyChallenge(new Uint8Array(5), message, new Uint8Array(64))).toBe(false);
  });

  it('rejects a signature from a different key', () => {
    const pair = generateDeviceAuthKey();
    const attacker = ed25519.utils.randomPrivateKey();
    const message = new Uint8Array([7, 7, 7]);
    const forged = ed25519.sign(message, attacker);
    expect(verifyChallenge(pair.publicKey, message, forged)).toBe(false);
  });
});

describe('safety numbers', () => {
  it('produces the same 60-digit number regardless of argument order', async () => {
    const fromAlice = await deriveSafetyNumber(aliceIdentity, bobIdentity);
    const fromBob = await deriveSafetyNumber(bobIdentity, aliceIdentity);

    expect(fromAlice.digits).toHaveLength(60);
    expect(fromAlice.digits).toBe(fromBob.digits);
    expect(fromAlice.qrPayload).toBe(fromBob.qrPayload);
    expect(fromAlice.formatted.split(' ')).toHaveLength(12);
  });

  it('changes when either identity key changes', async () => {
    const original = await deriveSafetyNumber(aliceIdentity, bobIdentity);
    const rotated = await deriveSafetyNumber(aliceIdentity, {
      ...bobIdentity,
      thumbprint: 'thumb-bob-DIFFERENT',
    });
    expect(rotated.digits).not.toBe(original.digits);
  });

  it('changes when the client identifier changes, even with the same key', async () => {
    const original = await deriveSafetyNumber(aliceIdentity, bobIdentity);
    const impostor = await deriveSafetyNumber(aliceIdentity, {
      address: { ...BOB, deviceId: '000000000000dead' },
      thumbprint: bobIdentity.thumbprint,
    });
    expect(impostor.digits).not.toBe(original.digits);
  });

  it('matches a correctly typed number and rejects a wrong one', async () => {
    const number = await deriveSafetyNumber(aliceIdentity, bobIdentity);
    expect(safetyNumberMatches(number, number.formatted)).toBe(true);
    expect(safetyNumberMatches(number, number.digits)).toBe(true);
    expect(safetyNumberMatches(number, `${number.digits.slice(0, 59)}9`)).toBe(
      number.digits.endsWith('9'),
    );
    expect(safetyNumberMatches(number, '123')).toBe(false);
    expect(safetyNumberMatches(number, '')).toBe(false);
  });

  it('matches a scanned QR payload and rejects a foreign one', async () => {
    const number = await deriveSafetyNumber(aliceIdentity, bobIdentity);
    const other = await deriveSafetyNumber(aliceIdentity, {
      ...bobIdentity,
      thumbprint: 'someone-else',
    });

    expect(qrPayloadMatches(number, number.qrPayload)).toBe(true);
    expect(qrPayloadMatches(number, other.qrPayload)).toBe(false);
    expect(qrPayloadMatches(number, 'not json at all')).toBe(false);
    expect(qrPayloadMatches(number, '{}')).toBe(false);
  });

  it('normalises separators before comparing', () => {
    expect(normaliseTypedSafetyNumber('12345 67890-11111')).toBe('123456789011111');
  });

  it('refuses to derive from a missing thumbprint', async () => {
    await expect(
      deriveSafetyNumber(aliceIdentity, { address: BOB, thumbprint: '' }),
    ).rejects.toThrow(/without the peer signature key/);
  });
});

describe('trust store', () => {
  function store(): TrustStore {
    return new TrustStore(new InMemoryTrustPersistence());
  }

  it('records a first sighting as unverified, not trusted', async () => {
    const trust = store();
    expect(await trust.observe(BOB, 'thumb-1')).toBeNull();
    expect(trust.get(BOB)?.state).toBe('unverified');
  });

  it('is idempotent when the key does not change', async () => {
    const trust = store();
    await trust.observe(BOB, 'thumb-1');
    expect(await trust.observe(BOB, 'thumb-1')).toBeNull();
    expect(trust.get(BOB)?.state).toBe('unverified');
  });

  it('flags a key change instead of silently accepting it', async () => {
    const trust = store();
    const events: IdentityChangeEvent[] = [];
    trust.onIdentityChange((event) => events.push(event));

    await trust.observe(BOB, 'thumb-1');
    const change = await trust.observe(BOB, 'thumb-2');

    expect(change).not.toBeNull();
    expect(change!.previousThumbprint).toBe('thumb-1');
    expect(change!.newThumbprint).toBe('thumb-2');
    expect(trust.get(BOB)?.state).toBe('changed');
    expect(events).toHaveLength(1);
  });

  it('drops verification when a verified key changes, and says it was verified', async () => {
    const trust = store();
    await trust.observe(BOB, 'thumb-1');
    await trust.markVerified(BOB, 'thumb-1');
    expect(trust.get(BOB)?.state).toBe('verified');

    const change = await trust.observe(BOB, 'thumb-2');
    expect(change!.wasVerified).toBe(true);
    expect(trust.get(BOB)?.state).toBe('changed');
    expect(trust.get(BOB)?.verifiedAt).toBeNull();
    expect(trust.get(BOB)?.wasVerifiedBeforeChange).toBe(true);
  });

  it('refuses to verify a stale thumbprint', async () => {
    const trust = store();
    await trust.observe(BOB, 'thumb-current');
    await expect(trust.markVerified(BOB, 'thumb-old')).rejects.toThrow(/identity changed/);
    expect(trust.get(BOB)?.state).toBe('unverified');
  });

  it('refuses to verify a device that was never seen', async () => {
    const trust = store();
    await expect(trust.markVerified(BOB, 'thumb')).rejects.toThrow(/has not been seen/);
  });

  it('acknowledging a change yields unverified, never verified', async () => {
    const trust = store();
    await trust.observe(BOB, 'thumb-1');
    await trust.markVerified(BOB, 'thumb-1');
    await trust.observe(BOB, 'thumb-2');

    await trust.acknowledgeChange(BOB);
    expect(trust.get(BOB)?.state).toBe('unverified');
    expect(trust.get(BOB)?.verifiedAt).toBeNull();
  });

  it('blocks sending to a changed identity only while the setting is on', async () => {
    const trust = store();
    await trust.observe(BOB, 'thumb-1');
    await trust.observe(BOB, 'thumb-2');

    expect(trust.isSendBlocked(BOB, true)).toBe(true);
    expect(trust.isSendBlocked(BOB, false)).toBe(false);

    await trust.acknowledgeChange(BOB);
    expect(trust.isSendBlocked(BOB, true)).toBe(false);
  });

  it('summarises a user as the worst state across their devices', async () => {
    const trust = store();
    const second = { userId: BOB.userId, deviceId: '00000000000000ff' };
    await trust.observe(BOB, 'thumb-1');
    await trust.markVerified(BOB, 'thumb-1');
    expect(trust.summaryForUser(BOB.userId)).toBe('verified');

    await trust.observe(second, 'thumb-2');
    expect(trust.summaryForUser(BOB.userId)).toBe('unverified');

    await trust.observe(second, 'thumb-3');
    expect(trust.summaryForUser(BOB.userId)).toBe('changed');
  });

  it('reloads state from persistence', async () => {
    const persistence = new InMemoryTrustPersistence();
    const first = new TrustStore(persistence);
    await first.observe(BOB, 'thumb-1');
    await first.markVerified(BOB, 'thumb-1');

    const second = new TrustStore(persistence);
    await second.load();
    expect(second.get(BOB)?.state).toBe('verified');
  });

  it('refuses to record an empty thumbprint', async () => {
    const trust = store();
    await expect(trust.observe(BOB, '')).rejects.toThrow(/empty identity thumbprint/);
  });
});
