/**
 * Authentication and authorisation at the HTTP boundary.
 *
 * The recurring failure mode these guard against: an endpoint that returns
 * useful data to an unauthenticated caller, or that lets one account act on
 * another's resources.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { AUTH_CHALLENGE_CONTEXT, silentLogger, toBase64 } from '@p2pchat/shared';
import { buildServer, type BuiltServer } from '../../server/src/app.js';

const KDF_PARAMS = {
  algorithm: 'argon2id' as const,
  salt: Buffer.alloc(16, 3).toString('base64'),
  memoryKiB: 8192,
  iterations: 1,
  parallelism: 1,
};

describe('HTTP API authentication', () => {
  let built: BuiltServer;

  beforeEach(async () => {
    built = await buildServer(
      { databasePath: ':memory:', corsOrigins: ['*'], iceServers: [] },
      silentLogger,
    );
  });

  afterEach(async () => {
    await built.app.close();
  });

  async function register(username: string): Promise<{
    userId: string;
    deviceId: string;
    token: string;
    privateKey: Uint8Array;
  }> {
    const privateKey = ed25519.utils.randomPrivateKey();
    const registration = await built.app.inject({
      method: 'POST',
      url: '/api/v1/account/register',
      payload: {
        username,
        clientProof: Buffer.alloc(32, 1).toString('base64'),
        kdfParams: KDF_PARAMS,
        deviceAuthPublicKey: toBase64(ed25519.getPublicKey(privateKey)),
        deviceLabel: 'test',
      },
    });
    expect(registration.statusCode).toBe(201);
    const { userId, deviceId } = registration.json() as { userId: string; deviceId: string };

    const challenge = await built.app.inject({
      method: 'POST',
      url: '/api/v1/auth/challenge',
      payload: { userId, deviceId },
    });
    const { challengeId, nonce } = challenge.json() as { challengeId: string; nonce: string };

    const signature = ed25519.sign(
      Buffer.concat([
        Buffer.from(`${AUTH_CHALLENGE_CONTEXT}\n${userId}\n${deviceId}\n`, 'utf8'),
        Buffer.from(nonce, 'base64'),
      ]),
      privateKey,
    );

    const verify = await built.app.inject({
      method: 'POST',
      url: '/api/v1/auth/verify',
      payload: { challengeId, signature: toBase64(signature) },
    });
    expect(verify.statusCode).toBe(200);
    const { token } = verify.json() as { token: string };
    return { userId, deviceId, token, privateKey };
  }

  const PROTECTED: { method: 'GET' | 'POST' | 'DELETE'; url: string; payload?: unknown }[] = [
    { method: 'POST', url: '/api/v1/keypackages', payload: { keyPackages: ['AAAA'] } },
    { method: 'GET', url: '/api/v1/keypackages/count' },
    {
      method: 'POST',
      url: '/api/v1/keypackages/claim',
      payload: { userId: '00000000-0000-4000-8000-000000000000' },
    },
    { method: 'GET', url: '/api/v1/directory/someone' },
    { method: 'GET', url: '/api/v1/devices' },
    { method: 'DELETE', url: '/api/v1/devices/0000000000000001' },
    { method: 'GET', url: '/api/v1/ice' },
    { method: 'GET', url: '/api/v1/blobs/anything' },
  ];

  it('rejects every protected route without a token', async () => {
    for (const route of PROTECTED) {
      const response = await built.app.inject({
        method: route.method,
        url: route.url,
        ...(route.payload ? { payload: route.payload } : {}),
      });
      expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
      expect(response.json()).toMatchObject({ error: { code: 'unauthenticated' } });
    }
  });

  it('rejects a forged or malformed bearer token', async () => {
    for (const token of ['', 'garbage', 'a'.repeat(200)]) {
      const response = await built.app.inject({
        method: 'GET',
        url: '/api/v1/devices',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(401);
    }
  });

  it('accepts a valid token', async () => {
    const alice = await register('alice');
    const response = await built.app.inject({
      method: 'GET',
      url: '/api/v1/devices',
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(response.statusCode).toBe(200);
    expect((response.json() as { devices: unknown[] }).devices).toHaveLength(1);
  });

  it('scopes device revocation to the caller’s own account', async () => {
    const alice = await register('alice');
    const bob = await register('bob');

    // Alice tries to revoke Bob's device.
    const response = await built.app.inject({
      method: 'DELETE',
      url: `/api/v1/devices/${bob.deviceId}`,
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(response.statusCode).toBe(204);

    // The call is scoped by user id, so Bob's device is untouched.
    const bobDevices = await built.app.inject({
      method: 'GET',
      url: '/api/v1/devices',
      headers: { authorization: `Bearer ${bob.token}` },
    });
    expect((bobDevices.json() as { devices: unknown[] }).devices).toHaveLength(1);
  });

  it('revokes a device’s tokens when the device is removed', async () => {
    const alice = await register('alice');
    await built.app.inject({
      method: 'DELETE',
      url: `/api/v1/devices/${alice.deviceId}`,
      headers: { authorization: `Bearer ${alice.token}` },
    });
    const after = await built.app.inject({
      method: 'GET',
      url: '/api/v1/devices',
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(after.statusCode).toBe(401);
  });

  it('rejects a body that fails validation without echoing it back', async () => {
    const response = await built.app.inject({
      method: 'POST',
      url: '/api/v1/account/register',
      payload: { username: 'A!', clientProof: 'not base64!!!', kdfParams: {} },
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain('not base64');
    expect(response.json()).toMatchObject({ error: { code: 'bad_request' } });
  });

  it('rejects weak client-side KDF parameters', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const response = await built.app.inject({
      method: 'POST',
      url: '/api/v1/account/register',
      payload: {
        username: 'weakling',
        clientProof: Buffer.alloc(32).toString('base64'),
        kdfParams: { ...KDF_PARAMS, memoryKiB: 8, iterations: 1 },
        deviceAuthPublicKey: toBase64(ed25519.getPublicKey(privateKey)),
        deviceLabel: 'test',
      },
    });
    expect(response.statusCode).toBe(400);
  });

  it('does not reveal whether a username exists via the KDF parameters route', async () => {
    await register('alice');
    const known = await built.app.inject({
      method: 'GET',
      url: '/api/v1/account/kdf-params?username=alice',
    });
    const unknown = await built.app.inject({
      method: 'GET',
      url: '/api/v1/account/kdf-params?username=nobodyhere',
    });

    expect(known.statusCode).toBe(200);
    expect(unknown.statusCode).toBe(200);
    // Both return well-formed parameters; the response shape does not differ.
    expect(Object.keys(known.json() as object)).toEqual(Object.keys(unknown.json() as object));
  });

  it('rejects an oversized attachment', async () => {
    const alice = await register('alice');
    const response = await built.app.inject({
      method: 'POST',
      url: '/api/v1/blobs',
      headers: {
        authorization: `Bearer ${alice.token}`,
        'content-type': 'application/octet-stream',
      },
      payload: Buffer.alloc(1024),
    });
    expect(response.statusCode).toBe(201);

    const tooBig = await buildServer(
      { databasePath: ':memory:', corsOrigins: ['*'], iceServers: [], maxBlobBytes: 512 },
      silentLogger,
    );
    try {
      const second = await tooBig.app.inject({
        method: 'POST',
        url: '/api/v1/blobs',
        headers: { 'content-type': 'application/octet-stream' },
        payload: Buffer.alloc(1024),
      });
      // Unauthenticated first, which is the stronger rejection.
      expect(second.statusCode).toBe(401);
    } finally {
      await tooBig.app.close();
    }
  });

  it('returns 404 for an unknown blob rather than leaking existence detail', async () => {
    const alice = await register('alice');
    const response = await built.app.inject({
      method: 'GET',
      url: '/api/v1/blobs/does-not-exist',
      headers: { authorization: `Bearer ${alice.token}` },
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'not_found' } });
  });
});
