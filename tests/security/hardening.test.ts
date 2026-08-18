/**
 * Regression tests for the findings in SECURITY_REVIEW.md.
 *
 * Each of these fails against the code as it stood before the corresponding
 * fix, which is the only way to know a security fix is real.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import {
  AUTH_CHALLENGE_CONTEXT,
  silentLogger,
  type ServerToClientMessage,
} from '@p2pchat/shared';
import { openDatabase, type Db } from '../../server/src/db.js';
import { Registry } from '../../server/src/identity/registry.js';
import { RelayQueue } from '../../server/src/relay/queue.js';
import { SignalingHub, type HubSocket } from '../../server/src/signaling/hub.js';
import { ApiClient } from '../../client/src/p2p/apiClient.js';

class FakeSocket implements HubSocket {
  readonly sent: ServerToClientMessage[] = [];
  closed = false;
  send(data: string): void {
    this.sent.push(JSON.parse(data) as ServerToClientMessage);
  }
  close(): void {
    this.closed = true;
  }
  errors(): string[] {
    return this.sent.filter((m) => m.type === 'error').map((m) => (m as { code: string }).code);
  }
}

describe('H1: the relay refuses envelopes for devices that do not exist', () => {
  let db: Db;
  let registry: Registry;
  let relayQueue: RelayQueue;
  let hub: SignalingHub;

  beforeEach(() => {
    db = openDatabase(':memory:');
    registry = new Registry(db);
    relayQueue = new RelayQueue(db);
    hub = new SignalingHub(registry, relayQueue, silentLogger);
  });

  function connect(): { socket: FakeSocket; userId: string; deviceId: string } {
    const privateKey = ed25519.utils.randomPrivateKey();
    const account = registry.registerAccount({
      username: 'attacker',
      clientProof: new Uint8Array(32).fill(1),
      kdfParams: {
        algorithm: 'argon2id',
        salt: Buffer.alloc(16).toString('base64'),
        memoryKiB: 8192,
        iterations: 1,
        parallelism: 1,
      },
      deviceAuthPublicKey: ed25519.getPublicKey(privateKey),
      deviceLabel: 'x',
    });
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const session = registry.verifyChallenge(
      challenge.challengeId,
      ed25519.sign(
        Buffer.concat([
          Buffer.from(
            `${AUTH_CHALLENGE_CONTEXT}\n${account.userId}\n${account.deviceId}\n`,
            'utf8',
          ),
          challenge.nonce,
        ]),
        privateKey,
      ),
    );
    const socket = new FakeSocket();
    hub.open(socket);
    hub.handleMessage(socket, JSON.stringify({ type: 'auth', token: session.token }));
    return { socket, ...account };
  }

  it('rejects a relay send addressed to an invented device', () => {
    const { socket } = connect();
    hub.handleMessage(
      socket,
      JSON.stringify({
        type: 'relay.send',
        to: {
          userId: '00000000-0000-4000-8000-00000000dead',
          deviceId: 'deadbeefdeadbeef',
        },
        frame: Buffer.from('junk').toString('base64'),
      }),
    );

    expect(socket.errors()).toContain('unknown_device');
    const stored = db.prepare('SELECT COUNT(*) AS n FROM relay_envelopes').get() as { n: number };
    expect(stored.n).toBe(0);
  });

  it('does not let one client grow the queue with fabricated recipients', () => {
    const { socket } = connect();
    for (let i = 0; i < 50; i++) {
      hub.handleMessage(
        socket,
        JSON.stringify({
          type: 'relay.send',
          to: {
            userId: '00000000-0000-4000-8000-0000000000' + i.toString(16).padStart(2, '0'),
            deviceId: i.toString(16).padStart(16, '0'),
          },
          frame: Buffer.from('junk').toString('base64'),
        }),
      );
    }
    const stored = db.prepare('SELECT COUNT(*) AS n FROM relay_envelopes').get() as { n: number };
    expect(stored.n).toBe(0);
  });
});

describe('M2: the signaling hub rate-limits a single socket', () => {
  it('starts rejecting once the burst allowance is spent', () => {
    const db = openDatabase(':memory:');
    const registry = new Registry(db);
    const hub = new SignalingHub(registry, new RelayQueue(db), silentLogger, () => 1_000_000);

    const socket = new FakeSocket();
    hub.open(socket);

    // The clock is frozen, so no allowance is refilled.
    for (let i = 0; i < 400; i++) {
      hub.handleMessage(socket, JSON.stringify({ type: 'ping', t: i }));
    }
    expect(socket.errors()).toContain('rate_limited');
  });

  it('refills the allowance as time passes', () => {
    const db = openDatabase(':memory:');
    const registry = new Registry(db);
    let clock = 1_000_000;
    const hub = new SignalingHub(registry, new RelayQueue(db), silentLogger, () => clock);

    const socket = new FakeSocket();
    hub.open(socket);
    for (let i = 0; i < 400; i++) {
      hub.handleMessage(socket, JSON.stringify({ type: 'ping', t: i }));
    }
    const before = socket.errors().length;
    expect(before).toBeGreaterThan(0);

    clock += 60_000; // a minute of refill
    socket.sent.length = 0;
    hub.handleMessage(socket, JSON.stringify({ type: 'ping', t: 999 }));
    expect(socket.errors()).toHaveLength(0);
  });
});

describe('H2: the API client re-authenticates instead of failing permanently', () => {
  it('retries once after a 401 and succeeds', async () => {
    let calls = 0;
    let reauthentications = 0;
    const client = new ApiClient('http://server.invalid', (async (
      _url: string,
      init?: RequestInit,
    ) => {
      calls += 1;
      const authorised = new Headers(init?.headers).get('authorization') === 'Bearer good';
      return new Response(authorised ? JSON.stringify({ devices: [] }) : JSON.stringify({}), {
        status: authorised ? 200 : 401,
      });
    }) as unknown as typeof fetch);

    client.setSession({ token: 'stale', userId: 'u', deviceId: 'd', expiresAt: 0 });
    client.setUnauthorizedHandler(async () => {
      reauthentications += 1;
      client.setSession({ token: 'good', userId: 'u', deviceId: 'd', expiresAt: Date.now() + 1e6 });
    });

    await expect(client.listOwnDevices()).resolves.toEqual([]);
    expect(reauthentications).toBe(1);
    expect(calls).toBe(2);
  });

  it('does not loop forever when re-authentication does not help', async () => {
    let calls = 0;
    const client = new ApiClient('http://server.invalid', (async () => {
      calls += 1;
      return new Response(JSON.stringify({}), { status: 401 });
    }) as unknown as typeof fetch);

    client.setSession({ token: 'stale', userId: 'u', deviceId: 'd', expiresAt: 0 });
    client.setUnauthorizedHandler(async () => {
      /* still broken */
    });

    await expect(client.listOwnDevices()).rejects.toMatchObject({ status: 401 });
    expect(calls).toBe(2);
  });

  it('coalesces concurrent 401s into a single re-authentication', async () => {
    let reauthentications = 0;
    let good = false;
    const client = new ApiClient('http://server.invalid', (async () => {
      return new Response(JSON.stringify(good ? { devices: [] } : {}), {
        status: good ? 200 : 401,
      });
    }) as unknown as typeof fetch);

    client.setSession({ token: 'stale', userId: 'u', deviceId: 'd', expiresAt: 0 });
    client.setUnauthorizedHandler(async () => {
      reauthentications += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      good = true;
    });

    await Promise.all([
      client.listOwnDevices(),
      client.listOwnDevices(),
      client.listOwnDevices(),
    ]);
    expect(reauthentications).toBe(1);
  });
});
