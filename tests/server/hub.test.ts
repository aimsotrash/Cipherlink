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

class FakeSocket implements HubSocket {
  readonly sent: ServerToClientMessage[] = [];
  closed: { code?: number; reason?: string } | null = null;

  send(data: string): void {
    this.sent.push(JSON.parse(data) as ServerToClientMessage);
  }

  close(code?: number, reason?: string): void {
    this.closed = { code, reason };
  }

  last<T extends ServerToClientMessage['type']>(type: T) {
    return [...this.sent].reverse().find((m) => m.type === type) as
      | Extract<ServerToClientMessage, { type: T }>
      | undefined;
  }

  all<T extends ServerToClientMessage['type']>(type: T) {
    return this.sent.filter((m) => m.type === type) as Extract<
      ServerToClientMessage,
      { type: T }
    >[];
  }
}

describe('SignalingHub', () => {
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

  function makeAccount(username: string): {
    userId: string;
    deviceId: string;
    token: string;
  } {
    const privateKey = ed25519.utils.randomPrivateKey();
    const account = registry.registerAccount({
      username,
      clientProof: new Uint8Array(32).fill(1),
      kdfParams: {
        algorithm: 'argon2id',
        salt: Buffer.alloc(16).toString('base64'),
        memoryKiB: 8192,
        iterations: 1,
        parallelism: 1,
      },
      deviceAuthPublicKey: ed25519.getPublicKey(privateKey),
      deviceLabel: username,
    });
    const challenge = registry.createChallenge(account.userId, account.deviceId);
    const signature = ed25519.sign(
      Buffer.concat([
        Buffer.from(`${AUTH_CHALLENGE_CONTEXT}\n${account.userId}\n${account.deviceId}\n`, 'utf8'),
        challenge.nonce,
      ]),
      privateKey,
    );
    const session = registry.verifyChallenge(challenge.challengeId, signature);
    return { ...account, token: session.token };
  }

  function connect(token: string): FakeSocket {
    const socket = new FakeSocket();
    hub.open(socket);
    hub.handleMessage(socket, JSON.stringify({ type: 'auth', token }));
    return socket;
  }

  it('rejects an unauthenticated socket and closes it after repeated attempts', () => {
    const socket = new FakeSocket();
    hub.open(socket);
    for (let i = 0; i < 6; i++) {
      hub.handleMessage(socket, JSON.stringify({ type: 'ping', t: i }));
    }
    expect(socket.last('error')?.code).toBe('unauthenticated');
    expect(socket.closed).not.toBeNull();
  });

  it('rejects an invalid token', () => {
    const socket = new FakeSocket();
    hub.open(socket);
    hub.handleMessage(socket, JSON.stringify({ type: 'auth', token: 'not-a-token' }));
    expect(socket.last('error')?.code).toBe('unauthenticated');
    expect(socket.closed).not.toBeNull();
  });

  it('routes signaling between two authenticated devices', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const aliceSocket = connect(alice.token);
    const bobSocket = connect(bob.token);

    hub.handleMessage(
      aliceSocket,
      JSON.stringify({
        type: 'signal',
        to: { userId: bob.userId, deviceId: bob.deviceId },
        payload: { kind: 'offer', sdp: 'v=0', sessionId: 's1' },
      }),
    );

    const received = bobSocket.last('signal');
    expect(received?.payload).toMatchObject({ kind: 'offer', sdp: 'v=0' });
    // `from` is derived from the authenticated connection, never the payload.
    expect(received?.from).toEqual({ userId: alice.userId, deviceId: alice.deviceId });
  });

  it('reports peer_offline rather than silently dropping signaling', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const aliceSocket = connect(alice.token);

    hub.handleMessage(
      aliceSocket,
      JSON.stringify({
        type: 'signal',
        to: { userId: bob.userId, deviceId: bob.deviceId },
        payload: { kind: 'offer', sdp: 'v=0', sessionId: 's1' },
      }),
    );
    expect(aliceSocket.last('error')?.code).toBe('peer_offline');
  });

  it('queues a relay frame for an offline device and delivers it on connect', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const aliceSocket = connect(alice.token);

    const frame = Buffer.from('opaque-ciphertext').toString('base64');
    hub.handleMessage(
      aliceSocket,
      JSON.stringify({
        type: 'relay.send',
        to: { userId: bob.userId, deviceId: bob.deviceId },
        frame,
      }),
    );

    const bobSocket = connect(bob.token);
    const delivered = bobSocket.all('relay.deliver');
    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.frame).toBe(frame);
    expect(delivered[0]!.from).toEqual({ userId: alice.userId, deviceId: alice.deviceId });
  });

  it('removes an envelope only when its recipient acknowledges it', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const mallory = makeAccount('mallory');
    const aliceSocket = connect(alice.token);

    hub.handleMessage(
      aliceSocket,
      JSON.stringify({
        type: 'relay.send',
        to: { userId: bob.userId, deviceId: bob.deviceId },
        frame: Buffer.from('x').toString('base64'),
      }),
    );

    const bobSocket = connect(bob.token);
    const envelopeId = bobSocket.all('relay.deliver')[0]!.envelopeId;

    // Another account cannot acknowledge — and therefore cannot delete —
    // someone else's envelope.
    const mallorySocket = connect(mallory.token);
    hub.handleMessage(mallorySocket, JSON.stringify({ type: 'relay.ack', envelopeIds: [envelopeId] }));
    expect(relayQueue.depth({ userId: bob.userId, deviceId: bob.deviceId })).toBe(1);

    hub.handleMessage(bobSocket, JSON.stringify({ type: 'relay.ack', envelopeIds: [envelopeId] }));
    expect(relayQueue.depth({ userId: bob.userId, deviceId: bob.deviceId })).toBe(0);
  });

  it('delivers immediately when the recipient is already online', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const aliceSocket = connect(alice.token);
    const bobSocket = connect(bob.token);
    bobSocket.sent.length = 0;

    hub.handleMessage(
      aliceSocket,
      JSON.stringify({
        type: 'relay.send',
        to: { userId: bob.userId, deviceId: bob.deviceId },
        frame: Buffer.from('live').toString('base64'),
      }),
    );

    expect(bobSocket.all('relay.deliver')).toHaveLength(1);
  });

  it('reports presence to subscribed peers', () => {
    const alice = makeAccount('alice');
    const bob = makeAccount('bob');
    const aliceSocket = connect(alice.token);

    hub.handleMessage(
      aliceSocket,
      JSON.stringify({ type: 'presence.subscribe', userIds: [bob.userId] }),
    );
    const snapshot = aliceSocket.last('presence');
    expect(snapshot?.devices[0]).toMatchObject({ deviceId: bob.deviceId, online: false });

    const bobSocket = connect(bob.token);
    expect(aliceSocket.last('presence')?.devices[0]).toMatchObject({ online: true });

    hub.close(bobSocket);
    expect(aliceSocket.last('presence')?.devices[0]).toMatchObject({ online: false });
  });

  it('discards malformed messages without disturbing the connection', () => {
    const alice = makeAccount('alice');
    const socket = connect(alice.token);
    hub.handleMessage(socket, 'not json');
    hub.handleMessage(socket, JSON.stringify({ type: 'nonsense' }));
    expect(socket.all('error').every((e) => e.code === 'bad_request')).toBe(true);
    expect(socket.closed).toBeNull();
  });
});
