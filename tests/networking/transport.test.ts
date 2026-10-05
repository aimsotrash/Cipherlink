/**
 * Transport behaviour: direct connections, relay fallback, reconnection and
 * network transitions.
 *
 * These drive the real {@link PeerLink} state machine and the real signaling
 * client over a simulated WebRTC layer and an in-memory hub, so the fallback
 * and session logic under test is the code that ships.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { silentLogger, type PeerAddress, type TransportFrame } from '@p2pchat/shared';
import { PeerLink } from '../../client/src/p2p/peerLink.js';
import { asSignalTransport } from '../../client/src/p2p/signalingClient.js';
import { TransportManager } from '../../client/src/p2p/transportManager.js';
import type {
  DirectChannelFactory,
  SignalTransport,
  TransportKind,
} from '../../client/src/p2p/types.js';
import { FakeDirectNetwork } from '../helpers/fakeTransport.js';
import { FakeSignalingHub } from '../helpers/fakeSignaling.js';
import { waitFor } from '../helpers/e2e.js';

const ALICE: PeerAddress = { userId: 'aaaaaaaa-0000-4000-8000-000000000001', deviceId: '0000000000000001' };
const BOB: PeerAddress = { userId: 'bbbbbbbb-0000-4000-8000-000000000002', deviceId: '0000000000000002' };

const FRAME: TransportFrame = {
  v: 1,
  type: 'mls-app',
  conversationId: 'conv',
  payload: Buffer.from('ciphertext').toString('base64'),
};

/** For links whose channel factory never consults signaling. */
const silentSignal: SignalTransport = {
  send: () => undefined,
  subscribe: () => () => undefined,
  subscribeOffers: () => () => undefined,
};

const FAST_TIMINGS = {
  connectTimeoutMs: 200,
  retryDelaysMs: [20, 20, 20],
  upgradeIntervalMs: 50,
  keepaliveMs: 10_000,
};

describe('peer transport', () => {
  let network: FakeDirectNetwork;
  let hub: FakeSignalingHub;
  const relayed: { peer: PeerAddress; frame: TransportFrame }[] = [];
  let links: PeerLink[] = [];

  beforeEach(() => {
    network = new FakeDirectNetwork();
    hub = new FakeSignalingHub();
    relayed.length = 0;
    links = [];
  });

  afterEach(() => {
    for (const link of links) link.close();
    hub.stopAll();
  });

  function makeLink(
    self: PeerAddress,
    peer: PeerAddress,
    policy = { allowRelayFallback: true, preferDirectOnly: false },
    signal: SignalTransport = asSignalTransport(hub.client(self)),
  ): PeerLink {
    const link = new PeerLink({
      self,
      peer,
      channelFactory: network.factoryFor(self),
      signal,
      relay: { send: (to, frame) => relayed.push({ peer: to, frame }) },
      getIceServers: async () => [],
      policy: () => policy,
      logger: silentLogger,
      timings: FAST_TIMINGS,
    });
    links.push(link);
    return link;
  }

  it('establishes a direct connection between two peers', async () => {
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);

    const receivedByB: TransportFrame[] = [];
    b.onFrame.subscribe(({ frame }) => receivedByB.push(frame));

    a.connect();
    b.connect();

    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 5000, 'direct connection');
    expect(a.status.transport).toBe('p2p-direct');

    const via = await a.send(FRAME);
    expect(via).toBe('p2p-direct');
    await waitFor(() => receivedByB.length === 1, 5000, 'frame delivery');
    expect(receivedByB[0]).toEqual(FRAME);
    expect(relayed).toHaveLength(0);
  });

  it('falls back to the relay when a direct connection cannot be made', async () => {
    network.mode = 'fail';
    const a = makeLink(ALICE, BOB);

    a.connect();
    await waitFor(() => a.status.state === 'relay-only', 5000, 'relay fallback');

    const via = await a.send(FRAME);
    expect(via).toBe('relay');
    expect(relayed).toHaveLength(1);
    expect(relayed[0]!.frame).toEqual(FRAME);
  });

  it('reports a TURN-relayed path honestly rather than as a direct one', async () => {
    network.mode = 'succeed-relayed';
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);
    a.connect();
    b.connect();

    await waitFor(() => a.status.state === 'connected', 5000, 'connection');
    expect(a.status.transport).toBe('p2p-turn');
  });

  it('refuses a relayed path when the user requires a direct connection', async () => {
    network.mode = 'succeed-relayed';
    const a = makeLink(ALICE, BOB, { allowRelayFallback: false, preferDirectOnly: true });

    a.connect();
    await waitFor(() => a.status.state === 'failed', 5000, 'failure');

    // With relay fallback off there is no path at all, and the caller is told
    // rather than being silently downgraded.
    await expect(a.send(FRAME)).rejects.toThrow(/no direct connection/);
    expect(relayed).toHaveLength(0);
  });

  it('does not relay when relay fallback is disabled', async () => {
    network.mode = 'fail';
    const a = makeLink(ALICE, BOB, { allowRelayFallback: false, preferDirectOnly: false });

    a.connect();
    await waitFor(() => a.status.state === 'failed', 5000, 'failure');
    await expect(a.send(FRAME)).rejects.toThrow();
    expect(relayed).toHaveLength(0);
  });

  it('re-establishes a direct connection after the channel drops', async () => {
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);
    a.connect();
    b.connect();
    await waitFor(() => a.status.state === 'connected', 5000, 'first connection');

    // Simulate a network change that kills the live channel.
    network.dropAll();
    await waitFor(() => a.status.state !== 'connected', 5000, 'disconnection');

    // Both sides retry automatically and re-pair.
    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 8000, 'reconnection');
    expect(network.attempts).toBeGreaterThan(2);
  });

  it('keeps working over the relay while direct connectivity is down, then upgrades', async () => {
    network.mode = 'fail';
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);

    a.connect();
    await waitFor(() => a.status.state === 'relay-only', 5000, 'relay mode');
    expect(await a.send(FRAME)).toBe('relay');

    // Connectivity returns (e.g. the user leaves a restrictive network).
    network.mode = 'succeed';
    b.connect();
    await waitFor(() => a.status.state === 'connected', 8000, 'upgrade to direct');
    expect(await a.send(FRAME)).toBe('p2p-direct');
  });

  it('accepts relayed frames as inbound traffic while offline', async () => {
    network.mode = 'fail';
    const a = makeLink(ALICE, BOB);
    const received: { frame: TransportFrame; via: TransportKind }[] = [];
    a.onFrame.subscribe((event) => received.push(event));

    a.acceptRelayFrame(FRAME);
    expect(received).toHaveLength(1);
    expect(received[0]!.via).toBe('relay');
  });

  it('ignores keepalives rather than surfacing them as messages', async () => {
    const a = makeLink(ALICE, BOB);
    const received: TransportFrame[] = [];
    a.onFrame.subscribe(({ frame }) => received.push(frame));
    a.acceptRelayFrame({ v: 1, type: 'keepalive', t: Date.now() });
    expect(received).toHaveLength(0);
  });

  // ALICE's address sorts first, so in these tests she offers and BOB answers.

  it('answers in the session the offer named, never one of its own', async () => {
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);
    a.connect();
    b.connect();
    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 5000, 'direct connection');

    const offered = network.attemptLog.filter((entry) => entry.initiator).map((entry) => entry.sessionId);
    const answered = network.attemptLog.filter((entry) => !entry.initiator).map((entry) => entry.sessionId);
    expect(answered.length).toBeGreaterThan(0);
    for (const sessionId of answered) expect(offered).toContain(sessionId);
  });

  it('answers an offer that arrived before the answering side was listening', async () => {
    // BOB is online but has no link to ALICE yet, as when her offer races ahead
    // of the relayed message that makes his client open one.
    const bobSignal = asSignalTransport(hub.client(BOB));
    const a = makeLink(ALICE, BOB);
    a.connect();
    await waitFor(() => network.attemptLog.some((entry) => entry.initiator), 5000, 'offer');
    await new Promise((resolve) => setTimeout(resolve, 30));

    const b = makeLink(BOB, ALICE, undefined, bobSignal);
    b.connect();
    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 5000, 'direct connection');
    // The original offer was answered: neither side had to retry.
    expect(network.attemptLog).toHaveLength(2);
  });

  it('replaces a stale channel when the offering side starts over', async () => {
    const a = makeLink(ALICE, BOB);
    const b = makeLink(BOB, ALICE);
    a.connect();
    b.connect();
    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 5000, 'first connection');
    const firstSession = network.attemptLog[0]!.sessionId;

    // Only ALICE notices the path died; BOB's end still looks open.
    network.dropEnd(ALICE);
    await waitFor(() => network.attemptLog.filter((entry) => entry.initiator).length >= 2, 5000, 'new offer');
    await waitFor(() => a.status.state === 'connected' && b.status.state === 'connected', 5000, 'reconnection');

    const received: TransportFrame[] = [];
    b.onFrame.subscribe(({ frame }) => received.push(frame));
    expect(await a.send(FRAME)).toBe('p2p-direct');
    await waitFor(() => received.length === 1, 5000, 'delivery over the new channel');
    expect(network.attemptLog.at(-1)!.sessionId).not.toBe(firstSession);
  });

  it('drops a negotiation the offerer abandoned when a newer offer arrives', async () => {
    const attempts: { sessionId: string; aborted: boolean }[] = [];
    const stalls: DirectChannelFactory = {
      connect: (options) =>
        new Promise((_resolve, reject) => {
          const attempt = { sessionId: options.sessionId, aborted: false };
          attempts.push(attempt);
          options.abortSignal?.addEventListener('abort', () => {
            attempt.aborted = true;
            reject(new Error('aborted'));
          });
        }),
    };
    const b = new PeerLink({
      self: BOB,
      peer: ALICE,
      channelFactory: stalls,
      signal: silentSignal,
      relay: { send: () => undefined },
      getIceServers: async () => [],
      policy: () => ({ allowRelayFallback: true, preferDirectOnly: false }),
      logger: silentLogger,
      timings: { ...FAST_TIMINGS, connectTimeoutMs: 5_000 },
    });
    links.push(b);

    b.acceptOffer('first-session');
    await waitFor(() => attempts.length === 1, 5000, 'first answer');
    b.acceptOffer('second-session');
    await waitFor(() => attempts.length === 2, 5000, 'second answer');

    expect(attempts[0]).toEqual({ sessionId: 'first-session', aborted: true });
    expect(attempts[1]).toEqual({ sessionId: 'second-session', aborted: false });
    // Being superseded is not a failure, so the link did not fall back.
    expect(b.status.state).toBe('connecting');
  });

  it('never answers on the offering side', async () => {
    const attempts: string[] = [];
    const a = new PeerLink({
      self: ALICE,
      peer: BOB,
      channelFactory: {
        connect: (options) => {
          attempts.push(options.sessionId);
          return new Promise(() => undefined);
        },
      },
      signal: silentSignal,
      relay: { send: () => undefined },
      getIceServers: async () => [],
      policy: () => ({ allowRelayFallback: true, preferDirectOnly: false }),
      logger: silentLogger,
      timings: FAST_TIMINGS,
    });
    links.push(a);

    a.acceptOffer('unsolicited');
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(attempts).toHaveLength(0);
  });
});

describe('transport manager', () => {
  it('routes frames per peer and reports status for each', async () => {
    const network = new FakeDirectNetwork();
    const hub = new FakeSignalingHub();
    const relayedFrames: TransportFrame[] = [];

    const managerA = new TransportManager({
      self: ALICE,
      channelFactory: network.factoryFor(ALICE),
      signal: asSignalTransport(hub.client(ALICE)),
      relay: { send: (_peer, frame) => relayedFrames.push(frame) },
      getIceServers: async () => [],
      policy: () => ({ allowRelayFallback: true, preferDirectOnly: false }),
      logger: silentLogger,
      timings: FAST_TIMINGS,
    });
    const managerB = new TransportManager({
      self: BOB,
      channelFactory: network.factoryFor(BOB),
      signal: asSignalTransport(hub.client(BOB)),
      relay: { send: () => undefined },
      getIceServers: async () => [],
      policy: () => ({ allowRelayFallback: true, preferDirectOnly: false }),
      logger: silentLogger,
      timings: FAST_TIMINGS,
    });

    const received: TransportFrame[] = [];
    managerB.onFrame.subscribe(({ frame }) => received.push(frame));

    managerA.warmUp(BOB);
    managerB.warmUp(ALICE);
    await waitFor(() => managerA.statusFor(BOB)?.state === 'connected', 5000, 'connection');

    await managerA.send(BOB, FRAME);
    await waitFor(() => received.length === 1, 5000, 'delivery');

    expect(managerA.allStatuses()).toHaveLength(1);
    expect(relayedFrames).toHaveLength(0);

    managerA.closeAll();
    managerB.closeAll();
    hub.stopAll();
  });
});
