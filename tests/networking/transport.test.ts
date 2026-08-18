/**
 * Transport behaviour: direct connections, relay fallback, reconnection and
 * network transitions.
 *
 * These drive the real {@link PeerLink} state machine over a simulated WebRTC
 * layer, so the fallback logic under test is the code that ships.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { silentLogger, type PeerAddress, type TransportFrame } from '@p2pchat/shared';
import { PeerLink } from '../../client/src/p2p/peerLink.js';
import { TransportManager } from '../../client/src/p2p/transportManager.js';
import type { SignalTransport, TransportKind } from '../../client/src/p2p/types.js';
import { FakeDirectNetwork } from '../helpers/fakeTransport.js';
import { waitFor } from '../helpers/e2e.js';

const ALICE: PeerAddress = { userId: 'aaaaaaaa-0000-4000-8000-000000000001', deviceId: '0000000000000001' };
const BOB: PeerAddress = { userId: 'bbbbbbbb-0000-4000-8000-000000000002', deviceId: '0000000000000002' };

const FRAME: TransportFrame = {
  v: 1,
  type: 'mls-app',
  conversationId: 'conv',
  payload: Buffer.from('ciphertext').toString('base64'),
};

/** Signaling is irrelevant to the simulated channel; satisfy the interface. */
const noopSignal: SignalTransport = {
  send: () => undefined,
  subscribe: () => () => undefined,
};

const FAST_TIMINGS = {
  connectTimeoutMs: 200,
  retryDelaysMs: [20, 20, 20],
  upgradeIntervalMs: 50,
  keepaliveMs: 10_000,
};

describe('peer transport', () => {
  let network: FakeDirectNetwork;
  const relayed: { peer: PeerAddress; frame: TransportFrame }[] = [];
  let links: PeerLink[] = [];

  beforeEach(() => {
    network = new FakeDirectNetwork();
    relayed.length = 0;
    links = [];
  });

  afterEach(() => {
    for (const link of links) link.close();
  });

  function makeLink(
    self: PeerAddress,
    peer: PeerAddress,
    policy = { allowRelayFallback: true, preferDirectOnly: false },
  ): PeerLink {
    const link = new PeerLink({
      self,
      peer,
      channelFactory: network.factoryFor(self),
      signal: noopSignal,
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
});

describe('transport manager', () => {
  it('routes frames per peer and reports status for each', async () => {
    const network = new FakeDirectNetwork();
    const relayedFrames: TransportFrame[] = [];

    const managerA = new TransportManager({
      self: ALICE,
      channelFactory: network.factoryFor(ALICE),
      signal: noopSignal,
      relay: { send: (_peer, frame) => relayedFrames.push(frame) },
      getIceServers: async () => [],
      policy: () => ({ allowRelayFallback: true, preferDirectOnly: false }),
      logger: silentLogger,
      timings: FAST_TIMINGS,
    });
    const managerB = new TransportManager({
      self: BOB,
      channelFactory: network.factoryFor(BOB),
      signal: noopSignal,
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
  });
});
