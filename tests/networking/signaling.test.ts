/**
 * Signaling routing: per-session delivery, replay of signals that arrive
 * before their session is joined, and the offer notifications the answering
 * side relies on to learn which session to join.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { PeerAddress, SignalPayload } from '@p2pchat/shared';
import type { SignalingClient } from '../../client/src/p2p/signalingClient.js';
import { FakeSignalingHub } from '../helpers/fakeSignaling.js';
import { waitFor } from '../helpers/e2e.js';

const ALICE: PeerAddress = { userId: 'aaaaaaaa-0000-4000-8000-000000000001', deviceId: '0000000000000001' };
const BOB: PeerAddress = { userId: 'bbbbbbbb-0000-4000-8000-000000000002', deviceId: '0000000000000002' };
const CAROL: PeerAddress = { userId: 'cccccccc-0000-4000-8000-000000000003', deviceId: '0000000000000003' };

const offer = (sessionId: string): SignalPayload => ({ kind: 'offer', sdp: 'v=0', sessionId });
const candidate = (sessionId: string, n: number): SignalPayload => ({
  kind: 'ice-candidate',
  sessionId,
  candidate: `candidate:${n} 1 udp 2122260223 192.0.2.1 ${50_000 + n} typ host`,
  sdpMid: '0',
  sdpMLineIndex: 0,
});

/** Let the hub's asynchronous deliveries land. */
const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

describe('signaling client', () => {
  let hub: FakeSignalingHub;
  let alice: SignalingClient;
  let bob: SignalingClient;
  let carol: SignalingClient;
  let clock: number;

  beforeEach(async () => {
    hub = new FakeSignalingHub();
    clock = 1_000_000;
    alice = hub.client(ALICE);
    bob = hub.client(BOB, { now: () => clock });
    carol = hub.client(CAROL);
    await waitFor(
      () => [alice, bob, carol].every((client) => client.currentState === 'ready'),
      5000,
      'clients ready',
    );
  });

  afterEach(() => hub.stopAll());

  it('replays signals that arrived before their session was joined, in order', async () => {
    alice.sendSignal(BOB, offer('s1'));
    alice.sendSignal(BOB, candidate('s1', 1));
    alice.sendSignal(BOB, candidate('s1', 2));
    await settle();

    const seen: SignalPayload[] = [];
    bob.subscribe(ALICE, 's1', (payload) => seen.push(payload));
    await waitFor(() => seen.length === 3, 5000, 'replay');
    expect(seen).toEqual([offer('s1'), candidate('s1', 1), candidate('s1', 2)]);

    // Replayed once only: a later subscriber starts from live traffic.
    const later: SignalPayload[] = [];
    bob.subscribe(ALICE, 's1', (payload) => later.push(payload));
    alice.sendSignal(BOB, candidate('s1', 3));
    await waitFor(() => later.length === 1, 5000, 'live candidate');
    expect(later).toEqual([candidate('s1', 3)]);
  });

  it('tells offer listeners which session to join, including an offer that arrived first', async () => {
    alice.sendSignal(BOB, offer('early'));
    await settle();

    const sessions: string[] = [];
    bob.subscribeOffers(ALICE, (sessionId) => sessions.push(sessionId));
    await waitFor(() => sessions.length === 1, 5000, 'held offer');

    alice.sendSignal(BOB, offer('live'));
    await waitFor(() => sessions.length === 2, 5000, 'live offer');
    expect(sessions).toEqual(['early', 'live']);
  });

  it('reports offers only from the peer that was asked about', async () => {
    const sessions: string[] = [];
    bob.subscribeOffers(ALICE, (sessionId) => sessions.push(sessionId));
    carol.sendSignal(BOB, offer('from-carol'));
    alice.sendSignal(BOB, candidate('not-an-offer', 1));
    await settle();
    expect(sessions).toEqual([]);
  });

  it('forgets signals for sessions nobody joins', async () => {
    alice.sendSignal(BOB, offer('stale'));
    await settle();
    clock += 31_000;

    const seen: SignalPayload[] = [];
    const sessions: string[] = [];
    bob.subscribe(ALICE, 'stale', (payload) => seen.push(payload));
    bob.subscribeOffers(ALICE, (sessionId) => sessions.push(sessionId));
    await settle();
    expect(seen).toEqual([]);
    expect(sessions).toEqual([]);
  });

  it('caps how many unjoined sessions it holds, dropping the oldest', async () => {
    for (let i = 0; i < 20; i++) alice.sendSignal(BOB, offer(`s${i}`));
    await settle();

    const oldest: SignalPayload[] = [];
    const newest: SignalPayload[] = [];
    bob.subscribe(ALICE, 's0', (payload) => oldest.push(payload));
    bob.subscribe(ALICE, 's19', (payload) => newest.push(payload));
    await settle();
    expect(oldest).toEqual([]);
    expect(newest).toEqual([offer('s19')]);
  });
});
