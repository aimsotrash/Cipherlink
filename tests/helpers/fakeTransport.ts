/**
 * Simulated WebRTC layer.
 *
 * Real WebRTC is not available in Node, and more importantly it is not
 * *controllable*: these tests need to force a direct connection to fail, to
 * drop mid-session, or to succeed on the second attempt. This factory does
 * that deterministically while driving the same {@link PeerLink} state machine
 * the browser uses.
 *
 * It negotiates over the signaling the caller supplies, the way WebRTC does:
 * the offering side sends an offer under its session ID and waits for an
 * answer under the same ID, and channels pair up by session. Two sides that
 * disagree about the session never meet, exactly as in a browser.
 */
import type { PeerAddress, SignalPayload } from '@p2pchat/shared';
import {
  EventChannel,
  peerKey,
  type DirectChannel,
  type DirectChannelConnectOptions,
  type DirectChannelFactory,
} from '../../client/src/p2p/types.js';

class LoopbackChannel implements DirectChannel {
  readonly onMessage = new EventChannel<string>();
  readonly onClose = new EventChannel<{ reason: string }>();
  peer: LoopbackChannel | null = null;
  private open = true;

  constructor(
    readonly relayed: boolean,
    /** Address of the side that holds this end. */
    readonly owner: string,
  ) {}

  send(data: string): void {
    if (!this.open) throw new Error('channel is closed');
    // Deliver asynchronously, like a real network would.
    queueMicrotask(() => this.peer?.onMessage.emit(data));
  }

  close(): void {
    if (!this.open) return;
    this.open = false;
    this.onClose.emit({ reason: 'closed locally' });
    const peer = this.peer;
    this.peer = null;
    peer?.remoteClosed();
  }

  /**
   * Lose this end only, as when one side's network changes and the other side
   * has not noticed yet: the far end stays open, and what it sends vanishes.
   */
  loseLocally(): void {
    if (!this.open) return;
    this.open = false;
    if (this.peer) this.peer.peer = null;
    this.peer = null;
    this.onClose.emit({ reason: 'network changed' });
  }

  /** Simulate the far end (or the network) going away. */
  remoteClosed(): void {
    if (!this.open) return;
    this.open = false;
    this.peer = null;
    this.onClose.emit({ reason: 'peer disconnected' });
  }
}

interface PendingConnect {
  resolve(channel: LoopbackChannel): void;
  channel: LoopbackChannel;
}

export type DirectMode = 'succeed' | 'fail' | 'succeed-relayed';

export interface AttemptRecord {
  readonly self: string;
  readonly sessionId: string;
  readonly initiator: boolean;
}

/**
 * Shared rendezvous between the clients in a test. Both sides call
 * `connect()` and negotiate; the first to finish waits, the second links them
 * together.
 */
export class FakeDirectNetwork {
  mode: DirectMode = 'succeed';
  /** Incremented on every connection attempt, successful or not. */
  attempts = 0;
  /** Every connection attempt, in order, with the session it used. */
  readonly attemptLog: AttemptRecord[] = [];
  private readonly waiting = new Map<string, PendingConnect>();
  private readonly live = new Set<LoopbackChannel>();

  factoryFor(self: PeerAddress): DirectChannelFactory {
    return {
      connect: (options: DirectChannelConnectOptions) => this.connect(self, options),
    };
  }

  private async connect(
    self: PeerAddress,
    options: DirectChannelConnectOptions,
  ): Promise<DirectChannel> {
    this.attempts += 1;
    this.attemptLog.push({
      self: peerKey(self),
      sessionId: options.sessionId,
      initiator: options.initiator,
    });

    if (this.mode === 'fail') {
      throw new Error('simulated: no direct path available');
    }
    if (options.directOnly && this.mode === 'succeed-relayed') {
      throw new Error('simulated: only a relayed path was available');
    }

    await negotiate(options);
    return this.rendezvous(peerKey(self), options, this.mode === 'succeed-relayed');
  }

  private rendezvous(
    owner: string,
    options: DirectChannelConnectOptions,
    relayed: boolean,
  ): Promise<DirectChannel> {
    const key = options.sessionId;
    const waiting = this.waiting.get(key);

    if (waiting) {
      this.waiting.delete(key);
      const ours = new LoopbackChannel(relayed, owner);
      ours.peer = waiting.channel;
      waiting.channel.peer = ours;
      this.live.add(ours).add(waiting.channel);
      waiting.resolve(waiting.channel);
      return Promise.resolve(ours);
    }

    const channel = new LoopbackChannel(relayed, owner);
    return new Promise<DirectChannel>((resolve, reject) => {
      this.waiting.set(key, { resolve, channel });
      const timer = setTimeout(() => {
        if (this.waiting.get(key)?.channel === channel) {
          this.waiting.delete(key);
          reject(new Error('simulated: timed out waiting for the peer'));
        }
      }, options.timeoutMs);
      if (typeof timer === 'object' && 'unref' in timer) timer.unref();
    });
  }

  /** Lose `self`'s ends of its live channels, leaving the far ends open. */
  dropEnd(self: PeerAddress): void {
    for (const channel of this.live) {
      if (channel.owner !== peerKey(self)) continue;
      channel.loseLocally();
      this.live.delete(channel);
    }
  }

  /** Kill every live direct channel, as a network change would. */
  dropAll(): void {
    for (const channel of this.live) channel.remoteClosed();
    this.live.clear();
    this.waiting.clear();
  }

  reset(): void {
    this.dropAll();
    this.attempts = 0;
    this.attemptLog.length = 0;
    this.mode = 'succeed';
  }
}

/** Offer/answer exchange over the caller's signaling, keyed by session. */
function negotiate(options: DirectChannelConnectOptions): Promise<void> {
  const { peer, sessionId, initiator, signal, abortSignal } = options;
  return new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let unsubscribe = (): void => undefined;
    const finish = (error?: Error): void => {
      clearTimeout(timer);
      unsubscribe();
      abortSignal?.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve();
    };
    const onAbort = (): void => finish(new Error('simulated: connection attempt aborted'));

    unsubscribe = signal.subscribe(peer, sessionId, (payload: SignalPayload) => {
      if (initiator && payload.kind === 'answer') finish();
      if (!initiator && payload.kind === 'offer') {
        signal.send(peer, { kind: 'answer', sdp: 'simulated-answer', sessionId });
        finish();
      }
    });
    abortSignal?.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(
      () => finish(new Error('simulated: timed out waiting for the peer')),
      options.timeoutMs,
    );
    if (typeof timer === 'object' && 'unref' in timer) timer.unref();

    if (initiator) signal.send(peer, { kind: 'offer', sdp: 'simulated-offer', sessionId });
  });
}
