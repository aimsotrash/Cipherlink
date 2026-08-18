/**
 * Simulated WebRTC layer.
 *
 * Real WebRTC is not available in Node, and more importantly it is not
 * *controllable*: these tests need to force a direct connection to fail, to
 * drop mid-session, or to succeed on the second attempt. This factory does
 * that deterministically while driving the same {@link PeerLink} state machine
 * the browser uses.
 */
import type { PeerAddress } from '@p2pchat/shared';
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

  constructor(readonly relayed: boolean) {}

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

/**
 * Shared rendezvous between the clients in a test. Both sides call
 * `connect()`; the first waits, the second links them together.
 */
export class FakeDirectNetwork {
  mode: DirectMode = 'succeed';
  /** Incremented on every connection attempt, successful or not. */
  attempts = 0;
  private readonly waiting = new Map<string, PendingConnect>();
  private readonly live = new Set<LoopbackChannel>();

  factoryFor(self: PeerAddress): DirectChannelFactory {
    return {
      connect: (options: DirectChannelConnectOptions) => this.connect(self, options),
    };
  }

  private connect(
    self: PeerAddress,
    options: DirectChannelConnectOptions,
  ): Promise<DirectChannel> {
    this.attempts += 1;

    if (this.mode === 'fail') {
      return Promise.reject(new Error('simulated: no direct path available'));
    }
    if (options.directOnly && this.mode === 'succeed-relayed') {
      return Promise.reject(new Error('simulated: only a relayed path was available'));
    }

    const relayed = this.mode === 'succeed-relayed';
    const key = [peerKey(self), peerKey(options.peer)].sort().join('|');
    const waiting = this.waiting.get(key);

    if (waiting) {
      this.waiting.delete(key);
      const ours = new LoopbackChannel(relayed);
      ours.peer = waiting.channel;
      waiting.channel.peer = ours;
      this.live.add(ours).add(waiting.channel);
      waiting.resolve(waiting.channel);
      return Promise.resolve(ours);
    }

    const channel = new LoopbackChannel(relayed);
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

  /** Kill every live direct channel, as a network change would. */
  dropAll(): void {
    for (const channel of this.live) channel.remoteClosed();
    this.live.clear();
    this.waiting.clear();
  }

  reset(): void {
    this.dropAll();
    this.attempts = 0;
    this.mode = 'succeed';
  }
}
