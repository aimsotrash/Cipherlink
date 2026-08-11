/**
 * Per-peer connection manager.
 *
 * Implements the policy the architecture calls for: prefer a direct WebRTC
 * DataChannel; when that cannot be established, fall back to the server relay
 * carrying the same ciphertext; keep trying to upgrade back to direct.
 *
 * The security-relevant property is that the fallback changes *nothing* about
 * confidentiality. Frames handed to `send()` are already MLS ciphertext, so
 * both paths carry bytes the server cannot read. Falling back is a privacy and
 * latency downgrade (the server learns timing and volume, and holds the
 * envelope until collection), never a confidentiality one.
 */
import {
  silentLogger,
  transportFrameSchema,
  type Logger,
  type PeerAddress,
  type TransportFrame,
} from '@p2pchat/shared';
import {
  EventChannel,
  peerKey,
  type ConnectionState,
  type DirectChannel,
  type DirectChannelFactory,
  type PeerLinkStatus,
  type SignalTransport,
  type TransportKind,
} from './types.js';
import { randomId } from '../crypto/random.js';

export interface PeerLinkRelay {
  send(peer: PeerAddress, frame: TransportFrame): void;
}

export interface PeerLinkPolicy {
  /** Allow store-and-forward through the server when direct fails. */
  readonly allowRelayFallback: boolean;
  /** Refuse TURN-relayed media paths; direct-or-nothing. */
  readonly preferDirectOnly: boolean;
}

export interface PeerLinkTimings {
  readonly connectTimeoutMs: number;
  /** How long to wait before retrying a direct connection after a failure. */
  readonly retryDelaysMs: number[];
  /** While on relay, how often to attempt an upgrade back to direct. */
  readonly upgradeIntervalMs: number;
  readonly keepaliveMs: number;
}

export const DEFAULT_TIMINGS: PeerLinkTimings = {
  connectTimeoutMs: 15_000,
  retryDelaysMs: [1_000, 3_000, 8_000, 20_000, 60_000],
  upgradeIntervalMs: 60_000,
  keepaliveMs: 20_000,
};

export interface PeerLinkOptions {
  readonly self: PeerAddress;
  readonly peer: PeerAddress;
  readonly channelFactory: DirectChannelFactory;
  readonly signal: SignalTransport;
  readonly relay: PeerLinkRelay;
  readonly getIceServers: () => Promise<RTCIceServer[]>;
  readonly policy: () => PeerLinkPolicy;
  readonly logger?: Logger;
  readonly timings?: Partial<PeerLinkTimings>;
  readonly now?: () => number;
}

export class PeerLink {
  readonly onFrame = new EventChannel<{ frame: TransportFrame; via: TransportKind }>();
  readonly onStatus = new EventChannel<PeerLinkStatus>();

  private readonly logger: Logger;
  private readonly timings: PeerLinkTimings;
  private readonly now: () => number;

  private state: ConnectionState = 'idle';
  private transport: TransportKind | null = null;
  private lastError: string | null = null;
  private since: number;

  private channel: DirectChannel | null = null;
  private channelDisposers: Array<() => void> = [];
  private connectAbort: AbortController | null = null;
  private attempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private upgradeTimer: ReturnType<typeof setInterval> | null = null;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private connecting: Promise<void> | null = null;
  private closed = false;
  /** Frames waiting for any usable path. */
  private readonly pending: TransportFrame[] = [];

  constructor(private readonly options: PeerLinkOptions) {
    this.logger = (options.logger ?? silentLogger).child('peerlink', {
      peerUserId: options.peer.userId,
      peerDeviceId: options.peer.deviceId,
    });
    this.timings = { ...DEFAULT_TIMINGS, ...(options.timings ?? {}) };
    this.now = options.now ?? Date.now;
    this.since = this.now();
  }

  get status(): PeerLinkStatus {
    return {
      peer: this.options.peer,
      state: this.state,
      transport: this.transport,
      since: this.since,
      lastError: this.lastError,
    };
  }

  /**
   * Glare avoidance: exactly one side sends the offer, decided by comparing
   * addresses, so two peers connecting simultaneously do not deadlock.
   */
  private get isInitiator(): boolean {
    return peerKey(this.options.self) < peerKey(this.options.peer);
  }

  private setState(state: ConnectionState, transport: TransportKind | null): void {
    if (this.state === state && this.transport === transport) return;
    this.state = state;
    this.transport = transport;
    this.since = this.now();
    this.onStatus.emit(this.status);
  }

  /** Begin (or resume) trying to reach the peer. */
  connect(): void {
    if (this.closed) return;
    void this.ensureDirectChannel();
  }

  private async ensureDirectChannel(): Promise<void> {
    if (this.closed || this.channel || this.connecting) return;
    const policy = this.options.policy();

    this.setState(this.state === 'relay-only' ? 'relay-only' : 'connecting', this.transport);

    const attempt = (async () => {
      const abort = new AbortController();
      this.connectAbort = abort;
      try {
        const iceServers = await this.options.getIceServers();
        const channel = await this.options.channelFactory.connect({
          peer: this.options.peer,
          sessionId: randomId(),
          initiator: this.isInitiator,
          iceServers,
          directOnly: policy.preferDirectOnly,
          signal: this.options.signal,
          timeoutMs: this.timings.connectTimeoutMs,
          abortSignal: abort.signal,
        });
        this.adoptChannel(channel);
      } catch (error) {
        this.handleDirectFailure(error);
      } finally {
        this.connectAbort = null;
        this.connecting = null;
      }
    })();

    this.connecting = attempt;
    await attempt;
  }

  private adoptChannel(channel: DirectChannel): void {
    if (this.closed) {
      channel.close();
      return;
    }
    this.channel = channel;
    this.attempt = 0;
    this.lastError = null;
    this.stopUpgradeTimer();

    this.channelDisposers = [
      channel.onMessage.subscribe((data) => this.handleChannelMessage(data)),
      channel.onClose.subscribe(({ reason }) => this.handleChannelClosed(reason)),
    ];

    this.setState('connected', channel.relayed ? 'p2p-turn' : 'p2p-direct');
    this.logger.info('direct channel ready', { relayed: channel.relayed });
    this.startKeepalive();
    this.flushPending();
  }

  private handleDirectFailure(error: unknown): void {
    const reason = error instanceof Error ? error.message : 'direct connection failed';
    this.lastError = reason;
    this.logger.warn('direct connection attempt failed', { attempt: this.attempt });

    const policy = this.options.policy();
    if (policy.allowRelayFallback) {
      this.setState('relay-only', 'relay');
      this.flushPending();
      this.startUpgradeTimer();
    } else {
      this.setState('failed', null);
    }
    this.scheduleRetry();
  }

  private handleChannelClosed(reason: string): void {
    this.teardownChannel();
    if (this.closed) return;
    this.lastError = reason;
    this.logger.info('direct channel closed, will re-establish');
    const policy = this.options.policy();
    this.setState(policy.allowRelayFallback ? 'relay-only' : 'reconnecting', policy.allowRelayFallback ? 'relay' : null);
    if (policy.allowRelayFallback) this.startUpgradeTimer();
    this.scheduleRetry();
  }

  private teardownChannel(): void {
    for (const dispose of this.channelDisposers.splice(0)) dispose();
    this.channel = null;
    this.stopKeepalive();
  }

  private scheduleRetry(): void {
    if (this.closed || this.retryTimer) return;
    const delays = this.timings.retryDelaysMs;
    const delay = delays[Math.min(this.attempt, delays.length - 1)] ?? 30_000;
    this.attempt += 1;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (!this.closed && !this.channel) void this.ensureDirectChannel();
    }, delay);
  }

  private startUpgradeTimer(): void {
    if (this.upgradeTimer || this.closed) return;
    this.upgradeTimer = setInterval(() => {
      if (!this.channel && !this.closed) void this.ensureDirectChannel();
    }, this.timings.upgradeIntervalMs);
  }

  private stopUpgradeTimer(): void {
    if (this.upgradeTimer) {
      clearInterval(this.upgradeTimer);
      this.upgradeTimer = null;
    }
  }

  private startKeepalive(): void {
    this.stopKeepalive();
    this.keepaliveTimer = setInterval(() => {
      if (!this.channel) return;
      try {
        this.channel.send(
          JSON.stringify({ v: 1, type: 'keepalive', t: this.now() } satisfies TransportFrame),
        );
      } catch {
        this.handleChannelClosed('keepalive failed');
      }
    }, this.timings.keepaliveMs);
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
    }
  }

  private handleChannelMessage(data: string): void {
    let frame: TransportFrame;
    try {
      frame = transportFrameSchema.parse(JSON.parse(data));
    } catch {
      // Never attempt to salvage a malformed frame from the network.
      this.logger.warn('discarded malformed frame from data channel');
      return;
    }
    if (frame.type === 'keepalive') return;
    this.onFrame.emit({ frame, via: this.transport === 'p2p-turn' ? 'p2p-turn' : 'p2p-direct' });
  }

  /** Called by the transport manager when a relay envelope arrives for us. */
  acceptRelayFrame(frame: TransportFrame): void {
    if (frame.type === 'keepalive') return;
    this.onFrame.emit({ frame, via: 'relay' });
  }

  /**
   * Send an already-encrypted frame by the best available path.
   *
   * Returns which transport carried it. Throws only when no path is usable and
   * the caller must treat the message as unsent.
   */
  async send(frame: TransportFrame): Promise<TransportKind> {
    if (this.closed) throw new Error('peer link is closed');

    if (this.channel) {
      try {
        this.channel.send(JSON.stringify(frame));
        return this.transport === 'p2p-turn' ? 'p2p-turn' : 'p2p-direct';
      } catch {
        // The channel died between the readiness check and the write.
        this.handleChannelClosed('send failed');
      }
    }

    const policy = this.options.policy();
    if (policy.allowRelayFallback) {
      this.options.relay.send(this.options.peer, frame);
      this.connect();
      return 'relay';
    }

    this.pending.push(frame);
    this.connect();
    throw new Error('no direct connection available and relay fallback is disabled');
  }

  private flushPending(): void {
    if (this.pending.length === 0) return;
    const queued = this.pending.splice(0);
    for (const frame of queued) {
      void this.send(frame).catch(() => {
        // Put it back; the next transition will try again.
        this.pending.push(frame);
      });
    }
  }

  close(): void {
    this.closed = true;
    this.connectAbort?.abort();
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.stopUpgradeTimer();
    this.stopKeepalive();
    if (this.channel) {
      const channel = this.channel;
      this.teardownChannel();
      channel.close();
    }
    this.setState('closed', null);
  }
}
