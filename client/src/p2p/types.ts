/**
 * Transport abstractions.
 *
 * Everything below carries opaque, already-encrypted frames. No component in
 * this directory can read message content: by the time a frame reaches the
 * transport it is an MLS message, and the transport holds no MLS state.
 */
import type { PeerAddress, SignalPayload, TransportFrame } from '@p2pchat/shared';

export type ConnectionState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'relay-only'
  | 'failed'
  | 'closed';

/** How a frame actually travelled. Surfaced in the UI so users can see it. */
export type TransportKind = 'p2p-direct' | 'p2p-turn' | 'relay';

export interface PeerLinkStatus {
  readonly peer: PeerAddress;
  readonly state: ConnectionState;
  readonly transport: TransportKind | null;
  readonly since: number;
  /** Populated when the last connection attempt failed; never secret. */
  readonly lastError: string | null;
}

/**
 * A bidirectional direct channel to a peer.
 *
 * Implemented by WebRTC in production and by a simulator in tests, so the
 * fallback and reconnection logic can be exercised deterministically.
 */
export interface DirectChannel {
  /** True when media is flowing through a TURN relay rather than peer-to-peer. */
  readonly relayed: boolean;
  send(data: string): void;
  close(): void;
  readonly onMessage: EventChannel<string>;
  readonly onClose: EventChannel<{ reason: string }>;
}

export interface DirectChannelFactory {
  /**
   * Attempt to establish a direct channel. Rejects if connectivity cannot be
   * established within the caller's timeout — the signal to fall back.
   */
  connect(options: DirectChannelConnectOptions): Promise<DirectChannel>;
}

export interface DirectChannelConnectOptions {
  readonly peer: PeerAddress;
  readonly sessionId: string;
  /** True when we send the offer; false when we answer one. */
  readonly initiator: boolean;
  readonly iceServers: RTCIceServer[];
  /** Refuse TURN candidates, keeping traffic strictly peer-to-peer. */
  readonly directOnly: boolean;
  readonly signal: SignalTransport;
  readonly timeoutMs: number;
  readonly abortSignal?: AbortSignal;
}

/** The subset of signaling a channel implementation needs. */
export interface SignalTransport {
  send(peer: PeerAddress, payload: SignalPayload): void;
  /**
   * Fires for signaling addressed to us from `peer` for `sessionId`. Signals
   * that arrived before anyone subscribed (the offer, early ICE candidates)
   * are replayed to the subscriber, so joining a session late loses nothing.
   */
  subscribe(
    peer: PeerAddress,
    sessionId: string,
    handler: (payload: SignalPayload) => void,
  ): () => void;
  /**
   * Fires with the session ID of each offer `peer` sends us, including one
   * that arrived shortly before this subscription. Only the offering side
   * picks session IDs; this is how the answering side learns which to join.
   */
  subscribeOffers(peer: PeerAddress, handler: (sessionId: string) => void): () => void;
}

/** Minimal typed event emitter. */
export class EventChannel<T> {
  private readonly handlers = new Set<(value: T) => void>();

  subscribe(handler: (value: T) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  emit(value: T): void {
    for (const handler of [...this.handlers]) {
      try {
        handler(value);
      } catch {
        // A misbehaving subscriber must not break delivery to the others.
      }
    }
  }

  get size(): number {
    return this.handlers.size;
  }
}

export interface InboundFrame {
  readonly from: PeerAddress;
  readonly frame: TransportFrame;
  readonly via: TransportKind;
}

export function peerKey(peer: PeerAddress): string {
  return `${peer.userId}:${peer.deviceId}`;
}
