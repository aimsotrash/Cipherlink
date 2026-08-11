/**
 * WebSocket client for signaling, presence and the ciphertext relay.
 *
 * Responsibilities:
 *   - authenticate the socket with the device session token,
 *   - carry WebRTC offer/answer/ICE to a peer,
 *   - carry opaque relay frames when direct connectivity is unavailable,
 *   - reconnect with exponential backoff and resume delivery.
 *
 * The server sees every byte that crosses this socket. That is fine for
 * signaling (SDP/ICE are inherently server-visible) and safe for relay frames
 * (they are MLS ciphertext), but it is why offline/online transitions and IP
 * exposure are called out in THREAT_MODEL.md.
 */
import {
  clientToServerSchema,
  serverToClientSchema,
  silentLogger,
  transportFrameSchema,
  type ClientToServerMessage,
  type Logger,
  type PeerAddress,
  type ServerToClientMessage,
  type SignalPayload,
  type TransportFrame,
} from '@p2pchat/shared';
import { EventChannel, peerKey, type SignalTransport } from './types.js';

export type SignalingState = 'closed' | 'connecting' | 'authenticating' | 'ready';

type WebSocketLike = {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: ((event: unknown) => void) | null;
  onerror: ((event: unknown) => void) | null;
};

export type WebSocketConstructor = new (url: string) => WebSocketLike;

export interface SignalingClientOptions {
  readonly url: string;
  readonly getToken: () => string | null;
  readonly logger?: Logger;
  readonly webSocketConstructor?: WebSocketConstructor;
  /** Backoff schedule for reconnection, in milliseconds. */
  readonly backoffMs?: number[];
  readonly now?: () => number;
}

const DEFAULT_BACKOFF = [500, 1000, 2000, 5000, 10_000, 30_000];

export interface RelayDelivery {
  readonly envelopeId: string;
  readonly from: PeerAddress;
  readonly frame: TransportFrame;
  readonly receivedAt: number;
}

export class SignalingClient {
  readonly onState = new EventChannel<SignalingState>();
  readonly onRelayFrame = new EventChannel<RelayDelivery>();
  readonly onPresence = new EventChannel<{
    userId: string;
    devices: { deviceId: string; online: boolean }[];
  }>();

  private socket: WebSocketLike | null = null;
  private state: SignalingState = 'closed';
  private attempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = true;
  private readonly logger: Logger;
  private readonly backoff: number[];
  private readonly WebSocketImpl: WebSocketConstructor;
  private readonly signalHandlers = new Map<string, Set<(payload: SignalPayload) => void>>();
  /** Frames queued while the socket is down, flushed on reconnect. */
  private readonly outboundQueue: ClientToServerMessage[] = [];

  constructor(private readonly options: SignalingClientOptions) {
    this.logger = (options.logger ?? silentLogger).child('signaling');
    this.backoff = options.backoffMs ?? DEFAULT_BACKOFF;
    const impl =
      options.webSocketConstructor ??
      (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket;
    if (!impl) throw new Error('no WebSocket implementation available');
    this.WebSocketImpl = impl;
  }

  get currentState(): SignalingState {
    return this.state;
  }

  private setState(state: SignalingState): void {
    if (this.state === state) return;
    this.state = state;
    this.onState.emit(state);
  }

  start(): void {
    this.stopped = false;
    this.openSocket();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      try {
        this.socket.close(1000, 'client shutdown');
      } catch {
        /* ignore */
      }
      this.socket = null;
    }
    this.setState('closed');
  }

  private openSocket(): void {
    if (this.stopped || this.socket) return;
    const token = this.options.getToken();
    if (!token) {
      this.logger.warn('cannot connect without a session token');
      this.scheduleReconnect();
      return;
    }

    this.setState('connecting');
    let socket: WebSocketLike;
    try {
      socket = new this.WebSocketImpl(this.options.url);
    } catch (error) {
      this.logger.warn('failed to construct socket', {
        reason: error instanceof Error ? error.name : 'unknown',
      });
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      this.setState('authenticating');
      this.sendNow({ type: 'auth', token });
    };
    socket.onmessage = (event) => this.handleMessage(event.data);
    socket.onerror = () => {
      this.logger.warn('signaling socket error');
    };
    socket.onclose = () => {
      const wasReady = this.state === 'ready';
      this.socket = null;
      this.setState('closed');
      if (wasReady) this.logger.info('signaling socket closed');
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    const delay = this.backoff[Math.min(this.attempt, this.backoff.length - 1)]!;
    this.attempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.openSocket();
    }, delay);
  }

  private handleMessage(raw: unknown): void {
    if (typeof raw !== 'string') return;
    let parsed: ServerToClientMessage;
    try {
      parsed = serverToClientSchema.parse(JSON.parse(raw));
    } catch {
      // A message we cannot validate is dropped. It is never "best-effort"
      // interpreted: malformed input from the network is exactly where parsing
      // bugs turn into security bugs.
      this.logger.warn('discarded unparseable server message');
      return;
    }

    switch (parsed.type) {
      case 'auth.ok':
        this.attempt = 0;
        this.setState('ready');
        this.flushQueue();
        this.sendNow({ type: 'relay.pull' });
        break;
      case 'error':
        this.logger.warn('server reported an error', { code: parsed.code });
        break;
      case 'signal': {
        const handlers = this.signalHandlers.get(
          signalKey(parsed.from, parsed.payload.sessionId),
        );
        if (handlers) for (const handler of [...handlers]) handler(parsed.payload);
        break;
      }
      case 'relay.deliver': {
        const frame = this.decodeFrame(parsed.frame);
        if (!frame) {
          // Acknowledge undecodable envelopes so they cannot wedge the queue.
          this.send({ type: 'relay.ack', envelopeIds: [parsed.envelopeId] });
          return;
        }
        this.onRelayFrame.emit({
          envelopeId: parsed.envelopeId,
          from: parsed.from,
          frame,
          receivedAt: parsed.receivedAt,
        });
        break;
      }
      case 'presence':
        this.onPresence.emit({ userId: parsed.userId, devices: parsed.devices });
        break;
      case 'relay.queue-empty':
      case 'pong':
        break;
    }
  }

  private decodeFrame(encoded: string): TransportFrame | null {
    try {
      const json = new TextDecoder().decode(base64ToBytes(encoded));
      return transportFrameSchema.parse(JSON.parse(json));
    } catch {
      this.logger.warn('discarded malformed relay frame');
      return null;
    }
  }

  private flushQueue(): void {
    const queued = this.outboundQueue.splice(0);
    for (const message of queued) this.sendNow(message);
  }

  private sendNow(message: ClientToServerMessage): void {
    const socket = this.socket;
    if (!socket) return;
    try {
      socket.send(JSON.stringify(clientToServerSchema.parse(message)));
    } catch (error) {
      this.logger.warn('failed to send on signaling socket', {
        reason: error instanceof Error ? error.name : 'unknown',
      });
    }
  }

  /** Queue if the socket is not ready, so callers need not care about state. */
  private send(message: ClientToServerMessage): void {
    if (this.state === 'ready') this.sendNow(message);
    else this.outboundQueue.push(message);
  }

  // -- SignalTransport ------------------------------------------------------

  sendSignal(peer: PeerAddress, payload: SignalPayload): void {
    this.send({ type: 'signal', to: peer, payload });
  }

  subscribe(
    peer: PeerAddress,
    sessionId: string,
    handler: (payload: SignalPayload) => void,
  ): () => void {
    const key = signalKey(peer, sessionId);
    let handlers = this.signalHandlers.get(key);
    if (!handlers) {
      handlers = new Set();
      this.signalHandlers.set(key, handlers);
    }
    handlers.add(handler);
    return () => {
      handlers!.delete(handler);
      if (handlers!.size === 0) this.signalHandlers.delete(key);
    };
  }

  // -- relay ----------------------------------------------------------------

  /** Hand an encrypted frame to the server for store-and-forward delivery. */
  relay(peer: PeerAddress, frame: TransportFrame): void {
    this.send({
      type: 'relay.send',
      to: peer,
      frame: bytesToBase64(new TextEncoder().encode(JSON.stringify(frame))),
    });
  }

  acknowledgeRelay(envelopeIds: string[]): void {
    if (envelopeIds.length === 0) return;
    this.send({ type: 'relay.ack', envelopeIds });
  }

  subscribePresence(userIds: string[]): void {
    if (userIds.length === 0) return;
    this.send({ type: 'presence.subscribe', userIds });
  }
}

/** Adapter exposing a {@link SignalTransport} with the expected method name. */
export function asSignalTransport(client: SignalingClient): SignalTransport {
  return {
    send: (peer, payload) => client.sendSignal(peer, payload),
    subscribe: (peer, sessionId, handler) => client.subscribe(peer, sessionId, handler),
  };
}

function signalKey(peer: PeerAddress, sessionId: string): string {
  return `${peerKey(peer)}|${sessionId}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(bytes).toString('base64');
}

function base64ToBytes(encoded: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(encoded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}
