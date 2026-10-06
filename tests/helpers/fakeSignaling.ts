/**
 * In-memory stand-in for the signaling server.
 *
 * Connects real {@link SignalingClient}s through a fake WebSocket, so transport
 * tests exercise the routing that ships: per-session handlers, replay of
 * signals that arrive before their session is joined, and offer notifications.
 * Like the real hub it forwards signaling verbatim, stamps `from` with the
 * sender's authenticated address, and reports `peer_offline` for a recipient
 * that is not connected.
 */
import { silentLogger, type PeerAddress } from '@p2pchat/shared';
import { SignalingClient, type WebSocketConstructor } from '../../client/src/p2p/signalingClient.js';
import { peerKey } from '../../client/src/p2p/types.js';

const OPEN = 1;
const CLOSED = 3;

class FakeSocket {
  readyState = 0;
  onopen: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;

  constructor(
    private readonly hub: FakeSignalingHub,
    readonly self: PeerAddress,
  ) {
    setTimeout(() => {
      if (this.readyState === CLOSED) return;
      this.readyState = OPEN;
      this.onopen?.({});
    }, 0);
  }

  send(data: string): void {
    if (this.readyState !== OPEN) throw new Error('socket is not open');
    this.hub.handle(this, JSON.parse(data) as { type: string } & Record<string, unknown>);
  }

  close(): void {
    if (this.readyState === CLOSED) return;
    this.readyState = CLOSED;
    this.hub.disconnect(this);
    setTimeout(() => this.onclose?.({}), 0);
  }

  /** Deliver a server message asynchronously, as a network would. */
  receive(message: unknown): void {
    setTimeout(() => {
      if (this.readyState === OPEN) this.onmessage?.({ data: JSON.stringify(message) });
    }, 0);
  }
}

export class FakeSignalingHub {
  private readonly sockets = new Map<string, FakeSocket>();
  private readonly clients: SignalingClient[] = [];

  /** A started client that authenticates as `self`. */
  client(self: PeerAddress, options: { now?: () => number } = {}): SignalingClient {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- in the class, `this` is the socket
    const hub = this;
    const Socket = class extends FakeSocket {
      constructor() {
        super(hub, self);
      }
    };
    const client = new SignalingClient({
      url: 'ws://hub.test/ws',
      getToken: async () => 'test-token',
      webSocketConstructor: Socket as unknown as WebSocketConstructor,
      logger: silentLogger,
      ...(options.now ? { now: options.now } : {}),
    });
    client.start();
    this.clients.push(client);
    return client;
  }

  handle(socket: FakeSocket, message: { type: string } & Record<string, unknown>): void {
    switch (message.type) {
      case 'auth':
        this.sockets.set(peerKey(socket.self), socket);
        socket.receive({ type: 'auth.ok', userId: socket.self.userId, deviceId: socket.self.deviceId });
        break;
      case 'signal': {
        const target = this.sockets.get(peerKey(message.to as PeerAddress));
        if (!target) {
          socket.receive({ type: 'error', code: 'peer_offline', message: 'peer device is not connected' });
          return;
        }
        target.receive({ type: 'signal', from: socket.self, payload: message.payload });
        break;
      }
      case 'relay.pull':
        socket.receive({ type: 'relay.queue-empty' });
        break;
      default:
        break;
    }
  }

  disconnect(socket: FakeSocket): void {
    const key = peerKey(socket.self);
    if (this.sockets.get(key) === socket) this.sockets.delete(key);
  }

  stopAll(): void {
    for (const client of this.clients.splice(0)) client.stop();
  }
}
