/**
 * WebSocket hub: authentication, WebRTC signaling, presence, relay delivery.
 *
 * The hub routes; it does not interpret. SDP and ICE candidates pass through
 * verbatim (the server can read them — see THREAT_MODEL.md), and relay frames
 * pass through as opaque bytes.
 *
 * Every inbound message is schema-validated before use, and every outbound
 * route is checked against the authenticated identity of the sender, so a
 * client cannot spoof its `from` address or read another device's queue.
 */
import {
  clientToServerSchema,
  serverToClientSchema,
  type ClientToServerMessage,
  type Logger,
  type PeerAddress,
  type ServerToClientMessage,
} from '@p2pchat/shared';
import type { Registry } from '../identity/registry.js';
import type { RelayQueue } from '../relay/queue.js';

export interface HubSocket {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

interface Connection {
  readonly socket: HubSocket;
  device: PeerAddress | null;
  /** Accounts this connection asked to receive presence for. */
  presenceInterest: Set<string>;
  /** Guards against unauthenticated flooding before `auth` arrives. */
  preAuthMessages: number;
  /** Token bucket limiting how fast this socket may send. */
  budget: number;
  budgetUpdatedAt: number;
}

const MAX_PREAUTH_MESSAGES = 4;
const RELAY_BATCH = 50;

/**
 * Per-socket message allowance.
 *
 * Without this, one authenticated client can flood the hub with signaling or
 * relay traffic aimed at another device. The burst is generous enough for a
 * normal client resuming a large queue, and the refill rate is well above
 * interactive use.
 */
const SOCKET_BURST = 120;
const SOCKET_REFILL_PER_SECOND = 20;

export class SignalingHub {
  private readonly connections = new Map<HubSocket, Connection>();
  /** deviceKey -> connections (a device may briefly have two during reconnect). */
  private readonly byDevice = new Map<string, Set<Connection>>();

  constructor(
    private readonly registry: Registry,
    private readonly relayQueue: RelayQueue,
    private readonly logger: Logger,
    private readonly now: () => number = Date.now,
  ) {}

  open(socket: HubSocket): void {
    this.connections.set(socket, {
      socket,
      device: null,
      presenceInterest: new Set(),
      preAuthMessages: 0,
      budget: SOCKET_BURST,
      budgetUpdatedAt: this.now(),
    });
  }

  /** Consume one unit of the socket's allowance. */
  private withinBudget(connection: Connection): boolean {
    const now = this.now();
    const elapsedSeconds = (now - connection.budgetUpdatedAt) / 1000;
    connection.budget = Math.min(
      SOCKET_BURST,
      connection.budget + elapsedSeconds * SOCKET_REFILL_PER_SECOND,
    );
    connection.budgetUpdatedAt = now;
    if (connection.budget < 1) return false;
    connection.budget -= 1;
    return true;
  }

  close(socket: HubSocket): void {
    const connection = this.connections.get(socket);
    if (!connection) return;
    this.connections.delete(socket);
    if (connection.device) {
      const key = deviceKey(connection.device);
      const set = this.byDevice.get(key);
      set?.delete(connection);
      if (set && set.size === 0) {
        this.byDevice.delete(key);
        this.broadcastPresence(connection.device, false);
      }
    }
  }

  handleMessage(socket: HubSocket, raw: string): void {
    const connection = this.connections.get(socket);
    if (!connection) return;

    if (!this.withinBudget(connection)) {
      this.sendTo(connection, {
        type: 'error',
        code: 'rate_limited',
        message: 'too many messages',
      });
      return;
    }

    let message: ClientToServerMessage;
    try {
      message = clientToServerSchema.parse(JSON.parse(raw));
    } catch {
      this.sendTo(connection, { type: 'error', code: 'bad_request', message: 'malformed message' });
      return;
    }

    if (!connection.device) {
      if (message.type !== 'auth') {
        connection.preAuthMessages += 1;
        if (connection.preAuthMessages > MAX_PREAUTH_MESSAGES) {
          socket.close(1008, 'authentication required');
          return;
        }
        this.sendTo(connection, {
          type: 'error',
          code: 'unauthenticated',
          message: 'authenticate first',
        });
        return;
      }
      this.handleAuth(connection, message.token);
      return;
    }

    switch (message.type) {
      case 'auth':
        // Already authenticated; re-auth is not supported on a live socket.
        this.sendTo(connection, {
          type: 'error',
          code: 'already_authenticated',
          message: 'already authenticated',
        });
        return;
      case 'ping':
        this.sendTo(connection, { type: 'pong', t: message.t });
        return;
      case 'presence.subscribe':
        connection.presenceInterest = new Set(message.userIds);
        for (const userId of message.userIds) this.sendPresenceSnapshot(connection, userId);
        return;
      case 'signal':
        this.routeSignal(connection, message);
        return;
      case 'relay.send':
        this.handleRelaySend(connection, message);
        return;
      case 'relay.ack':
        this.relayQueue.acknowledge(connection.device, message.envelopeIds);
        this.pumpRelay(connection);
        return;
      case 'relay.pull':
        this.pumpRelay(connection);
        return;
    }
  }

  private handleAuth(connection: Connection, token: string): void {
    const device = this.registry.authenticate(token);
    if (!device) {
      this.sendTo(connection, {
        type: 'error',
        code: 'unauthenticated',
        message: 'invalid or expired token',
      });
      connection.socket.close(1008, 'authentication failed');
      return;
    }

    connection.device = device;
    const key = deviceKey(device);
    let set = this.byDevice.get(key);
    const wasOffline = !set || set.size === 0;
    if (!set) {
      set = new Set();
      this.byDevice.set(key, set);
    }
    set.add(connection);

    this.sendTo(connection, {
      type: 'auth.ok',
      userId: device.userId,
      deviceId: device.deviceId,
    });
    if (wasOffline) this.broadcastPresence(device, true);
    this.logger.info('device connected', {
      userId: device.userId,
      deviceId: device.deviceId,
      queueDepth: this.relayQueue.depth(device),
    });

    // A device that has just come online is exactly the case the store-and-
    // forward queue exists for; deliver without waiting for an explicit pull.
    this.pumpRelay(connection);
  }

  /**
   * Forward signaling to the addressed device.
   *
   * `from` is taken from the authenticated connection, never from the payload,
   * so a client cannot impersonate another device during negotiation.
   */
  private routeSignal(
    connection: Connection,
    message: Extract<ClientToServerMessage, { type: 'signal' }>,
  ): void {
    const targets = this.byDevice.get(deviceKey(message.to));
    if (!targets || targets.size === 0) {
      this.sendTo(connection, {
        type: 'error',
        code: 'peer_offline',
        message: 'peer device is not connected',
      });
      return;
    }
    for (const target of targets) {
      this.sendTo(target, {
        type: 'signal',
        from: connection.device!,
        payload: message.payload,
      });
    }
  }

  private handleRelaySend(
    connection: Connection,
    message: Extract<ClientToServerMessage, { type: 'relay.send' }>,
  ): void {
    // Refuse to queue for a device that does not exist. Without this a client
    // could invent unlimited recipient addresses and grow the queue without
    // bound, since the depth limit is per recipient device.
    if (!this.registry.deviceExists(message.to.userId, message.to.deviceId)) {
      this.sendTo(connection, {
        type: 'error',
        code: 'unknown_device',
        message: 'no such recipient device',
      });
      return;
    }

    const frame = Buffer.from(message.frame, 'base64');
    const id = this.relayQueue.enqueue({
      to: message.to,
      from: connection.device!,
      frame,
    });
    if (!id) {
      this.sendTo(connection, {
        type: 'error',
        code: 'relay_queue_full',
        message: 'recipient queue is full',
      });
      return;
    }
    // Deliver immediately if the recipient is online.
    const targets = this.byDevice.get(deviceKey(message.to));
    if (targets) for (const target of targets) this.pumpRelay(target);
  }

  /** Push queued envelopes to a connected device. */
  private pumpRelay(connection: Connection): void {
    if (!connection.device) return;
    const pending = this.relayQueue.pending(connection.device, RELAY_BATCH);
    for (const envelope of pending) {
      this.sendTo(connection, {
        type: 'relay.deliver',
        envelopeId: envelope.id,
        from: envelope.from,
        frame: envelope.frame.toString('base64'),
        receivedAt: envelope.receivedAt,
      });
    }
    if (pending.length === 0) this.sendTo(connection, { type: 'relay.queue-empty' });
  }

  private sendPresenceSnapshot(connection: Connection, userId: string): void {
    const devices = this.registry.listDevices(userId).map((device) => ({
      deviceId: device.deviceId,
      online: (this.byDevice.get(`${userId}:${device.deviceId}`)?.size ?? 0) > 0,
    }));
    this.sendTo(connection, { type: 'presence', userId, devices });
  }

  private broadcastPresence(device: PeerAddress, online: boolean): void {
    for (const connection of this.connections.values()) {
      if (!connection.device) continue;
      if (!connection.presenceInterest.has(device.userId)) continue;
      this.sendTo(connection, {
        type: 'presence',
        userId: device.userId,
        devices: [{ deviceId: device.deviceId, online }],
      });
    }
  }

  private sendTo(connection: Connection, message: ServerToClientMessage): void {
    try {
      connection.socket.send(JSON.stringify(serverToClientSchema.parse(message)));
    } catch (error) {
      this.logger.warn('failed to write to socket', {
        reason: error instanceof Error ? error.name : 'unknown',
      });
    }
  }

  /** Test/introspection helper: which devices are currently connected. */
  onlineDeviceCount(): number {
    return this.byDevice.size;
  }
}

function deviceKey(address: PeerAddress): string {
  return `${address.userId}:${address.deviceId}`;
}
