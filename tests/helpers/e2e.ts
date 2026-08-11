/**
 * End-to-end harness: a real server process plus real client sessions.
 *
 * Nothing is stubbed on the security path. The server is the actual Fastify
 * app with the actual SQLite schema; the clients run the actual MLS engine,
 * vault, trust store and messaging service, talking over a real WebSocket.
 * Only the WebRTC layer is simulated, because Node has no WebRTC and because
 * the tests need to force direct connectivity to fail.
 *
 * `capturedServerBytes` records everything the server holds or forwards, which
 * is what the "a compromised relay learns nothing" tests assert against.
 */
import type { AddressInfo } from 'node:net';
import { createLogger, silentLogger, type LogRecord, type Logger } from '@p2pchat/shared';
import { buildServer, type BuiltServer } from '../../server/src/app.js';
import { AppSession, memoryDeviceRecordStore, type ReadySession } from '../../client/src/app/session.js';
import { MemoryKeyValueStore } from '../../client/src/storage/kv.js';
import { TEST_ARGON2_PARAMS } from '../../client/src/storage/vault.js';
import { FakeDirectNetwork } from './fakeTransport.js';

export interface Harness {
  readonly server: BuiltServer;
  readonly baseUrl: string;
  readonly wsUrl: string;
  readonly network: FakeDirectNetwork;
  /** Every structured log record the server emitted. */
  readonly serverLogs: LogRecord[];
  readonly serverLogger: Logger;
  /**
   * Every frame that passed through the relay, retained even after the
   * recipient acknowledged it — i.e. what an operator who logs everything
   * would accumulate.
   */
  readonly relayedFrames: Buffer[];
  createClient(username: string, options?: { logs?: LogRecord[] }): Promise<TestUser>;
  stop(): Promise<void>;
}

export interface TestUser {
  readonly username: string;
  readonly session: AppSession;
  readonly ready: ReadySession;
  readonly logs: LogRecord[];
}

export async function startHarness(): Promise<Harness> {
  const serverLogs: LogRecord[] = [];
  const serverLogger = createLogger('server', {
    level: 'debug',
    sink: (record) => serverLogs.push(record),
  });

  const server = await buildServer(
    {
      databasePath: ':memory:',
      host: '127.0.0.1',
      port: 0,
      corsOrigins: ['*'],
      iceServers: [],
    },
    serverLogger,
  );

  await server.app.listen({ host: '127.0.0.1', port: 0 });
  const address = server.app.server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const wsUrl = `ws://127.0.0.1:${address.port}/ws`;

  const network = new FakeDirectNetwork();
  const clients: AppSession[] = [];

  // Simulate an operator that archives every relayed frame. The queue itself
  // deletes envelopes on acknowledgement, so without this tap the strongest
  // adversary would be under-modelled.
  const relayedFrames: Buffer[] = [];
  const originalEnqueue = server.relayQueue.enqueue.bind(server.relayQueue);
  server.relayQueue.enqueue = (params) => {
    relayedFrames.push(Buffer.from(params.frame));
    return originalEnqueue(params);
  };

  return {
    server,
    baseUrl,
    wsUrl,
    network,
    serverLogs,
    serverLogger,
    relayedFrames,

    async createClient(username, options = {}): Promise<TestUser> {
      const logs = options.logs ?? [];
      const logger = createLogger(`client:${username}`, {
        level: 'debug',
        sink: (record) => logs.push(record),
      });

      const session = await AppSession.bootstrap({
        apiBaseUrl: baseUrl,
        wsUrl,
        logger,
        // The factory needs this client's own address for rendezvous, but the
        // address only exists after registration; resolve it lazily.
        channelFactory: {
          connect: (connectOptions) => {
            const self = session.session?.self;
            if (!self) return Promise.reject(new Error('client is not ready'));
            return network.factoryFor(self).connect(connectOptions);
          },
        },
        keyValueStoreFactory: () => new MemoryKeyValueStore(),
        argon2Params: TEST_ARGON2_PARAMS,
        ephemeralMlsStorage: true,
        deviceRecordStore: memoryDeviceRecordStore(),
      });

      const ready = await session.register({
        username,
        passphrase: `correct-horse-battery-${username}`,
        deviceLabel: `${username}-laptop`,
      });

      clients.push(session);
      await waitFor(() => ready.signaling.currentState === 'ready', 10_000);
      return { username, session, ready, logs };
    },

    async stop(): Promise<void> {
      for (const client of clients) await client.lock().catch(() => undefined);
      await server.app.close();
    },
  };
}

/** Poll until `predicate` holds, or throw. Avoids arbitrary sleeps in tests. */
export async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 10_000,
  description = 'condition',
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${description}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** Everything the server can see: stored rows plus relayed frames. */
export function dumpServerState(server: BuiltServer): {
  accounts: unknown[];
  devices: unknown[];
  keyPackages: Buffer[];
  envelopes: Buffer[];
  blobs: Buffer[];
} {
  const db = server.db;
  return {
    accounts: db.prepare('SELECT * FROM accounts').all(),
    devices: db.prepare('SELECT * FROM devices').all(),
    keyPackages: (db.prepare('SELECT data FROM key_packages').all() as { data: Buffer }[]).map(
      (row) => row.data,
    ),
    envelopes: (db.prepare('SELECT frame FROM relay_envelopes').all() as { frame: Buffer }[]).map(
      (row) => row.frame,
    ),
    blobs: (db.prepare('SELECT data FROM blobs').all() as { data: Buffer }[]).map((row) => row.data),
  };
}

export { silentLogger };
