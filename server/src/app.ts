/**
 * HTTP + WebSocket application.
 *
 * Route inventory, and what each one is allowed to see:
 *
 *   POST /api/v1/account/register     username, client proof, device pubkey
 *   GET  /api/v1/account/kdf-params   username -> public KDF parameters
 *   POST /api/v1/device/register      as above, for an additional device
 *   POST /api/v1/auth/challenge       -> random nonce
 *   POST /api/v1/auth/verify          Ed25519 signature -> session token
 *   POST /api/v1/keypackages          public MLS key packages
 *   GET  /api/v1/keypackages/count
 *   POST /api/v1/keypackages/claim    consumes one package per peer device
 *   GET  /api/v1/directory/:username  public device list
 *   GET  /api/v1/devices              own device list
 *   DEL  /api/v1/devices/:id          revoke a device
 *   GET  /api/v1/ice                  STUN/TURN configuration
 *   POST /api/v1/blobs                opaque encrypted attachment
 *   GET  /api/v1/blobs/:id            opaque encrypted attachment
 *   WS   /ws                          signaling, presence, ciphertext relay
 *
 * No route accepts or returns plaintext message content, and none accepts a
 * private key. Request logging records method, route and status only — never
 * bodies, never query strings.
 */
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import { ZodError } from 'zod';
import {
  MAX_ATTACHMENT_BYTES,
  TARGET_KEY_PACKAGE_COUNT,
  authChallengeRequestSchema,
  authVerifyRequestSchema,
  claimKeyPackagesRequestSchema,
  createLogger,
  fromBase64,
  publishKeyPackagesRequestSchema,
  registerAccountRequestSchema,
  registerDeviceRequestSchema,
  usernameSchema,
  type Logger,
} from '@p2pchat/shared';
import { loadConfig, type ServerConfig } from './config.js';
import { openDatabase, pruneExpired, type Db } from './db.js';
import { Registry, RegistryError, type AuthenticatedDevice } from './identity/registry.js';
import { RelayQueue } from './relay/queue.js';
import { BlobStore, QuotaExceededError } from './relay/blobs.js';
import { SignalingHub, type HubSocket } from './signaling/hub.js';
import { RateLimiter } from './rateLimit.js';

export interface BuiltServer {
  readonly app: FastifyInstance;
  readonly db: Db;
  readonly registry: Registry;
  readonly relayQueue: RelayQueue;
  readonly blobs: BlobStore;
  readonly hub: SignalingHub;
  readonly config: ServerConfig;
}

declare module 'fastify' {
  interface FastifyRequest {
    device?: AuthenticatedDevice;
  }
}

export async function buildServer(
  overrides: Partial<ServerConfig> = {},
  loggerOverride?: Logger,
): Promise<BuiltServer> {
  const config: ServerConfig = { ...loadConfig(), ...overrides };
  const logger =
    loggerOverride ?? createLogger('server', { level: config.logLevel });

  const db = openDatabase(config.databasePath);
  pruneExpired(db, Date.now());

  const registry = new Registry(db);
  const relayQueue = new RelayQueue(db);
  const blobs = new BlobStore(db, config.blobQuotaBytes);
  const hub = new SignalingHub(registry, relayQueue, logger.child('hub'));

  // Fastify's own logger is disabled; we log through the redacting logger so
  // no request body or query string can ever reach an access log.
  const app = Fastify({
    logger: false,
    trustProxy: config.trustProxy,
    bodyLimit: MAX_ATTACHMENT_BYTES + 1024,
  });

  await app.register(cors, {
    origin: config.corsOrigins,
    credentials: false,
  });
  await app.register(websocket, { options: { maxPayload: 8 * 1024 * 1024 } });

  app.addContentTypeParser(
    'application/octet-stream',
    { parseAs: 'buffer' },
    (_request, body, done) => done(null, body),
  );

  const authLimiter = new RateLimiter({ capacity: 10, refillPerSecond: 0.2 });
  const generalLimiter = new RateLimiter({ capacity: 120, refillPerSecond: 2 });

  app.addHook('onRequest', async (request, reply) => {
    const limiter = request.url.startsWith('/api/v1/auth') ||
      request.url.startsWith('/api/v1/account') ||
      request.url.startsWith('/api/v1/device/register')
        ? authLimiter
        : generalLimiter;
    if (!limiter.take(clientIp(request))) {
      return reply.code(429).send({ error: { code: 'rate_limited', message: 'slow down' } });
    }
    return undefined;
  });

  app.addHook('onResponse', async (request, reply) => {
    logger.debug('request', {
      method: request.method,
      // routeOptions.url is the route pattern, so path parameters (which can
      // contain usernames and blob ids) never reach the log.
      route: request.routeOptions?.url ?? 'unmatched',
      status: reply.statusCode,
    });
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof RegistryError) {
      return reply.code(error.status).send({ error: { code: error.code, message: error.message } });
    }
    if (error instanceof QuotaExceededError) {
      return reply
        .code(413)
        .send({ error: { code: 'quota_exceeded', message: 'upload allowance exhausted' } });
    }
    if ((error as { statusCode?: number }).statusCode === 413) {
      return reply.code(413).send({ error: { code: 'too_large', message: 'payload too large' } });
    }
    if (error instanceof ZodError) {
      // Report only that validation failed. Echoing back which field was
      // rejected, or its value, would put request content into the response
      // (and from there into a client log).
      return reply
        .code(400)
        .send({ error: { code: 'bad_request', message: 'request failed validation' } });
    }
    logger.error('unhandled request error', {
      route: request.routeOptions?.url ?? 'unmatched',
      name: error instanceof Error ? error.name : 'Error',
    });
    return reply.code(500).send({ error: { code: 'internal', message: 'internal error' } });
  });

  /** Bearer-token guard for authenticated routes. */
  const requireDevice = async (request: FastifyRequest, reply: import('fastify').FastifyReply) => {
    const header = request.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;
    const device = registry.authenticate(token);
    if (!device) {
      return reply
        .code(401)
        .send({ error: { code: 'unauthenticated', message: 'authentication required' } });
    }
    request.device = device;
    return undefined;
  };

  // -- account & device registration ---------------------------------------

  app.get('/api/v1/account/kdf-params', async (request, reply) => {
    const parsed = usernameSchema.safeParse(
      (request.query as { username?: string } | undefined)?.username,
    );
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ error: { code: 'bad_request', message: 'invalid username' } });
    }
    return { kdfParams: registry.passwordKdfParams(parsed.data) };
  });

  app.post('/api/v1/account/register', async (request, reply) => {
    const body = registerAccountRequestSchema.parse(request.body);
    const result = registry.registerAccount({
      username: body.username,
      clientProof: fromBase64(body.clientProof),
      kdfParams: body.kdfParams,
      deviceAuthPublicKey: fromBase64(body.deviceAuthPublicKey),
      deviceLabel: body.deviceLabel,
    });
    logger.info('account registered', { userId: result.userId, deviceId: result.deviceId });
    return reply.code(201).send(result);
  });

  app.post('/api/v1/device/register', async (request, reply) => {
    const body = registerDeviceRequestSchema.parse(request.body);
    const result = registry.registerDevice({
      username: body.username,
      clientProof: fromBase64(body.clientProof),
      deviceAuthPublicKey: fromBase64(body.deviceAuthPublicKey),
      deviceLabel: body.deviceLabel,
    });
    logger.info('device registered', { userId: result.userId, deviceId: result.deviceId });
    return reply.code(201).send(result);
  });

  // -- device authentication ------------------------------------------------

  app.post('/api/v1/auth/challenge', async (request) => {
    const body = authChallengeRequestSchema.parse(request.body);
    const challenge = registry.createChallenge(body.userId, body.deviceId);
    return {
      challengeId: challenge.challengeId,
      nonce: challenge.nonce.toString('base64'),
      expiresAt: challenge.expiresAt,
    };
  });

  app.post('/api/v1/auth/verify', async (request) => {
    const body = authVerifyRequestSchema.parse(request.body);
    return registry.verifyChallenge(body.challengeId, fromBase64(body.signature));
  });

  // -- key package directory ------------------------------------------------

  app.post('/api/v1/keypackages', { preHandler: requireDevice }, async (request, reply) => {
    const body = publishKeyPackagesRequestSchema.parse(request.body);
    registry.publishKeyPackages(
      request.device!,
      body.keyPackages.map((encoded) => fromBase64(encoded)),
    );
    return reply.code(204).send();
  });

  app.get('/api/v1/keypackages/count', { preHandler: requireDevice }, async (request) => {
    return { count: registry.countKeyPackages(request.device!) };
  });

  app.post('/api/v1/keypackages/claim', { preHandler: requireDevice }, async (request) => {
    const body = claimKeyPackagesRequestSchema.parse(request.body);
    const claimed = registry.claimKeyPackages(body.userId);
    return {
      userId: body.userId,
      keyPackages: claimed.map((entry) => ({
        deviceId: entry.deviceId,
        keyPackage: entry.keyPackage.toString('base64'),
      })),
    };
  });

  // -- directory & devices --------------------------------------------------

  app.get('/api/v1/directory/:username', { preHandler: requireDevice }, async (request, reply) => {
    const parsed = usernameSchema.safeParse((request.params as { username: string }).username);
    if (!parsed.success) {
      return reply.code(400).send({ error: { code: 'bad_request', message: 'invalid username' } });
    }
    return registry.lookupByUsername(parsed.data);
  });

  app.get('/api/v1/devices', { preHandler: requireDevice }, async (request) => {
    return { devices: registry.listDevices(request.device!.userId) };
  });

  app.delete('/api/v1/devices/:deviceId', { preHandler: requireDevice }, async (request, reply) => {
    const { deviceId } = request.params as { deviceId: string };
    registry.removeDevice(request.device!.userId, deviceId);
    logger.info('device revoked', { userId: request.device!.userId, deviceId });
    return reply.code(204).send();
  });

  // -- ICE ------------------------------------------------------------------

  app.get('/api/v1/ice', { preHandler: requireDevice }, async () => {
    return { iceServers: config.iceServers, expiresAt: null };
  });

  // -- encrypted blobs ------------------------------------------------------

  app.post('/api/v1/blobs', { preHandler: requireDevice }, async (request, reply) => {
    const body = request.body;
    if (!Buffer.isBuffer(body) || body.length === 0) {
      return reply
        .code(400)
        .send({ error: { code: 'bad_request', message: 'expected a binary body' } });
    }
    if (body.length > config.maxBlobBytes) {
      return reply.code(413).send({ error: { code: 'too_large', message: 'attachment too large' } });
    }
    const stored = blobs.put(request.device!.userId, body);
    logger.info('encrypted blob stored', { bytes: body.length });
    return reply.code(201).send(stored);
  });

  app.get('/api/v1/blobs/:blobId', { preHandler: requireDevice }, async (request, reply) => {
    const { blobId } = request.params as { blobId: string };
    const data = blobs.get(blobId);
    if (!data) {
      return reply.code(404).send({ error: { code: 'not_found', message: 'no such blob' } });
    }
    return reply.header('content-type', 'application/octet-stream').send(data);
  });

  app.get('/api/v1/health', async () => ({ status: 'ok' }));

  // -- WebSocket ------------------------------------------------------------

  app.get('/ws', { websocket: true }, (connection) => {
    const socket = connection as unknown as {
      send(data: string): void;
      close(code?: number, reason?: string): void;
      on(event: string, handler: (...args: unknown[]) => void): void;
    };
    const hubSocket: HubSocket = {
      send: (data) => socket.send(data),
      close: (code, reason) => socket.close(code, reason),
    };
    hub.open(hubSocket);
    socket.on('message', (raw: unknown) => {
      hub.handleMessage(hubSocket, String(raw));
    });
    socket.on('close', () => hub.close(hubSocket));
    socket.on('error', () => hub.close(hubSocket));
  });

  // Periodic cleanup of expired tokens, challenges, envelopes and blobs.
  const pruneTimer = setInterval(() => pruneExpired(db, Date.now()), 60_000);
  pruneTimer.unref?.();
  app.addHook('onClose', async () => {
    clearInterval(pruneTimer);
    db.close();
  });

  return { app, db, registry, relayQueue, blobs, hub, config };
}

export { TARGET_KEY_PACKAGE_COUNT };

function clientIp(request: FastifyRequest): string {
  return request.ip || 'unknown';
}
