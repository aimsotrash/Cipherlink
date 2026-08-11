/**
 * Client <-> server wire protocol.
 *
 * Everything in this file is visible to the server. Nothing here carries
 * plaintext message content, private keys, or session secrets: message bodies
 * only ever appear as opaque base64 ciphertext in `TransportFrame.payload`
 * (see frames.ts), which the server routes without being able to interpret.
 */
import { z } from 'zod';

/** Base64 (standard or URL-safe) with a bounded decoded size. */
const base64 = (maxEncodedLength: number) =>
  z
    .string()
    .max(maxEncodedLength)
    .regex(/^[A-Za-z0-9+/\-_]*={0,2}$/, 'expected base64');

export const uuidSchema = z.string().uuid();
export const deviceIdSchema = z
  .string()
  .regex(/^[0-9a-f]{1,16}$/, 'device id must be lowercase hex');
export const usernameSchema = z
  .string()
  .min(3)
  .max(32)
  .regex(/^[a-z0-9_.-]+$/, 'usernames are lowercase alphanumeric with . _ -');

// ---------------------------------------------------------------------------
// Account & device registration
// ---------------------------------------------------------------------------

/**
 * Argon2id parameters the client must use to stretch the account password
 * before it is transmitted. The server never sees the password itself, only
 * the stretched `clientProof`, which it hashes again before storage.
 */
export const passwordKdfParamsSchema = z.object({
  algorithm: z.literal('argon2id'),
  salt: base64(64),
  memoryKiB: z.number().int().min(8 * 1024).max(1024 * 1024),
  iterations: z.number().int().min(1).max(16),
  parallelism: z.number().int().min(1).max(8),
});
export type PasswordKdfParams = z.infer<typeof passwordKdfParamsSchema>;

export const registerAccountRequestSchema = z.object({
  username: usernameSchema,
  /** Argon2id(password, salt) computed on the client. 32 bytes. */
  clientProof: base64(64),
  kdfParams: passwordKdfParamsSchema,
  /** Ed25519 public key of the first device's *server authentication* key. */
  deviceAuthPublicKey: base64(64),
  deviceLabel: z.string().min(1).max(64),
});
export type RegisterAccountRequest = z.infer<typeof registerAccountRequestSchema>;

export const registerAccountResponseSchema = z.object({
  userId: uuidSchema,
  deviceId: deviceIdSchema,
});
export type RegisterAccountResponse = z.infer<typeof registerAccountResponseSchema>;

export const kdfParamsResponseSchema = z.object({
  kdfParams: passwordKdfParamsSchema,
});

export const registerDeviceRequestSchema = z.object({
  username: usernameSchema,
  clientProof: base64(64),
  deviceAuthPublicKey: base64(64),
  deviceLabel: z.string().min(1).max(64),
});
export type RegisterDeviceRequest = z.infer<typeof registerDeviceRequestSchema>;

// ---------------------------------------------------------------------------
// Device-key authentication (challenge/response over Ed25519)
// ---------------------------------------------------------------------------

export const authChallengeRequestSchema = z.object({
  userId: uuidSchema,
  deviceId: deviceIdSchema,
});

export const authChallengeResponseSchema = z.object({
  challengeId: z.string().min(1).max(64),
  /** 32 random bytes to be signed with the device authentication key. */
  nonce: base64(64),
  expiresAt: z.number().int(),
});
export type AuthChallengeResponse = z.infer<typeof authChallengeResponseSchema>;

export const authVerifyRequestSchema = z.object({
  challengeId: z.string().min(1).max(64),
  /** Ed25519 signature over the domain-separated challenge context. */
  signature: base64(128),
});

export const authVerifyResponseSchema = z.object({
  token: z.string().min(1).max(512),
  userId: uuidSchema,
  deviceId: deviceIdSchema,
  expiresAt: z.number().int(),
});
export type AuthVerifyResponse = z.infer<typeof authVerifyResponseSchema>;

/**
 * Domain-separation prefix signed alongside the nonce, so a device signature
 * produced for one purpose cannot be replayed as another.
 */
export const AUTH_CHALLENGE_CONTEXT = 'p2pchat/v1/device-auth';

// ---------------------------------------------------------------------------
// Key package directory (the MLS equivalent of a prekey store)
// ---------------------------------------------------------------------------

export const publishKeyPackagesRequestSchema = z.object({
  keyPackages: z.array(base64(8192)).min(1).max(100),
});

export const keyPackageCountResponseSchema = z.object({
  count: z.number().int().min(0),
});

export const claimKeyPackagesRequestSchema = z.object({
  userId: uuidSchema,
});

export const claimedKeyPackageSchema = z.object({
  deviceId: deviceIdSchema,
  keyPackage: base64(8192),
});

export const claimKeyPackagesResponseSchema = z.object({
  userId: uuidSchema,
  keyPackages: z.array(claimedKeyPackageSchema),
});
export type ClaimKeyPackagesResponse = z.infer<typeof claimKeyPackagesResponseSchema>;

// ---------------------------------------------------------------------------
// Directory & device management
// ---------------------------------------------------------------------------

export const deviceInfoSchema = z.object({
  deviceId: deviceIdSchema,
  label: z.string().max(64),
  createdAt: z.number().int(),
  lastSeenAt: z.number().int().nullable(),
});
export type DeviceInfo = z.infer<typeof deviceInfoSchema>;

export const directoryEntrySchema = z.object({
  userId: uuidSchema,
  username: usernameSchema,
  devices: z.array(deviceInfoSchema),
});
export type DirectoryEntry = z.infer<typeof directoryEntrySchema>;

export const deviceListResponseSchema = z.object({
  devices: z.array(deviceInfoSchema),
});

// ---------------------------------------------------------------------------
// ICE configuration for WebRTC
// ---------------------------------------------------------------------------

export const iceServerSchema = z.object({
  urls: z.array(z.string()).min(1),
  username: z.string().optional(),
  credential: z.string().optional(),
});

export const iceConfigResponseSchema = z.object({
  iceServers: z.array(iceServerSchema),
  /** Expiry of any short-lived TURN credentials above. */
  expiresAt: z.number().int().nullable(),
});
export type IceConfigResponse = z.infer<typeof iceConfigResponseSchema>;

// ---------------------------------------------------------------------------
// Encrypted attachment blobs
// ---------------------------------------------------------------------------

export const blobUploadResponseSchema = z.object({
  blobId: z.string().min(1).max(64),
  expiresAt: z.number().int(),
});
export type BlobUploadResponse = z.infer<typeof blobUploadResponseSchema>;

// ---------------------------------------------------------------------------
// WebSocket: signaling + relay
// ---------------------------------------------------------------------------

export const peerAddressSchema = z.object({
  userId: uuidSchema,
  deviceId: deviceIdSchema,
});
export type PeerAddress = z.infer<typeof peerAddressSchema>;

/**
 * WebRTC signaling payload. The server routes these verbatim; it can read SDP
 * and ICE candidates (see THREAT_MODEL.md "metadata the server observes").
 */
export const signalPayloadSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('offer'), sdp: z.string().max(64 * 1024), sessionId: z.string().max(64) }),
  z.object({ kind: z.literal('answer'), sdp: z.string().max(64 * 1024), sessionId: z.string().max(64) }),
  z.object({
    kind: z.literal('ice-candidate'),
    sessionId: z.string().max(64),
    candidate: z.string().max(4096),
    sdpMid: z.string().max(64).nullable(),
    sdpMLineIndex: z.number().int().nullable(),
  }),
  z.object({ kind: z.literal('hangup'), sessionId: z.string().max(64) }),
]);
export type SignalPayload = z.infer<typeof signalPayloadSchema>;

export const clientToServerSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('auth'), token: z.string().max(512) }),
  z.object({ type: z.literal('ping'), t: z.number().int() }),
  z.object({ type: z.literal('presence.subscribe'), userIds: z.array(uuidSchema).max(200) }),
  z.object({ type: z.literal('signal'), to: peerAddressSchema, payload: signalPayloadSchema }),
  /** Store-and-forward fallback: an opaque ciphertext frame for a peer device. */
  z.object({ type: z.literal('relay.send'), to: peerAddressSchema, frame: base64(4 * 1024 * 1024) }),
  z.object({ type: z.literal('relay.ack'), envelopeIds: z.array(z.string().max(64)).max(500) }),
  z.object({ type: z.literal('relay.pull') }),
]);
export type ClientToServerMessage = z.infer<typeof clientToServerSchema>;

export const serverToClientSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('auth.ok'), userId: uuidSchema, deviceId: deviceIdSchema }),
  z.object({ type: z.literal('pong'), t: z.number().int() }),
  z.object({
    type: z.literal('error'),
    code: z.string().max(64),
    message: z.string().max(256),
  }),
  z.object({ type: z.literal('signal'), from: peerAddressSchema, payload: signalPayloadSchema }),
  z.object({
    type: z.literal('relay.deliver'),
    envelopeId: z.string().max(64),
    from: peerAddressSchema,
    frame: base64(4 * 1024 * 1024),
    receivedAt: z.number().int(),
  }),
  z.object({ type: z.literal('relay.queue-empty') }),
  z.object({
    type: z.literal('presence'),
    userId: uuidSchema,
    devices: z.array(z.object({ deviceId: deviceIdSchema, online: z.boolean() })),
  }),
]);
export type ServerToClientMessage = z.infer<typeof serverToClientSchema>;

export const errorResponseSchema = z.object({
  error: z.object({ code: z.string(), message: z.string() }),
});
