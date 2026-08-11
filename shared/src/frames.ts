/**
 * Peer <-> peer transport frames.
 *
 * A `TransportFrame` is what travels over the WebRTC DataChannel, or — when
 * direct connectivity fails — through the server's store-and-forward relay.
 *
 * The server can read a frame's `type` and `conversationId` (it must, to route
 * and de-duplicate), but `payload` is always an MLS message: the server holds
 * no group secret for the conversation and therefore cannot decrypt it, forge
 * it, or modify it undetectably. See SECURITY.md.
 */
import { z } from 'zod';

const framePayload = z
  .string()
  .max(4 * 1024 * 1024)
  .regex(/^[A-Za-z0-9+/\-_]*={0,2}$/, 'expected base64');

export const transportFrameSchema = z.discriminatedUnion('type', [
  /**
   * MLS Welcome: invites the recipient into a new group. Produced by the
   * initiator's Add commit. Carries no plaintext.
   */
  z.object({
    v: z.literal(1),
    type: z.literal('mls-welcome'),
    conversationId: z.string().max(128),
    payload: framePayload,
  }),
  /**
   * MLS handshake message (Commit / Proposal): membership changes and key
   * rotation. Must be applied in order by every member.
   */
  z.object({
    v: z.literal(1),
    type: z.literal('mls-commit'),
    conversationId: z.string().max(128),
    payload: framePayload,
  }),
  /** MLS application message: the encrypted chat payload. */
  z.object({
    v: z.literal(1),
    type: z.literal('mls-app'),
    conversationId: z.string().max(128),
    payload: framePayload,
  }),
  /**
   * Transport-level keepalive. Contains no user data and is never persisted;
   * used to detect a dead DataChannel before the ICE timeout fires.
   */
  z.object({
    v: z.literal(1),
    type: z.literal('keepalive'),
    t: z.number().int(),
  }),
]);
export type TransportFrame = z.infer<typeof transportFrameSchema>;

// ---------------------------------------------------------------------------
// Application payloads — these exist ONLY inside MLS ciphertext.
// ---------------------------------------------------------------------------

/**
 * Metadata needed to fetch and decrypt an attachment.
 *
 * The key never leaves the encrypted channel: it is generated per attachment,
 * used once, and delivered inside an MLS application message. The relay stores
 * only the ciphertext blob and can neither name nor read it.
 */
export const attachmentDescriptorSchema = z.object({
  blobId: z.string().min(1).max(64),
  /** Base64 AES-256-GCM content key, random per attachment. */
  key: z.string().max(64),
  /** Base64 96-bit GCM nonce, random per attachment. */
  iv: z.string().max(32),
  /** Base64 SHA-256 of the *ciphertext*, binding the blob to this message. */
  ciphertextDigest: z.string().max(64),
  filename: z.string().max(255),
  mimeType: z.string().max(128),
  /** Plaintext byte length, used for UI progress only. */
  size: z.number().int().min(0),
});
export type AttachmentDescriptor = z.infer<typeof attachmentDescriptorSchema>;

export const appPayloadSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('text'),
    /** Client-generated message id (UUID); used for de-duplication and receipts. */
    id: z.string().max(64),
    /** Sender's clock, for display only — never trusted for ordering decisions. */
    sentAt: z.number().int(),
    /**
     * Strictly increasing per-sender counter. Combined with MLS's own replay
     * protection this lets the receiver reject out-of-band duplicates cheaply.
     */
    seq: z.number().int().min(0),
    body: z.string().max(64 * 1024),
    attachments: z.array(attachmentDescriptorSchema).max(8).optional(),
  }),
  /** Delivery receipt: the peer's client received and decrypted the message. */
  z.object({
    kind: z.literal('delivered'),
    ids: z.array(z.string().max(64)).max(200),
    at: z.number().int(),
  }),
  /** Read receipt, only sent when the user has enabled them. */
  z.object({
    kind: z.literal('read'),
    ids: z.array(z.string().max(64)).max(200),
    at: z.number().int(),
  }),
  z.object({
    kind: z.literal('typing'),
    active: z.boolean(),
    at: z.number().int(),
  }),
  /**
   * Sent when a client rotates its own leaf key. Purely informational — the
   * actual rotation is the MLS commit; this just lets the UI explain it.
   */
  z.object({
    kind: z.literal('rekey-notice'),
    epoch: z.string().max(32),
    at: z.number().int(),
  }),
]);
export type AppPayload = z.infer<typeof appPayloadSchema>;
