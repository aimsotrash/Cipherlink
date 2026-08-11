/**
 * MLS (RFC 9420) session engine.
 *
 * This is a thin, opinionated wrapper over `@wireapp/core-crypto`. It owns:
 *   - the device's long-term MLS signature credential (Ed25519),
 *   - the encrypted key store those private keys live in,
 *   - conversation lifecycle (create / join / rekey / leave),
 *   - application message encryption and decryption.
 *
 * Deliberately NOT in this file: any cryptographic construction. Group key
 * agreement, the key schedule, per-message key derivation, AEAD, signing and
 * replay rejection are all performed by core-crypto's Rust implementation of
 * RFC 9420. See SECURITY.md for the protocol properties this relies on.
 */
import {
  MLS_CIPHERSUITE,
  MLS_DOMAIN,
  toBase64Url,
  fromBase64Url,
  type Logger,
  silentLogger,
} from '@p2pchat/shared';
import { initCryptoBackend, type CoreCryptoApi } from './binding.js';

export interface MlsClientAddress {
  /** Account-level identifier (UUID). */
  readonly userId: string;
  /** Device-level identifier (lowercase hex, ≤16 chars). */
  readonly deviceId: string;
}

export function formatClientAddress(address: MlsClientAddress): string {
  return `${address.userId}:${address.deviceId}`;
}

/** A commit (and possibly a Welcome) that must be delivered to peers. */
export interface OutboundCommitBundle {
  readonly conversationId: string;
  readonly commit: Uint8Array;
  readonly welcome?: Uint8Array;
}

export interface DecryptedApplicationMessage {
  readonly kind: 'application';
  readonly plaintext: Uint8Array;
  readonly sender: MlsClientAddress;
  /** JWK thumbprint of the sender's MLS signature key — the identity to verify. */
  readonly senderThumbprint: string;
}

export interface AppliedCommit {
  readonly kind: 'commit';
  /** False once we have been removed from the group by this commit. */
  readonly stillMember: boolean;
  /** Messages that arrived early and became decryptable once the commit landed. */
  readonly buffered: DecryptedApplicationMessage[];
}

export interface ReceivedProposal {
  readonly kind: 'proposal';
}

export type DecryptOutcome = DecryptedApplicationMessage | AppliedCommit | ReceivedProposal;

export interface MlsMemberIdentity {
  readonly address: MlsClientAddress;
  readonly thumbprint: string;
}

export type MlsErrorCode =
  | 'duplicate-message'
  | 'wrong-epoch'
  | 'buffered'
  | 'self-commit'
  | 'unauthorized'
  | 'decryption-failed'
  | 'unknown-conversation'
  | 'backend';

/**
 * Error raised by the engine.
 *
 * Carries a coarse machine-readable code and never embeds plaintext, key
 * material or ciphertext, so it is safe to log and to surface in the UI.
 */
export class MlsEngineError extends Error {
  readonly code: MlsErrorCode;

  constructor(code: MlsErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'MlsEngineError';
    this.code = code;
  }
}

/**
 * Map a core-crypto failure onto a stable code.
 *
 * core-crypto reports several *expected* conditions as errors (a replayed
 * message, a message from an epoch we have already left, a message that
 * arrived before its commit). Callers need to distinguish those from genuine
 * authentication failures, which must be surfaced to the user.
 */
function classifyError(error: unknown): MlsEngineError {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  const lower = text.toLowerCase();

  if (lower.includes('duplicate')) {
    return new MlsEngineError('duplicate-message', 'Message was already processed', { cause: error });
  }
  if (lower.includes('buffered') || lower.includes('future epoch') || lower.includes('unmerged')) {
    return new MlsEngineError('buffered', 'Message buffered pending its commit', { cause: error });
  }
  if (lower.includes('wrong epoch') || lower.includes('stale') || lower.includes('epoch')) {
    return new MlsEngineError('wrong-epoch', 'Message belongs to a different epoch', { cause: error });
  }
  if (lower.includes('self commit') || lower.includes('own commit')) {
    return new MlsEngineError('self-commit', 'Message is our own commit echoed back', { cause: error });
  }
  if (lower.includes('conversation not found') || lower.includes('no such conversation')) {
    return new MlsEngineError('unknown-conversation', 'Unknown conversation', { cause: error });
  }
  if (
    lower.includes('unauthorized') ||
    lower.includes('signature') ||
    lower.includes('invalid') ||
    lower.includes('decrypt') ||
    lower.includes('tag')
  ) {
    return new MlsEngineError('decryption-failed', 'Message failed authentication', { cause: error });
  }
  return new MlsEngineError('backend', 'MLS backend error', { cause: error });
}

export type MlsStorageConfig =
  | { readonly kind: 'memory' }
  | {
      readonly kind: 'persistent';
      /** IndexedDB database name (browser) or file path (Node). */
      readonly location: string;
      /**
       * 32-byte key encrypting the MLS key store at rest. Supplied by the
       * vault; derived from the user's passphrase, never persisted verbatim.
       */
      readonly databaseKey: Uint8Array;
    };

export interface MlsEngineOptions {
  readonly address: MlsClientAddress;
  readonly storage: MlsStorageConfig;
  /**
   * Called whenever MLS produces a handshake message that peers must receive.
   * Delivery is the transport layer's problem; the engine only guarantees it
   * hands over bytes that are safe for an untrusted relay to carry.
   */
  readonly onOutboundCommit: (bundle: OutboundCommitBundle) => Promise<void>;
  readonly logger?: Logger;
  readonly wasmUrl?: string;
}

type Backend = CoreCryptoApi;
/* eslint-disable @typescript-eslint/no-explicit-any */
type CoreCryptoInstance = any;
type CoreCryptoContext = any;
type CredentialRef = any;
/* eslint-enable @typescript-eslint/no-explicit-any */

export class MlsEngine {
  readonly address: MlsClientAddress;

  private readonly cc: CoreCryptoInstance;
  private readonly api: Backend;
  private readonly logger: Logger;
  private readonly onOutboundCommit: (bundle: OutboundCommitBundle) => Promise<void>;
  private credentialRef: CredentialRef;

  /**
   * Serialises every backend operation.
   *
   * Two reasons this is required rather than merely tidy:
   *  1. `CommitBundle` does not name its conversation, so we must know which
   *     conversation the in-flight operation belongs to when the transport
   *     callback fires (`currentConversationId` below).
   *  2. Concurrent core-crypto transactions on one instance can interleave
   *     group-state mutations.
   */
  private queue: Promise<unknown> = Promise.resolve();
  private currentConversationId: string | null = null;
  private outboundBuffer: OutboundCommitBundle[] = [];
  private closed = false;

  private constructor(params: {
    api: Backend;
    cc: CoreCryptoInstance;
    address: MlsClientAddress;
    credentialRef: CredentialRef;
    logger: Logger;
    onOutboundCommit: (bundle: OutboundCommitBundle) => Promise<void>;
  }) {
    this.api = params.api;
    this.cc = params.cc;
    this.address = params.address;
    this.credentialRef = params.credentialRef;
    this.logger = params.logger;
    this.onOutboundCommit = params.onOutboundCommit;
  }

  static async create(options: MlsEngineOptions): Promise<MlsEngine> {
    const logger = (options.logger ?? silentLogger).child('mls', {
      userId: options.address.userId,
      deviceId: options.address.deviceId,
    });
    const api = await initCryptoBackend(options.wasmUrl ? { wasmUrl: options.wasmUrl } : {});

    const database =
      options.storage.kind === 'memory'
        ? await api.Database.inMemory()
        : await api.Database.open(
            options.storage.location,
            new api.DatabaseKey(options.storage.databaseKey),
          );

    const cc = api.CoreCrypto.new(database);
    const clientId = new api.ClientId(
      new api.Uuid(options.address.userId),
      api.DeviceId.fromHexString(options.address.deviceId),
      MLS_DOMAIN,
    );

    // Placeholder so the transport closure can reach the finished instance.
    let engine: MlsEngine | undefined;
    const transport = {
      async sendCommitBundle(bundle: {
        commit: Uint8Array;
        welcome?: { serialize(): Uint8Array };
      }): Promise<void> {
        engine?.captureCommitBundle(bundle);
      },
      async prepareForTransport(): Promise<never> {
        // History sharing would hand a decryption secret for past messages to a
        // newly added member. We never enable it, so this must be unreachable.
        throw new Error('history sharing is disabled in this application');
      },
    };

    let credentialRef: CredentialRef;
    await cc.transaction(async (ctx: CoreCryptoContext) => {
      await ctx.mlsInit(clientId, transport);
    });

    // Reuse the device's existing credential across restarts. Creating a fresh
    // one would silently change this device's public identity — exactly the
    // event contacts are asked to treat as suspicious.
    const existing = await cc.findCredentials({
      clientId,
      cipherSuite: MLS_CIPHERSUITE,
      credentialType: api.CredentialType.Basic,
    });

    if (existing.length > 0) {
      credentialRef = existing[0];
      logger.info('reused existing device credential', { credentialCount: existing.length });
    } else {
      const credential = api.Credential.basic(MLS_CIPHERSUITE, clientId);
      await cc.transaction(async (ctx: CoreCryptoContext) => {
        credentialRef = await ctx.addCredential(credential);
      });
      logger.info('generated new device credential');
    }

    engine = new MlsEngine({
      api,
      cc,
      address: options.address,
      credentialRef: credentialRef!,
      logger,
      onOutboundCommit: options.onOutboundCommit,
    });
    return engine;
  }

  /** Invoked synchronously by core-crypto while a commit-producing op runs. */
  private captureCommitBundle(bundle: {
    commit: Uint8Array;
    welcome?: { serialize(): Uint8Array };
  }): void {
    const conversationId = this.currentConversationId;
    if (!conversationId) {
      // Should be unreachable: every commit-producing call sets this first.
      this.logger.error('commit bundle produced outside a tracked operation');
      return;
    }
    const welcome = bundle.welcome?.serialize();
    this.outboundBuffer.push(
      welcome
        ? { conversationId, commit: bundle.commit, welcome }
        : { conversationId, commit: bundle.commit },
    );
  }

  /**
   * Run `fn` with exclusive access to the backend, then hand any commits it
   * produced to the transport.
   *
   * Commits are dispatched *after* the transaction commits so that we never
   * publish a group state we failed to persist locally.
   */
  private run<T>(conversationId: string | null, fn: (ctx: CoreCryptoContext) => Promise<T>): Promise<T> {
    const task = this.queue.then(async () => {
      if (this.closed) throw new MlsEngineError('backend', 'MLS engine is closed');
      this.currentConversationId = conversationId;
      this.outboundBuffer = [];
      let result: T;
      try {
        result = await this.cc.transaction((ctx: CoreCryptoContext) => fn(ctx));
      } catch (error) {
        this.outboundBuffer = [];
        throw classifyError(error);
      } finally {
        this.currentConversationId = null;
      }
      const pending = this.outboundBuffer;
      this.outboundBuffer = [];
      for (const bundle of pending) {
        await this.onOutboundCommit(bundle);
      }
      return result;
    });
    // Keep the chain alive even when a caller's promise rejects.
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  /** SHA-256 of this device's MLS signature public key. */
  publicKeyHash(): Uint8Array {
    return this.credentialRef.publicKeyHash();
  }

  /**
   * Produce fresh key packages for publication to the directory.
   *
   * A key package is this device's offer to be added to a group: it contains
   * the credential, the signature public key and a one-time HPKE init key.
   * The matching private keys stay in the local encrypted store.
   */
  async generateKeyPackages(count: number): Promise<Uint8Array[]> {
    return this.run(null, async (ctx) => {
      const packages: Uint8Array[] = [];
      for (let i = 0; i < count; i++) {
        const kp = await ctx.generateKeyPackage(this.credentialRef);
        packages.push(kp.serialize());
      }
      return packages;
    });
  }

  async createConversation(conversationId: string, peerKeyPackages: Uint8Array[]): Promise<void> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    await this.run(conversationId, async (ctx) => {
      await ctx.createConversation(convId, this.credentialRef);
      if (peerKeyPackages.length > 0) {
        await ctx.addClientsToConversation(
          convId,
          peerKeyPackages.map((bytes) => new this.api.KeyPackage(bytes)),
        );
      }
    });
    this.logger.info('conversation created', {
      conversationId,
      addedMembers: peerKeyPackages.length,
    });
  }

  /** Add more devices (e.g. a contact's new device) to an existing group. */
  async addMembers(conversationId: string, peerKeyPackages: Uint8Array[]): Promise<void> {
    if (peerKeyPackages.length === 0) return;
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    await this.run(conversationId, async (ctx) => {
      await ctx.addClientsToConversation(
        convId,
        peerKeyPackages.map((bytes) => new this.api.KeyPackage(bytes)),
      );
    });
    this.logger.info('members added', { conversationId, count: peerKeyPackages.length });
  }

  async removeMembers(conversationId: string, members: MlsClientAddress[]): Promise<void> {
    if (members.length === 0) return;
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    await this.run(conversationId, async (ctx) => {
      await ctx.removeClientsFromConversation(
        convId,
        members.map((m) => this.toClientId(m)),
      );
    });
    this.logger.info('members removed', { conversationId, count: members.length });
  }

  /** Join a group from a Welcome produced by the initiator's Add commit. */
  async joinFromWelcome(welcome: Uint8Array): Promise<string> {
    const conversationId = await this.run(null, async (ctx) => {
      const convId = await ctx.processWelcomeMessage(new this.api.Welcome(welcome));
      return toBase64Url(convId.copyBytes());
    });
    this.logger.info('joined conversation from welcome', { conversationId });
    return conversationId;
  }

  async conversationExists(conversationId: string): Promise<boolean> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    return this.run(conversationId, async (ctx) => ctx.conversationExists(convId));
  }

  async encrypt(conversationId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    return this.run(conversationId, async (ctx) => ctx.encryptMessage(convId, plaintext));
  }

  /**
   * Decrypt an inbound MLS message.
   *
   * Authentication is not optional here: core-crypto verifies the sender's
   * signature and the AEAD tag before returning anything, and rejects replays
   * and out-of-epoch messages. A thrown {@link MlsEngineError} with code
   * `decryption-failed` means the frame was forged or tampered with.
   */
  async decrypt(conversationId: string, ciphertext: Uint8Array): Promise<DecryptOutcome> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    const message = await this.run(conversationId, async (ctx) =>
      ctx.decryptMessage(convId, ciphertext),
    );
    return this.interpretDecrypted(message);
  }

  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  private interpretDecrypted(message: any): DecryptOutcome {
    switch (message.tag) {
      case 'Text':
        return {
          kind: 'application',
          plaintext: message.inner.plaintext,
          sender: this.fromClientId(message.inner.senderClientId),
          senderThumbprint: String(message.inner.identity?.thumbprint ?? ''),
        };
      case 'Commit': {
        /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
        const buffered: DecryptedApplicationMessage[] = (message.inner.bufferedMessages ?? [])
          /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
          .filter((m: any) => m.tag === 'Text')
          /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
          .map((m: any) => ({
            kind: 'application' as const,
            plaintext: m.inner.plaintext,
            sender: this.fromClientId(m.inner.senderClientId),
            senderThumbprint: String(m.inner.identity?.thumbprint ?? ''),
          }));
        return { kind: 'commit', stillMember: Boolean(message.inner.isActive), buffered };
      }
      default:
        return { kind: 'proposal' };
    }
  }

  /**
   * Advance the group to a new epoch with fresh keys (an MLS self-update
   * commit). This is what gives post-compromise security: an attacker who
   * stole the previous epoch's secrets is locked out of everything after it.
   */
  async rotateKeys(conversationId: string): Promise<void> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    await this.run(conversationId, async (ctx) => ctx.updateKeyingMaterial(convId));
    this.logger.info('group keying material rotated', { conversationId });
  }

  async epoch(conversationId: string): Promise<bigint> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    return this.run(conversationId, async (ctx) => ctx.conversationEpoch(convId));
  }

  async members(conversationId: string): Promise<MlsClientAddress[]> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    const ids = await this.run(conversationId, async (ctx) => ctx.getClientIds(convId));
    /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
    return ids.map((id: any) => this.fromClientId(id));
  }

  /**
   * Signature-key thumbprints for the given members, read out of the live
   * group state rather than from anything the server told us. These are the
   * inputs to the safety number.
   */
  async memberIdentities(
    conversationId: string,
    members: MlsClientAddress[],
  ): Promise<MlsMemberIdentity[]> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    const identities = await this.run(conversationId, async (ctx) =>
      ctx.getDeviceIdentities(
        convId,
        members.map((m) => this.toClientId(m)),
      ),
    );
    /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
    return identities.map((identity: any) => ({
      address: this.fromClientId(identity.clientId),
      thumbprint: String(identity.thumbprint ?? ''),
    }));
  }

  /**
   * RFC 9420 §8.5 exporter. Bound to the group and the current epoch, so a
   * value exported in epoch N is unrelated to one exported in epoch N+1.
   */
  async exportSecret(conversationId: string, length: number): Promise<Uint8Array> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    const secret = await this.run(conversationId, async (ctx) =>
      ctx.exportSecretKey(convId, length),
    );
    return secret.copyBytes();
  }

  /** Destroy all local state for a conversation (secure session termination). */
  async wipeConversation(conversationId: string): Promise<void> {
    const convId = new this.api.ConversationId(fromBase64Url(conversationId));
    await this.run(conversationId, async (ctx) => ctx.wipeConversation(convId));
    this.logger.info('conversation wiped', { conversationId });
  }

  async close(): Promise<void> {
    // Drain in-flight work before tearing the backend down.
    await this.queue.catch(() => undefined);
    this.closed = true;
  }

  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  private toClientId(address: MlsClientAddress): any {
    return new this.api.ClientId(
      new this.api.Uuid(address.userId),
      this.api.DeviceId.fromHexString(address.deviceId),
      MLS_DOMAIN,
    );
  }

  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  private fromClientId(clientId: any): MlsClientAddress {
    const parts = clientId.deserialize();
    return {
      userId: String(parts.userId ?? parts.user_id ?? ''),
      deviceId: normaliseDeviceId(parts.deviceId ?? parts.device_id),
    };
  }
}

/** core-crypto returns device ids as u64; our wire format is lowercase hex. */
function normaliseDeviceId(value: unknown): string {
  if (typeof value === 'bigint') return value.toString(16);
  if (typeof value === 'number') return Math.trunc(value).toString(16);
  if (typeof value === 'string') return value.toLowerCase().replace(/^0x/, '');
  if (value && typeof value === 'object') {
    const maybe = value as { toString(): string };
    const text = maybe.toString();
    if (/^\d+$/.test(text)) return BigInt(text).toString(16);
    return text.toLowerCase().replace(/^0x/, '');
  }
  return '';
}

/** Fresh, unpredictable 32-byte conversation identifier. */
export function newConversationId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}
