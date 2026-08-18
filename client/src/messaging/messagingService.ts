/**
 * The messaging layer: where a user's plaintext meets the crypto and transport
 * layers, and the only place both are visible at once.
 *
 * Outbound lifecycle
 *   user text
 *     -> AppPayload (JSON, with per-sender sequence number)
 *     -> MlsEngine.encrypt          [authenticated encryption, per-message key]
 *     -> TransportFrame             [opaque]
 *     -> TransportManager.send      [WebRTC DataChannel, else server relay]
 *
 * Inbound lifecycle
 *   TransportFrame
 *     -> MlsEngine.decrypt          [signature + AEAD verified, replays rejected]
 *     -> identity check against the trust store
 *     -> AppPayload validated against a schema
 *     -> stored (encrypted at rest) and surfaced to the UI
 *
 * Invariants enforced here:
 *   - Nothing is stored or displayed before MLS has authenticated it.
 *   - A sender whose signature key changed is never silently accepted.
 *   - Outbound messages to an unacknowledged changed identity are blocked when
 *     the corresponding setting is on.
 *   - Message bodies never reach the logger.
 */
import {
  appPayloadSchema,
  REKEY_AFTER_MESSAGES,
  REKEY_AFTER_MS,
  silentLogger,
  toBase64,
  fromBase64,
  utf8Decode,
  utf8Encode,
  type AppPayload,
  type AttachmentDescriptor,
  type Logger,
  type PeerAddress,
  type TransportFrame,
} from '@p2pchat/shared';
import { MlsEngineError, newConversationId, type MlsEngine } from '../crypto/mls.js';
import { encryptAttachment, decryptAttachment } from '../crypto/attachments.js';
import { randomId } from '../crypto/random.js';
import type { TrustStore, IdentityChangeEvent } from '../identity/trustStore.js';
import type { Repository } from '../storage/repository.js';
import type {
  AppSettings,
  Conversation,
  DeliveryStatus,
  StoredMessage,
  TransportUsed,
} from '../storage/models.js';
import type { TransportManager } from '../p2p/transportManager.js';
import { EventChannel, type TransportKind } from '../p2p/types.js';
import type { ApiClient } from '../p2p/apiClient.js';

export interface OutgoingAttachment {
  readonly data: Uint8Array;
  readonly filename: string;
  readonly mimeType: string;
}

export interface MessagingServiceOptions {
  readonly self: PeerAddress;
  readonly engine: MlsEngine;
  readonly transport: TransportManager;
  readonly repository: Repository;
  readonly trustStore: TrustStore;
  readonly api: ApiClient;
  readonly settings: () => AppSettings;
  readonly logger?: Logger;
  readonly now?: () => number;
}

/** Reason a message could not be sent, in user-presentable terms. */
export class SendBlockedError extends Error {
  constructor(
    readonly reason: 'identity-changed' | 'no-transport' | 'not-a-member',
    message: string,
  ) {
    super(message);
    this.name = 'SendBlockedError';
  }
}

export class MessagingService {
  readonly onMessage = new EventChannel<StoredMessage>();
  readonly onMessageUpdated = new EventChannel<StoredMessage>();
  readonly onConversationUpdated = new EventChannel<Conversation>();
  readonly onIdentityChange = new EventChannel<IdentityChangeEvent>();
  readonly onTyping = new EventChannel<{ conversationId: string; from: PeerAddress; active: boolean }>();

  private readonly logger: Logger;
  private readonly now: () => number;
  /** conversationId -> peer devices that should receive its frames. */
  private readonly routing = new Map<string, PeerAddress[]>();
  /** Set while an Add is in flight so the Welcome reaches the right devices. */
  private pendingAdds: { conversationId: string; members: PeerAddress[] } | null = null;

  constructor(private readonly options: MessagingServiceOptions) {
    this.logger = (options.logger ?? silentLogger).child('messaging');
    this.now = options.now ?? Date.now;
  }

  /** Wire up transport and trust callbacks and restore routing from storage. */
  async start(): Promise<void> {
    this.options.transport.onFrame.subscribe(({ from, frame, via }) => {
      void this.handleInboundFrame(from, frame, via).catch((error) => {
        this.logger.warn('failed to process inbound frame', {
          kind: frame.type,
          reason: error instanceof Error ? error.name : 'unknown',
        });
      });
    });

    this.options.trustStore.onIdentityChange((event) => this.onIdentityChange.emit(event));

    for (const conversation of await this.options.repository.listConversations()) {
      const members = await this.membersOf(conversation.id);
      this.routing.set(conversation.id, members);
    }
  }

  /**
   * Route a handshake message produced by the MLS engine.
   *
   * Registered as the engine's `onOutboundCommit`; see {@link MlsEngine}.
   */
  readonly handleOutboundCommit = async (bundle: {
    conversationId: string;
    commit: Uint8Array;
    welcome?: Uint8Array;
  }): Promise<void> => {
    const newMembers =
      this.pendingAdds?.conversationId === bundle.conversationId ? this.pendingAdds.members : [];
    const newKeys = new Set(newMembers.map(addressKey));

    if (bundle.welcome) {
      for (const member of newMembers) {
        await this.sendFrame(member, {
          v: 1,
          type: 'mls-welcome',
          conversationId: bundle.conversationId,
          payload: toBase64(bundle.welcome),
        });
      }
    }

    // Existing members need the commit itself; the newly added ones get their
    // state from the Welcome and must not be sent the commit.
    const existing = (this.routing.get(bundle.conversationId) ?? []).filter(
      (member) => !newKeys.has(addressKey(member)),
    );
    for (const member of existing) {
      await this.sendFrame(member, {
        v: 1,
        type: 'mls-commit',
        conversationId: bundle.conversationId,
        payload: toBase64(bundle.commit),
      });
    }
  };

  private async sendFrame(peer: PeerAddress, frame: TransportFrame): Promise<TransportKind> {
    return this.options.transport.send(peer, frame);
  }

  // -- conversation setup ---------------------------------------------------

  /**
   * Create a 1:1 conversation with every device belonging to `username`.
   *
   * Key packages come from the server's directory. The server chooses which to
   * hand over and could substitute its own — the safety number check in the
   * verification screen is what detects that, and until it is done the
   * conversation is shown as unverified.
   */
  async startConversation(username: string): Promise<Conversation> {
    const directory = await this.options.api.lookupUser(username);
    if (directory.devices.length === 0) {
      throw new Error(`${username} has no registered devices`);
    }

    const claimed = await this.options.api.claimKeyPackages(directory.userId);
    if (claimed.keyPackages.length === 0) {
      throw new Error(`no key packages available for ${username}; they may need to come online`);
    }

    const conversationId = newConversationId();
    const members: PeerAddress[] = claimed.keyPackages.map((entry) => ({
      userId: directory.userId,
      deviceId: entry.deviceId,
    }));

    this.routing.set(conversationId, members);
    this.pendingAdds = { conversationId, members };
    try {
      await this.options.engine.createConversation(
        conversationId,
        claimed.keyPackages.map((entry) => fromBase64(entry.keyPackage)),
      );
    } finally {
      this.pendingAdds = null;
    }

    await this.recordMemberIdentities(conversationId);

    const conversation: Conversation = {
      id: conversationId,
      peerUserId: directory.userId,
      peerUsername: directory.username,
      createdAt: this.now(),
      lastActivityAt: this.now(),
      lastMessagePreview: '',
      unreadCount: 0,
      active: true,
    };
    await this.options.repository.saveConversation(conversation);
    await this.options.repository.saveContact({
      userId: directory.userId,
      username: directory.username,
      addedAt: this.now(),
      deviceIds: directory.devices.map((d) => d.deviceId),
    });

    for (const member of members) this.options.transport.warmUp(member);
    this.onConversationUpdated.emit(conversation);
    this.logger.info('conversation started', { conversationId, memberCount: members.length });
    return conversation;
  }

  /**
   * Bring a contact's newly registered devices into an existing conversation.
   *
   * `pendingAdds` must be set around the call: the Welcome produced by the Add
   * commit is routed to exactly those devices, while the commit itself goes to
   * the members who were already in the group.
   */
  async addDevicesToConversation(conversationId: string, userId: string): Promise<number> {
    const known = new Set(
      (this.routing.get(conversationId) ?? []).map((member) => addressKey(member)),
    );
    const claimed = await this.options.api.claimKeyPackages(userId);
    const fresh = claimed.keyPackages.filter(
      (entry) => !known.has(addressKey({ userId, deviceId: entry.deviceId })),
    );
    if (fresh.length === 0) return 0;

    const newMembers: PeerAddress[] = fresh.map((entry) => ({
      userId,
      deviceId: entry.deviceId,
    }));

    this.pendingAdds = { conversationId, members: newMembers };
    try {
      await this.options.engine.addMembers(
        conversationId,
        fresh.map((entry) => fromBase64(entry.keyPackage)),
      );
    } finally {
      this.pendingAdds = null;
    }

    await this.recordMemberIdentities(conversationId);
    for (const member of newMembers) this.options.transport.warmUp(member);
    this.logger.info('added devices to conversation', {
      conversationId,
      added: newMembers.length,
    });
    return newMembers.length;
  }

  private async membersOf(conversationId: string): Promise<PeerAddress[]> {
    try {
      const members = await this.options.engine.members(conversationId);
      return members
        .filter((m) => !(m.userId === this.options.self.userId && m.deviceId === this.options.self.deviceId))
        .map((m) => ({ userId: m.userId, deviceId: m.deviceId }));
    } catch {
      return [];
    }
  }

  /**
   * Read every member's signature-key thumbprint out of live group state and
   * feed it to the trust store, so a substituted key is caught immediately
   * rather than at first message.
   */
  private async recordMemberIdentities(conversationId: string): Promise<void> {
    const members = await this.membersOf(conversationId);
    this.routing.set(conversationId, members);
    if (members.length === 0) return;

    const identities = await this.options.engine.memberIdentities(
      conversationId,
      members.map((m) => ({ userId: m.userId, deviceId: m.deviceId })),
    );
    for (const identity of identities) {
      if (!identity.thumbprint) continue;
      await this.options.trustStore.observe(identity.address, identity.thumbprint);
    }
  }

  // -- sending --------------------------------------------------------------

  async sendText(
    conversationId: string,
    body: string,
    attachments: OutgoingAttachment[] = [],
  ): Promise<StoredMessage> {
    const conversation = await this.options.repository.getConversation(conversationId);
    if (!conversation) throw new SendBlockedError('not-a-member', 'unknown conversation');

    const members = this.routing.get(conversationId) ?? (await this.membersOf(conversationId));
    if (members.length === 0) {
      throw new SendBlockedError('not-a-member', 'this conversation has no other members');
    }

    const settings = this.options.settings();
    const blocked = members.filter((member) =>
      this.options.trustStore.isSendBlocked(member, settings.blockOnIdentityChange),
    );
    if (blocked.length > 0) {
      throw new SendBlockedError(
        'identity-changed',
        'This contact’s security code changed. Review it before sending.',
      );
    }

    const descriptors = await this.uploadAttachments(attachments);

    const session = await this.options.repository.getSessionState(conversationId);
    const messageId = randomId();
    const sentAt = this.now();
    const payload: AppPayload = {
      kind: 'text',
      id: messageId,
      sentAt,
      seq: session.nextSeq,
      body,
      ...(descriptors.length > 0 ? { attachments: descriptors } : {}),
    };

    let epoch: string | null = null;
    try {
      epoch = (await this.options.engine.epoch(conversationId)).toString();
    } catch {
      /* epoch is informational only */
    }

    const stored: StoredMessage = {
      id: messageId,
      conversationId,
      senderUserId: this.options.self.userId,
      senderDeviceId: this.options.self.deviceId,
      outgoing: true,
      body,
      attachments: descriptors,
      sentAt,
      receivedAt: sentAt,
      status: 'pending',
      transport: 'pending',
      epoch,
      senderTrustAtReceipt: null,
    };
    await this.options.repository.appendMessage(stored);
    this.onMessage.emit(stored);

    const { status, transport } = await this.encryptAndFanOut(conversationId, payload, members);

    await this.options.repository.saveSessionState({
      ...session,
      nextSeq: session.nextSeq + 1,
      messagesSinceRekey: session.messagesSinceRekey + 1,
    });

    const updated = await this.patchMessage(conversationId, messageId, { status, transport });
    await this.touchConversation(conversation, body || attachmentPreview(descriptors));
    void this.maybeRotateKeys(conversationId);
    return updated ?? stored;
  }

  private async uploadAttachments(
    attachments: OutgoingAttachment[],
  ): Promise<AttachmentDescriptor[]> {
    const descriptors: AttachmentDescriptor[] = [];
    for (const attachment of attachments) {
      // Encrypt first, upload second. The relay only ever holds ciphertext,
      // and the key goes out through the MLS channel below.
      const encrypted = await encryptAttachment(attachment.data, {
        filename: attachment.filename,
        mimeType: attachment.mimeType,
      });
      const uploaded = await this.options.api.uploadBlob(encrypted.ciphertext);
      descriptors.push({ ...encrypted.secrets, blobId: uploaded.blobId });
      this.logger.info('attachment uploaded', {
        blobId: uploaded.blobId,
        bytes: encrypted.ciphertext.length,
      });
    }
    return descriptors;
  }

  private async encryptAndFanOut(
    conversationId: string,
    payload: AppPayload,
    members: PeerAddress[],
  ): Promise<{ status: DeliveryStatus; transport: TransportUsed }> {
    let ciphertext: Uint8Array;
    try {
      ciphertext = await this.options.engine.encrypt(
        conversationId,
        utf8Encode(JSON.stringify(payload)),
      );
    } catch (error) {
      this.logger.error('failed to encrypt outbound message', {
        conversationId,
        code: error instanceof MlsEngineError ? error.code : 'unknown',
      });
      return { status: 'failed', transport: 'pending' };
    }

    const frame: TransportFrame = {
      v: 1,
      type: 'mls-app',
      conversationId,
      payload: toBase64(ciphertext),
    };

    let anyDelivered = false;
    let usedRelay = false;
    for (const member of members) {
      try {
        const via = await this.sendFrame(member, frame);
        anyDelivered = true;
        if (via === 'relay') usedRelay = true;
      } catch {
        this.logger.warn('no transport available for member', {
          peerUserId: member.userId,
          peerDeviceId: member.deviceId,
        });
      }
    }

    if (!anyDelivered) return { status: 'failed', transport: 'pending' };
    return { status: 'sent', transport: usedRelay ? 'relay' : 'p2p' };
  }

  // -- receiving ------------------------------------------------------------

  async handleInboundFrame(
    from: PeerAddress,
    frame: TransportFrame,
    via: TransportKind,
  ): Promise<void> {
    switch (frame.type) {
      case 'keepalive':
        return;
      case 'mls-welcome':
        await this.handleWelcome(from, frame.payload);
        return;
      case 'mls-commit':
        await this.handleCommit(frame.conversationId, frame.payload, via);
        return;
      case 'mls-app':
        await this.handleApplication(frame.conversationId, frame.payload, via);
        return;
    }
  }

  private async handleWelcome(from: PeerAddress, payload: string): Promise<void> {
    const conversationId = await this.options.engine.joinFromWelcome(fromBase64(payload));
    await this.recordMemberIdentities(conversationId);

    // Start reaching every member directly, so replies do not have to take the
    // relay path the Welcome arrived on.
    for (const member of this.routing.get(conversationId) ?? []) {
      this.options.transport.warmUp(member);
    }

    const existing = await this.options.repository.getConversation(conversationId);
    if (existing) return;

    // Take the peer's identity from the MLS group state, not from the frame's
    // sender address. The sender address is asserted by the server, so trusting
    // it would let a hostile server label a conversation with the wrong
    // contact's name while the actual group member is someone else.
    const members = this.routing.get(conversationId) ?? [];
    const peerUserId = members[0]?.userId ?? from.userId;
    if (!members.some((member) => member.userId === from.userId)) {
      this.logger.warn('welcome sender is not a member of the group it invited us to', {
        conversationId,
      });
    }

    // Resolve a display name: local contact first, then the public directory.
    // The name is cosmetic — it is not what safety-number verification checks —
    // so a failure here falls back to the raw id rather than blocking the join.
    let username = peerUserId;
    try {
      const contact = await this.options.repository.getContact(peerUserId);
      if (contact) {
        username = contact.username;
      } else {
        const directory = await this.options.api.lookupUserById(peerUserId);
        username = directory.username;
        await this.options.repository.saveContact({
          userId: directory.userId,
          username: directory.username,
          addedAt: this.now(),
          deviceIds: directory.devices.map((device) => device.deviceId),
        });
      }
    } catch {
      /* name is cosmetic */
    }

    const conversation: Conversation = {
      id: conversationId,
      peerUserId,
      peerUsername: username,
      createdAt: this.now(),
      lastActivityAt: this.now(),
      lastMessagePreview: '',
      unreadCount: 0,
      active: true,
    };
    await this.options.repository.saveConversation(conversation);
    this.onConversationUpdated.emit(conversation);
    this.logger.info('joined a conversation', { conversationId });
  }

  private async handleCommit(
    conversationId: string,
    payload: string,
    via: TransportKind,
  ): Promise<void> {
    let outcome;
    try {
      outcome = await this.options.engine.decrypt(conversationId, fromBase64(payload));
    } catch (error) {
      this.noteDecryptFailure(conversationId, error);
      return;
    }
    if (outcome.kind !== 'commit') return;

    await this.recordMemberIdentities(conversationId);

    if (!outcome.stillMember) {
      const conversation = await this.options.repository.getConversation(conversationId);
      if (conversation) {
        const updated = { ...conversation, active: false };
        await this.options.repository.saveConversation(updated);
        this.onConversationUpdated.emit(updated);
      }
      this.logger.info('removed from conversation', { conversationId });
      return;
    }

    for (const buffered of outcome.buffered) {
      await this.acceptApplicationMessage(
        conversationId,
        buffered.plaintext,
        { userId: buffered.sender.userId, deviceId: buffered.sender.deviceId },
        buffered.senderThumbprint,
        via,
      );
    }
  }

  private async handleApplication(
    conversationId: string,
    payload: string,
    via: TransportKind,
  ): Promise<void> {
    let outcome;
    try {
      outcome = await this.options.engine.decrypt(conversationId, fromBase64(payload));
    } catch (error) {
      this.noteDecryptFailure(conversationId, error);
      return;
    }
    if (outcome.kind !== 'application') {
      if (outcome.kind === 'commit') await this.recordMemberIdentities(conversationId);
      return;
    }
    await this.acceptApplicationMessage(
      conversationId,
      outcome.plaintext,
      { userId: outcome.sender.userId, deviceId: outcome.sender.deviceId },
      outcome.senderThumbprint,
      via,
    );
  }

  private noteDecryptFailure(conversationId: string, error: unknown): void {
    const code = error instanceof MlsEngineError ? error.code : 'unknown';
    if (code === 'duplicate-message') {
      // Replay rejected by MLS. Expected under retransmission; not alarming.
      this.logger.debug('dropped a duplicate message', { conversationId });
      return;
    }
    if (code === 'buffered' || code === 'wrong-epoch' || code === 'self-commit') {
      this.logger.debug('message deferred by the protocol', { conversationId, code });
      return;
    }
    this.logger.warn('inbound message failed authentication', { conversationId, code });
  }

  /**
   * Accept a message whose MLS authentication already succeeded.
   *
   * Everything from here on treats `plaintext` as *authenticated but still
   * untrusted structure*: it is schema-validated before use.
   */
  private async acceptApplicationMessage(
    conversationId: string,
    plaintext: Uint8Array,
    sender: PeerAddress,
    thumbprint: string,
    via: TransportKind,
  ): Promise<void> {
    let payload: AppPayload;
    try {
      payload = appPayloadSchema.parse(JSON.parse(utf8Decode(plaintext)));
    } catch {
      this.logger.warn('discarded a message with an invalid payload shape', { conversationId });
      return;
    }

    if (thumbprint) {
      const change = await this.options.trustStore.observe(sender, thumbprint);
      if (change) {
        this.logger.warn('peer identity key changed', {
          peerUserId: sender.userId,
          peerDeviceId: sender.deviceId,
          wasVerified: change.wasVerified,
        });
      }
    }

    switch (payload.kind) {
      case 'text':
        await this.acceptTextMessage(conversationId, payload, sender, via);
        return;
      case 'delivered':
        await this.applyReceipts(conversationId, payload.ids, 'delivered');
        return;
      case 'read':
        await this.applyReceipts(conversationId, payload.ids, 'read');
        return;
      case 'typing':
        this.onTyping.emit({ conversationId, from: sender, active: payload.active });
        return;
      case 'rekey-notice':
        this.logger.info('peer rotated keying material', { conversationId, epoch: payload.epoch });
        return;
    }
  }

  private async acceptTextMessage(
    conversationId: string,
    payload: Extract<AppPayload, { kind: 'text' }>,
    sender: PeerAddress,
    via: TransportKind,
  ): Promise<void> {
    const session = await this.options.repository.getSessionState(conversationId);
    const senderKey = addressKey(sender);

    // Application-level duplicate suppression. MLS already rejects replayed
    // ciphertext; this additionally catches a sender that re-encrypts the same
    // logical message (e.g. after a transport retry) under a fresh key.
    if (session.recentMessageIds.includes(payload.id)) {
      this.logger.debug('ignored a duplicate message id', { conversationId });
      return;
    }
    const lastSeq = session.inboundSeq[senderKey];
    if (lastSeq !== undefined && payload.seq <= lastSeq) {
      this.logger.warn('ignored an out-of-order or replayed sequence number', {
        conversationId,
        peerDeviceId: sender.deviceId,
      });
      return;
    }

    let epoch: string | null = null;
    try {
      epoch = (await this.options.engine.epoch(conversationId)).toString();
    } catch {
      /* informational */
    }

    const trust = this.options.trustStore.get(sender)?.state ?? 'unverified';
    const receivedAt = this.now();
    const stored: StoredMessage = {
      id: payload.id,
      conversationId,
      senderUserId: sender.userId,
      senderDeviceId: sender.deviceId,
      outgoing: false,
      body: payload.body,
      attachments: payload.attachments ?? [],
      sentAt: payload.sentAt,
      receivedAt,
      status: 'delivered',
      transport: via === 'relay' ? 'relay' : 'p2p',
      epoch,
      senderTrustAtReceipt: trust,
    };

    await this.options.repository.appendMessage(stored);
    await this.options.repository.saveSessionState({
      ...session,
      inboundSeq: { ...session.inboundSeq, [senderKey]: payload.seq },
      recentMessageIds: [...session.recentMessageIds, payload.id],
    });

    const conversation = await this.options.repository.getConversation(conversationId);
    if (conversation) {
      const updated: Conversation = {
        ...conversation,
        lastActivityAt: receivedAt,
        lastMessagePreview: payload.body || attachmentPreview(stored.attachments),
        unreadCount: conversation.unreadCount + 1,
      };
      await this.options.repository.saveConversation(updated);
      this.onConversationUpdated.emit(updated);
    }

    this.onMessage.emit(stored);
    void this.sendControl(conversationId, { kind: 'delivered', ids: [payload.id], at: this.now() });
  }

  private async applyReceipts(
    conversationId: string,
    ids: string[],
    status: DeliveryStatus,
  ): Promise<void> {
    for (const id of ids) {
      const updated = await this.patchMessage(conversationId, id, { status });
      if (updated) this.onMessageUpdated.emit(updated);
    }
  }

  private async patchMessage(
    conversationId: string,
    messageId: string,
    patch: Partial<StoredMessage>,
  ): Promise<StoredMessage | undefined> {
    const updated = await this.options.repository.updateMessage(conversationId, messageId, patch);
    if (updated) this.onMessageUpdated.emit(updated);
    return updated;
  }

  /**
   * Send a non-user-visible control payload through the same encrypted channel.
   *
   * Receipts and typing indicators are held by the same identity-change block
   * as ordinary messages. A delivery receipt sent to a device whose key just
   * changed would confirm to a possible man-in-the-middle that their message
   * landed, which is exactly the signal the block exists to withhold.
   */
  private async sendControl(conversationId: string, payload: AppPayload): Promise<void> {
    const members = this.routing.get(conversationId) ?? [];
    if (members.length === 0) return;

    const blockOnChange = this.options.settings().blockOnIdentityChange;
    if (members.some((member) => this.options.trustStore.isSendBlocked(member, blockOnChange))) {
      this.logger.debug('withheld a control message from a changed identity', { conversationId });
      return;
    }

    try {
      const ciphertext = await this.options.engine.encrypt(
        conversationId,
        utf8Encode(JSON.stringify(payload)),
      );
      const frame: TransportFrame = {
        v: 1,
        type: 'mls-app',
        conversationId,
        payload: toBase64(ciphertext),
      };
      for (const member of members) {
        await this.sendFrame(member, frame).catch(() => undefined);
      }
    } catch {
      // Receipts are best-effort; failing to send one must never surface as a
      // message failure to the user.
    }
  }

  // -- attachments ----------------------------------------------------------

  /** Fetch and decrypt an attachment referenced by a received message. */
  async fetchAttachment(descriptor: AttachmentDescriptor): Promise<Uint8Array> {
    const ciphertext = await this.options.api.downloadBlob(descriptor.blobId);
    return decryptAttachment(ciphertext, descriptor);
  }

  // -- session maintenance --------------------------------------------------

  async markConversationRead(conversationId: string): Promise<void> {
    const conversation = await this.options.repository.getConversation(conversationId);
    if (!conversation) return;
    if (conversation.unreadCount !== 0) {
      const updated = { ...conversation, unreadCount: 0 };
      await this.options.repository.saveConversation(updated);
      this.onConversationUpdated.emit(updated);
    }

    if (!this.options.settings().sendReadReceipts) return;
    const messages = await this.options.repository.listMessages(conversationId, 100);
    const ids = messages.filter((m) => !m.outgoing).map((m) => m.id);
    if (ids.length > 0) {
      await this.sendControl(conversationId, { kind: 'read', ids, at: this.now() });
    }
  }

  async sendTyping(conversationId: string, active: boolean): Promise<void> {
    if (!this.options.settings().sendTypingIndicators) return;
    await this.sendControl(conversationId, { kind: 'typing', active, at: this.now() });
  }

  /**
   * Rotate group keys once the message or time budget is exhausted.
   *
   * This is MLS's post-compromise security mechanism: after a self-update
   * commit, an attacker holding the previous epoch's secrets can no longer
   * read new traffic.
   */
  async maybeRotateKeys(conversationId: string): Promise<void> {
    const session = await this.options.repository.getSessionState(conversationId);
    const dueByCount = session.messagesSinceRekey >= REKEY_AFTER_MESSAGES;
    const dueByTime = this.now() - session.lastRekeyAt >= REKEY_AFTER_MS;
    if (!dueByCount && !dueByTime) return;
    await this.rotateKeys(conversationId);
  }

  async rotateKeys(conversationId: string): Promise<void> {
    try {
      await this.options.engine.rotateKeys(conversationId);
      const session = await this.options.repository.getSessionState(conversationId);
      await this.options.repository.saveSessionState({
        ...session,
        messagesSinceRekey: 0,
        lastRekeyAt: this.now(),
      });
      const epoch = await this.options.engine.epoch(conversationId);
      await this.sendControl(conversationId, {
        kind: 'rekey-notice',
        epoch: epoch.toString(),
        at: this.now(),
      });
    } catch (error) {
      this.logger.warn('key rotation failed; will retry on the next message', {
        conversationId,
        code: error instanceof MlsEngineError ? error.code : 'unknown',
      });
    }
  }

  /**
   * Leave a conversation and destroy its local key material.
   *
   * Removing ourselves first tells the peer the session is over; wiping
   * afterwards means the epoch secrets are gone from this device.
   */
  async leaveConversation(conversationId: string): Promise<void> {
    try {
      await this.options.engine.removeMembers(conversationId, [
        { userId: this.options.self.userId, deviceId: this.options.self.deviceId },
      ]);
    } catch {
      // We may already be removed; wiping locally is still correct.
    }
    await this.options.engine.wipeConversation(conversationId).catch(() => undefined);
    this.routing.delete(conversationId);

    const conversation = await this.options.repository.getConversation(conversationId);
    if (conversation) {
      const updated = { ...conversation, active: false };
      await this.options.repository.saveConversation(updated);
      this.onConversationUpdated.emit(updated);
    }
    this.logger.info('left conversation', { conversationId });
  }

  /** Peers currently routed for a conversation, for the UI's status display. */
  membersFor(conversationId: string): PeerAddress[] {
    return this.routing.get(conversationId) ?? [];
  }

  private async touchConversation(conversation: Conversation, preview: string): Promise<void> {
    const updated: Conversation = {
      ...conversation,
      lastActivityAt: this.now(),
      lastMessagePreview: preview,
    };
    await this.options.repository.saveConversation(updated);
    this.onConversationUpdated.emit(updated);
  }
}

function addressKey(address: PeerAddress): string {
  return `${address.userId}:${address.deviceId}`;
}

function attachmentPreview(attachments: AttachmentDescriptor[]): string {
  if (attachments.length === 0) return '';
  if (attachments.length === 1) return `📎 ${attachments[0]!.filename}`;
  return `📎 ${attachments.length} attachments`;
}
