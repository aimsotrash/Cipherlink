/**
 * Application record types persisted in the encrypted store.
 *
 * Every one of these is written through {@link EncryptedStore}, so message
 * bodies, contact names and trust state are ciphertext on disk.
 */
import type { AttachmentDescriptor } from '@p2pchat/shared';
import type { TrustState } from '../identity/trustStore.js';

export type DeliveryStatus =
  | 'pending' // queued locally, not yet handed to a transport
  | 'sent' // handed to the peer connection or the relay
  | 'delivered' // peer's client acknowledged decryption
  | 'read' // peer's user opened it (only if they send read receipts)
  | 'failed'; // could not be encrypted or transmitted

export type TransportUsed = 'p2p' | 'relay' | 'pending';

export interface StoredMessage {
  readonly id: string;
  readonly conversationId: string;
  readonly senderUserId: string;
  readonly senderDeviceId: string;
  readonly outgoing: boolean;
  readonly body: string;
  readonly attachments: AttachmentDescriptor[];
  /** Sender's clock; display only. */
  readonly sentAt: number;
  /** Our clock when we stored it; used for ordering. */
  readonly receivedAt: number;
  readonly status: DeliveryStatus;
  readonly transport: TransportUsed;
  /** MLS epoch the message was encrypted in — shown in message details. */
  readonly epoch: string | null;
  /**
   * Trust state of the sending device at the moment the message was accepted.
   * Frozen so history cannot be retroactively relabelled as trustworthy.
   */
  readonly senderTrustAtReceipt: TrustState | null;
}

export interface Conversation {
  readonly id: string;
  /** The other account in a 1:1 conversation. */
  readonly peerUserId: string;
  readonly peerUsername: string;
  readonly createdAt: number;
  readonly lastActivityAt: number;
  readonly lastMessagePreview: string;
  readonly unreadCount: number;
  /** False once we leave or are removed; kept for history. */
  readonly active: boolean;
}

export interface Contact {
  readonly userId: string;
  readonly username: string;
  readonly addedAt: number;
  readonly deviceIds: string[];
  /** Device names from the directory, as their owner chose them. Absent in older records. */
  readonly deviceLabels?: Record<string, string>;
}

/** Per-conversation protocol bookkeeping. */
export interface SessionState {
  readonly conversationId: string;
  /** Next outbound application sequence number. */
  readonly nextSeq: number;
  /** Highest inbound sequence number seen per sending device. */
  readonly inboundSeq: Record<string, number>;
  readonly messagesSinceRekey: number;
  readonly lastRekeyAt: number;
  /** Recently seen message ids, for cheap duplicate suppression. */
  readonly recentMessageIds: string[];
}

export interface AppSettings {
  readonly sendReadReceipts: boolean;
  readonly sendTypingIndicators: boolean;
  /** Hold messages to a contact whose identity key changed until acknowledged. */
  readonly blockOnIdentityChange: boolean;
  /** Allow falling back to the server relay when direct P2P fails. */
  readonly allowRelayFallback: boolean;
  /**
   * Require a direct peer connection, refusing TURN. Hides your IP from the
   * peer less, but avoids routing through the operator's relay.
   */
  readonly preferDirectOnly: boolean;
  /** Lock the vault after this many minutes idle. 0 disables auto-lock. */
  readonly autoLockMinutes: number;
  readonly theme: 'dark' | 'light';
}

export const DEFAULT_SETTINGS: AppSettings = {
  sendReadReceipts: false,
  sendTypingIndicators: false,
  blockOnIdentityChange: true,
  allowRelayFallback: true,
  preferDirectOnly: false,
  autoLockMinutes: 15,
  theme: 'dark',
};

/** Non-secret registration facts, needed before the vault is unlocked. */
export interface AccountProfile {
  readonly userId: string;
  readonly deviceId: string;
  readonly username: string;
  readonly deviceLabel: string;
  readonly registeredAt: number;
}
