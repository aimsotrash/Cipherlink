/**
 * Typed repositories over the encrypted record store.
 *
 * Key namespaces are chosen so that `keys(prefix)` gives useful ordering
 * without an index: message keys embed a zero-padded timestamp, so listing a
 * conversation returns messages in chronological order straight from the
 * backend.
 */
import { EncryptedStore } from './encryptedStore.js';
import type {
  AccountProfile,
  AppSettings,
  Contact,
  Conversation,
  SessionState,
  StoredMessage,
} from './models.js';
import { DEFAULT_SETTINGS } from './models.js';
import type { IdentityRecord, TrustPersistence } from '../identity/trustStore.js';

const KEYS = {
  conversation: (id: string) => `conv/${id}`,
  conversationPrefix: 'conv/',
  message: (conversationId: string, receivedAt: number, id: string) =>
    `msg/${conversationId}/${String(receivedAt).padStart(16, '0')}/${id}`,
  messagePrefix: (conversationId: string) => `msg/${conversationId}/`,
  contact: (userId: string) => `contact/${userId}`,
  contactPrefix: 'contact/',
  identity: (key: string) => `identity/${key}`,
  identityPrefix: 'identity/',
  session: (conversationId: string) => `session/${conversationId}`,
  settings: 'settings',
  profile: 'profile',
} as const;

/** Number of recent message ids retained per session for duplicate suppression. */
const RECENT_ID_WINDOW = 512;

export class Repository {
  constructor(private readonly store: EncryptedStore) {}

  // -- conversations --------------------------------------------------------

  async listConversations(): Promise<Conversation[]> {
    const conversations = await this.store.list<Conversation>(KEYS.conversationPrefix);
    return conversations.sort((a, b) => b.lastActivityAt - a.lastActivityAt);
  }

  async getConversation(id: string): Promise<Conversation | undefined> {
    return this.store.get<Conversation>(KEYS.conversation(id));
  }

  async saveConversation(conversation: Conversation): Promise<void> {
    await this.store.put(KEYS.conversation(conversation.id), conversation);
  }

  async deleteConversation(id: string): Promise<void> {
    for (const key of await this.store.keys(KEYS.messagePrefix(id))) {
      await this.store.delete(key);
    }
    await this.store.delete(KEYS.conversation(id));
    await this.store.delete(KEYS.session(id));
  }

  // -- messages -------------------------------------------------------------

  async appendMessage(message: StoredMessage): Promise<void> {
    await this.store.put(
      KEYS.message(message.conversationId, message.receivedAt, message.id),
      message,
    );
  }

  async listMessages(conversationId: string, limit = 500): Promise<StoredMessage[]> {
    const keys = await this.store.keys(KEYS.messagePrefix(conversationId));
    const slice = keys.slice(-limit);
    const messages: StoredMessage[] = [];
    for (const key of slice) {
      const message = await this.store.get<StoredMessage>(key);
      if (message) messages.push(message);
    }
    return messages;
  }

  /**
   * Update a stored message in place. Messages are keyed by receipt time, so
   * we locate the existing key rather than assuming we can recompute it.
   */
  async updateMessage(
    conversationId: string,
    messageId: string,
    patch: Partial<StoredMessage>,
  ): Promise<StoredMessage | undefined> {
    const keys = await this.store.keys(KEYS.messagePrefix(conversationId));
    const match = keys.find((key) => key.endsWith(`/${messageId}`));
    if (!match) return undefined;
    const existing = await this.store.get<StoredMessage>(match);
    if (!existing) return undefined;
    const updated: StoredMessage = { ...existing, ...patch };
    await this.store.put(match, updated);
    return updated;
  }

  // -- contacts -------------------------------------------------------------

  async listContacts(): Promise<Contact[]> {
    const contacts = await this.store.list<Contact>(KEYS.contactPrefix);
    return contacts.sort((a, b) => a.username.localeCompare(b.username));
  }

  async getContact(userId: string): Promise<Contact | undefined> {
    return this.store.get<Contact>(KEYS.contact(userId));
  }

  async saveContact(contact: Contact): Promise<void> {
    await this.store.put(KEYS.contact(contact.userId), contact);
  }

  async deleteContact(userId: string): Promise<void> {
    await this.store.delete(KEYS.contact(userId));
  }

  // -- session bookkeeping --------------------------------------------------

  async getSessionState(conversationId: string): Promise<SessionState> {
    const existing = await this.store.get<SessionState>(KEYS.session(conversationId));
    return (
      existing ?? {
        conversationId,
        nextSeq: 0,
        inboundSeq: {},
        messagesSinceRekey: 0,
        lastRekeyAt: Date.now(),
        recentMessageIds: [],
      }
    );
  }

  async saveSessionState(state: SessionState): Promise<void> {
    // Bound the replay-suppression window so the record cannot grow forever.
    const trimmed: SessionState = {
      ...state,
      recentMessageIds: state.recentMessageIds.slice(-RECENT_ID_WINDOW),
    };
    await this.store.put(KEYS.session(state.conversationId), trimmed);
  }

  // -- settings & profile ---------------------------------------------------

  async getSettings(): Promise<AppSettings> {
    const stored = await this.store.get<Partial<AppSettings>>(KEYS.settings);
    return { ...DEFAULT_SETTINGS, ...(stored ?? {}) };
  }

  async saveSettings(settings: AppSettings): Promise<void> {
    await this.store.put(KEYS.settings, settings);
  }

  async getProfile(): Promise<AccountProfile | undefined> {
    return this.store.get<AccountProfile>(KEYS.profile);
  }

  async saveProfile(profile: AccountProfile): Promise<void> {
    await this.store.put(KEYS.profile, profile);
  }

  /** Raw byte access, for the device authentication private key. */
  async getSecretBytes(name: string): Promise<Uint8Array | undefined> {
    return this.store.getRaw(`secret/${name}`);
  }

  async saveSecretBytes(name: string, bytes: Uint8Array): Promise<void> {
    await this.store.putRaw(`secret/${name}`, bytes);
  }

  /** Trust-store persistence backed by the same encrypted store. */
  trustPersistence(): TrustPersistence {
    const store = this.store;
    return {
      async loadAll(): Promise<IdentityRecord[]> {
        return store.list<IdentityRecord>(KEYS.identityPrefix);
      },
      async save(record: IdentityRecord): Promise<void> {
        await store.put(KEYS.identity(`${record.userId}:${record.deviceId}`), record);
      },
      async remove(key: string): Promise<void> {
        await store.delete(KEYS.identity(key));
      },
    };
  }

  /** Wipe every local record. Used by "delete all data" in security settings. */
  async wipeEverything(): Promise<void> {
    await this.store.clear();
  }
}
