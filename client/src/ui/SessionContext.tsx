/**
 * React binding for {@link AppSession}.
 *
 * Holds the live session plus the reactive slices the UI renders from:
 * conversations, messages, per-peer connection status and identity-change
 * alerts. All of it is derived from the encrypted repository and the transport
 * layer; this file never touches keys directly.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { createLogger, type PeerAddress } from '@p2pchat/shared';
import {
  AppSession,
  type ReadySession,
  type SessionConfig,
  type SessionPhase,
} from '../app/session.js';
import type { AppSettings, Conversation, StoredMessage } from '../storage/models.js';
import type { IdentityChangeEvent, TrustState } from '../identity/trustStore.js';
import type { PeerLinkStatus } from '../p2p/types.js';
import type { SignalingState } from '../p2p/signalingClient.js';

export interface IdentityAlert extends IdentityChangeEvent {
  readonly id: string;
}

interface SessionContextValue {
  readonly phase: SessionPhase;
  readonly ready: ReadySession | null;
  readonly settings: AppSettings | null;
  readonly conversations: Conversation[];
  readonly messages: Record<string, StoredMessage[]>;
  readonly peerStatuses: Record<string, PeerLinkStatus>;
  readonly signalingState: SignalingState;
  readonly identityAlerts: IdentityAlert[];
  readonly busy: boolean;
  register(params: {
    username: string;
    passphrase: string;
    deviceLabel: string;
    additionalDevice?: boolean;
  }): Promise<void>;
  unlock(passphrase: string): Promise<void>;
  lock(): Promise<void>;
  destroyLocalData(): Promise<void>;
  startConversation(username: string): Promise<Conversation>;
  loadMessages(conversationId: string): Promise<void>;
  sendMessage(
    conversationId: string,
    body: string,
    files: File[],
  ): Promise<void>;
  markRead(conversationId: string): Promise<void>;
  leaveConversation(conversationId: string): Promise<void>;
  rotateKeys(conversationId: string): Promise<void>;
  updateSettings(patch: Partial<AppSettings>): Promise<void>;
  changePassphrase(current: string, next: string): Promise<void>;
  trustFor(userId: string): TrustState;
  dismissAlert(id: string): void;
  refreshConversations(): Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error('useSession must be used inside a SessionProvider');
  return value;
}

export function SessionProvider({
  config,
  children,
}: {
  config: SessionConfig;
  children: ReactNode;
}): JSX.Element {
  const [session, setSession] = useState<AppSession | null>(null);
  const [phase, setPhase] = useState<SessionPhase>('loading');
  const [ready, setReady] = useState<ReadySession | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [messages, setMessages] = useState<Record<string, StoredMessage[]>>({});
  const [peerStatuses, setPeerStatuses] = useState<Record<string, PeerLinkStatus>>({});
  const [signalingState, setSignalingState] = useState<SignalingState>('closed');
  const [identityAlerts, setIdentityAlerts] = useState<IdentityAlert[]>([]);
  const [busy, setBusy] = useState(false);
  const [trustVersion, setTrustVersion] = useState(0);
  const logger = useMemo(() => config.logger ?? createLogger('ui', { level: 'warn' }), [config]);

  useEffect(() => {
    let cancelled = false;
    void AppSession.bootstrap({ ...config, logger }).then((instance) => {
      if (cancelled) return;
      setSession(instance);
      setPhase(instance.currentPhase);
    });
    return () => {
      cancelled = true;
    };
  }, [config, logger]);

  /** Attach listeners to a freshly activated session. */
  const attach = useCallback((instance: AppSession, active: ReadySession) => {
    setReady(active);
    setSettings(instance.currentSettings);
    setPhase('ready');

    active.messaging.onMessage.subscribe((message) => {
      setMessages((previous) => {
        const existing = previous[message.conversationId] ?? [];
        if (existing.some((m) => m.id === message.id)) return previous;
        return {
          ...previous,
          [message.conversationId]: [...existing, message].sort(
            (a, b) => a.receivedAt - b.receivedAt,
          ),
        };
      });
    });

    active.messaging.onMessageUpdated.subscribe((message) => {
      setMessages((previous) => {
        const existing = previous[message.conversationId];
        if (!existing) return previous;
        return {
          ...previous,
          [message.conversationId]: existing.map((m) => (m.id === message.id ? message : m)),
        };
      });
    });

    active.messaging.onConversationUpdated.subscribe((conversation) => {
      setConversations((previous) => {
        const next = previous.filter((c) => c.id !== conversation.id);
        next.push(conversation);
        return next.sort((a, b) => b.lastActivityAt - a.lastActivityAt);
      });
    });

    active.messaging.onIdentityChange.subscribe((event) => {
      setTrustVersion((v) => v + 1);
      setIdentityAlerts((previous) => [
        ...previous,
        { ...event, id: `${event.address.userId}:${event.address.deviceId}:${event.at}` },
      ]);
    });

    active.transport.onStatus.subscribe((status) => {
      setPeerStatuses((previous) => ({
        ...previous,
        [`${status.peer.userId}:${status.peer.deviceId}`]: status,
      }));
    });

    active.signaling.onState.subscribe(setSignalingState);
    setSignalingState(active.signaling.currentState);

    void active.repository.listConversations().then(setConversations);
  }, []);

  const register = useCallback<SessionContextValue['register']>(
    async (params) => {
      if (!session) return;
      setBusy(true);
      try {
        const active = await session.register(params);
        attach(session, active);
      } finally {
        setBusy(false);
      }
    },
    [session, attach],
  );

  const unlock = useCallback<SessionContextValue['unlock']>(
    async (passphrase) => {
      if (!session) return;
      setBusy(true);
      try {
        const active = await session.unlock(passphrase);
        attach(session, active);
      } finally {
        setBusy(false);
      }
    },
    [session, attach],
  );

  const lock = useCallback(async () => {
    if (!session) return;
    await session.lock();
    setReady(null);
    setConversations([]);
    setMessages({});
    setPeerStatuses({});
    setPhase(session.currentPhase);
  }, [session]);

  const destroyLocalData = useCallback(async () => {
    if (!session) return;
    await session.destroyLocalData();
    // The databases are deleted on the fresh load (see AppSession.bootstrap),
    // which also drops any key material still held in this page's memory.
    window.location.reload();
  }, [session]);

  const refreshConversations = useCallback(async () => {
    if (!ready) return;
    setConversations(await ready.repository.listConversations());
  }, [ready]);

  const loadMessages = useCallback(
    async (conversationId: string) => {
      if (!ready) return;
      const stored = await ready.repository.listMessages(conversationId);
      setMessages((previous) => ({ ...previous, [conversationId]: stored }));
    },
    [ready],
  );

  const startConversation = useCallback(
    async (username: string) => {
      if (!ready) throw new Error('session is not ready');
      setBusy(true);
      try {
        const conversation = await ready.messaging.startConversation(username);
        await refreshConversations();
        setTrustVersion((v) => v + 1);
        return conversation;
      } finally {
        setBusy(false);
      }
    },
    [ready, refreshConversations],
  );

  const sendMessage = useCallback(
    async (conversationId: string, body: string, files: File[]) => {
      if (!ready) return;
      const attachments = await Promise.all(
        files.map(async (file) => ({
          data: new Uint8Array(await file.arrayBuffer()),
          filename: file.name,
          mimeType: file.type || 'application/octet-stream',
        })),
      );
      await ready.messaging.sendText(conversationId, body, attachments);
    },
    [ready],
  );

  const markRead = useCallback(
    async (conversationId: string) => {
      await ready?.messaging.markConversationRead(conversationId);
    },
    [ready],
  );

  const leaveConversation = useCallback(
    async (conversationId: string) => {
      await ready?.messaging.leaveConversation(conversationId);
      await refreshConversations();
    },
    [ready, refreshConversations],
  );

  const rotateKeys = useCallback(
    async (conversationId: string) => {
      await ready?.messaging.rotateKeys(conversationId);
    },
    [ready],
  );

  const updateSettings = useCallback(
    async (patch: Partial<AppSettings>) => {
      if (!session) return;
      setSettings(await session.updateSettings(patch));
    },
    [session],
  );

  const changePassphrase = useCallback(
    async (current: string, next: string) => {
      if (!session) return;
      await session.changePassphrase(current, next);
    },
    [session],
  );

  const trustFor = useCallback(
    (userId: string): TrustState => {
      void trustVersion; // re-evaluate when trust state changes
      return ready?.trustStore.summaryForUser(userId) ?? 'unverified';
    },
    [ready, trustVersion],
  );

  const dismissAlert = useCallback((id: string) => {
    setIdentityAlerts((previous) => previous.filter((alert) => alert.id !== id));
  }, []);

  // Idle auto-lock: any interaction restarts the countdown.
  const sessionRef = useRef(session);
  sessionRef.current = session;
  useEffect(() => {
    if (phase !== 'ready') return undefined;
    const note = (): void => sessionRef.current?.noteActivity();
    const events = ['pointerdown', 'keydown', 'visibilitychange'] as const;
    for (const event of events) window.addEventListener(event, note);
    return () => {
      for (const event of events) window.removeEventListener(event, note);
    };
  }, [phase]);

  // Reflect a lock that the session performed on its own (idle timeout).
  useEffect(() => {
    if (phase !== 'ready' || !session) return undefined;
    const timer = setInterval(() => {
      if (session.currentPhase !== 'ready') {
        setReady(null);
        setPhase(session.currentPhase);
      }
    }, 5000);
    return () => clearInterval(timer);
  }, [phase, session]);

  const value: SessionContextValue = {
    phase,
    ready,
    settings,
    conversations,
    messages,
    peerStatuses,
    signalingState,
    identityAlerts,
    busy,
    register,
    unlock,
    lock,
    destroyLocalData,
    startConversation,
    loadMessages,
    sendMessage,
    markRead,
    leaveConversation,
    rotateKeys,
    updateSettings,
    changePassphrase,
    trustFor,
    dismissAlert,
    refreshConversations,
  };

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export type { PeerAddress };
