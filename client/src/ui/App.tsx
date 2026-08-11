/**
 * Application shell: routes between onboarding, unlock and the chat layout.
 */
import { useEffect, useState } from 'react';
import { useSession } from './SessionContext.js';
import { RegistrationScreen, UnlockScreen } from './screens/Onboarding.js';
import { ChatScreen } from './screens/ChatScreen.js';
import { VerificationModal } from './screens/VerificationModal.js';
import { SettingsModal } from './screens/SettingsModal.js';
import { SignalingBadge, TrustBadge } from './components/Badges.js';
import type { Conversation } from '../storage/models.js';

export function App(): JSX.Element {
  const { phase, settings } = useSession();

  useEffect(() => {
    if (settings) document.documentElement.dataset.theme = settings.theme;
  }, [settings]);

  switch (phase) {
    case 'loading':
      return (
        <div className="centered-screen">
          <div className="spinner" aria-label="Loading" />
        </div>
      );
    case 'needs-registration':
      return <RegistrationScreen />;
    case 'locked':
      return <UnlockScreen />;
    case 'ready':
      return <ChatLayout />;
  }
}

function ChatLayout(): JSX.Element {
  const {
    conversations,
    ready,
    signalingState,
    identityAlerts,
    dismissAlert,
    startConversation,
    lock,
    trustFor,
  } = useSession();
  const [activeId, setActiveId] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showVerification, setShowVerification] = useState(false);
  const [showNewChat, setShowNewChat] = useState(false);

  const active = conversations.find((conversation) => conversation.id === activeId) ?? null;

  return (
    <div className="app-shell" data-mobile-view={active ? 'chat' : 'list'}>
      <aside className="sidebar">
        <header className="sidebar-header">
          <div className="brand">
            <span className="brand-name">Cipherlink</span>
            <span className="brand-user">
              {ready?.profile.username} · {ready?.profile.deviceLabel}
            </span>
          </div>
          <div className="icon-row">
            <button
              className="icon-button"
              onClick={() => setShowNewChat(true)}
              title="New conversation"
              aria-label="New conversation"
            >
              ＋
            </button>
            <button
              className="icon-button"
              onClick={() => setShowSettings(true)}
              title="Settings"
              aria-label="Settings"
            >
              ⚙
            </button>
            <button
              className="icon-button"
              onClick={() => void lock()}
              title="Lock now"
              aria-label="Lock now"
            >
              🔒
            </button>
          </div>
        </header>

        <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)' }}>
          <SignalingBadge state={signalingState} />
        </div>

        <nav className="conversation-list" aria-label="Conversations">
          {conversations.length === 0 && (
            <p style={{ padding: 16, color: 'var(--text-faint)', fontSize: 13 }}>
              No conversations yet. Use ＋ to start one with someone&rsquo;s username.
            </p>
          )}
          {conversations.map((conversation) => (
            <ConversationRow
              key={conversation.id}
              conversation={conversation}
              active={conversation.id === activeId}
              trust={trustFor(conversation.peerUserId)}
              onSelect={() => setActiveId(conversation.id)}
            />
          ))}
        </nav>
      </aside>

      {active ? (
        <ChatScreen
          conversation={active}
          onOpenVerification={() => setShowVerification(true)}
          onBack={() => setActiveId(null)}
        />
      ) : (
        <div className="chat-pane">
          <div className="empty-state">
            <div className="empty-state-inner">
              <h2 style={{ marginBottom: 6 }}>Select a conversation</h2>
              <p style={{ fontSize: 14 }}>
                Messages are encrypted on this device before they are sent, and decrypted on your
                contact&rsquo;s device. The server carries data it cannot read.
              </p>
            </div>
          </div>
        </div>
      )}

      {showNewChat && (
        <NewConversationModal
          onClose={() => setShowNewChat(false)}
          onCreated={(conversation) => {
            setActiveId(conversation.id);
            setShowNewChat(false);
          }}
          onStart={startConversation}
        />
      )}
      {showSettings && <SettingsModal onClose={() => setShowSettings(false)} />}
      {showVerification && active && (
        <VerificationModal conversation={active} onClose={() => setShowVerification(false)} />
      )}

      {identityAlerts.length > 0 && (
        <div className="alert-stack" role="alert">
          {identityAlerts.map((alert) => (
            <div className="alert" key={alert.id}>
              <button
                className="alert-close"
                onClick={() => dismissAlert(alert.id)}
                aria-label="Dismiss"
              >
                ✕
              </button>
              <strong>Security code changed</strong>
              A device belonging to one of your contacts is now using a different identity key
              {alert.wasVerified ? ', and you had previously verified it' : ''}. Open the
              conversation and compare safety numbers before sending anything sensitive.
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ConversationRow({
  conversation,
  active,
  trust,
  onSelect,
}: {
  conversation: Conversation;
  active: boolean;
  trust: ReturnType<typeof useSession>['trustFor'] extends (u: string) => infer R ? R : never;
  onSelect: () => void;
}): JSX.Element {
  return (
    <button className="conversation-item" aria-current={active} onClick={onSelect}>
      <span className="avatar" aria-hidden="true">
        {conversation.peerUsername.slice(0, 2).toUpperCase()}
      </span>
      <span className="conversation-main">
        <span className="conversation-title">
          {conversation.peerUsername}
          {trust === 'verified' && (
            <span title="Verified" style={{ color: 'var(--ok)' }}>
              ✓
            </span>
          )}
          {trust === 'changed' && (
            <span title="Security code changed" style={{ color: 'var(--danger)' }}>
              ⚠
            </span>
          )}
        </span>
        <span className="conversation-preview">
          {conversation.lastMessagePreview || 'No messages yet'}
        </span>
      </span>
      <span className="conversation-meta">
        <span>{formatRelative(conversation.lastActivityAt)}</span>
        {conversation.unreadCount > 0 && (
          <span className="unread-badge">{conversation.unreadCount}</span>
        )}
      </span>
    </button>
  );
}

function NewConversationModal({
  onClose,
  onCreated,
  onStart,
}: {
  onClose: () => void;
  onCreated: (conversation: Conversation) => void;
  onStart: (username: string) => Promise<Conversation>;
}): JSX.Element {
  const [username, setUsername] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      onCreated(await onStart(username.trim().toLowerCase()));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not start that conversation.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="New conversation">
      <div className="modal">
        <h2>New conversation</h2>
        <p className="lede">
          Enter the username you want to message. Their key material is fetched from the directory —
          confirm the safety number with them afterwards to be certain it is really them.
        </p>
        {error && <p className="form-error">{error}</p>}
        <label className="field">
          <span>Username</span>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoFocus
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>
        <div className="modal-actions">
          <button className="secondary-button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="primary-button"
            style={{ width: 'auto' }}
            disabled={busy || username.trim().length < 3}
            onClick={() => void submit()}
          >
            {busy ? 'Setting up…' : 'Start'}
          </button>
        </div>
      </div>
    </div>
  );
}

function formatRelative(timestamp: number): string {
  const delta = Date.now() - timestamp;
  if (delta < 60_000) return 'now';
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h`;
  if (delta < 7 * 86_400_000) return `${Math.floor(delta / 86_400_000)}d`;
  return new Date(timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export { TrustBadge };
