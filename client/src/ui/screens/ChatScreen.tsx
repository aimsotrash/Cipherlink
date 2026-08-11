/**
 * Conversation view: header with security state, message list, composer.
 */
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { AttachmentDescriptor } from '@p2pchat/shared';
import { useSession } from '../SessionContext.js';
import {
  ConnectionBadge,
  DeliveryIndicator,
  EncryptionBadge,
  TrustBadge,
} from '../components/Badges.js';
import type { Conversation, StoredMessage } from '../../storage/models.js';

export function ChatScreen({
  conversation,
  onOpenVerification,
  onBack,
}: {
  conversation: Conversation;
  onOpenVerification: () => void;
  onBack: () => void;
}): JSX.Element {
  const { messages, loadMessages, sendMessage, markRead, peerStatuses, ready, trustFor, rotateKeys } =
    useSession();
  const [draft, setDraft] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const conversationMessages = messages[conversation.id] ?? [];
  const trust = trustFor(conversation.peerUserId);

  useEffect(() => {
    void loadMessages(conversation.id);
    void markRead(conversation.id);
  }, [conversation.id, loadMessages, markRead]);

  useEffect(() => {
    const element = scrollRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [conversationMessages.length]);

  // A 1:1 conversation can span several of the peer's devices; show the
  // healthiest link rather than an arbitrary one.
  const peerStatus = useMemo(() => {
    const members = ready?.messaging.membersFor(conversation.id) ?? [];
    const statuses = members
      .map((member) => peerStatuses[`${member.userId}:${member.deviceId}`])
      .filter((status): status is NonNullable<typeof status> => Boolean(status));
    const rank = { connected: 0, 'relay-only': 1, connecting: 2, reconnecting: 3, idle: 4, failed: 5, closed: 6 };
    return statuses.sort((a, b) => rank[a.state] - rank[b.state])[0];
  }, [ready, conversation.id, peerStatuses]);

  const submit = async (): Promise<void> => {
    const body = draft.trim();
    if (!body && files.length === 0) return;
    setSending(true);
    setError(null);
    try {
      await sendMessage(conversation.id, body, files);
      setDraft('');
      setFiles([]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not send that message.');
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>): void => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void submit();
    }
  };

  return (
    <section className="chat-pane">
      <header className="chat-header">
        <button
          className="icon-button"
          onClick={onBack}
          aria-label="Back to conversations"
          style={{ display: 'none' }}
          data-mobile-back
        >
          ←
        </button>
        <div className="avatar" aria-hidden="true">
          {conversation.peerUsername.slice(0, 2).toUpperCase()}
        </div>
        <div className="chat-header-main">
          <div className="chat-title">{conversation.peerUsername}</div>
          <div className="chat-subtitle">
            <EncryptionBadge />
            <TrustBadge state={trust} />
            {peerStatus && (
              <ConnectionBadge state={peerStatus.state} transport={peerStatus.transport} />
            )}
          </div>
        </div>
        <div className="icon-row">
          <button
            className="icon-button"
            onClick={() => void rotateKeys(conversation.id)}
            title="Rotate the encryption keys for this conversation now. New keys mean anything an attacker may have captured before cannot decrypt what comes next."
            aria-label="Rotate keys"
          >
            ⟳
          </button>
          <button
            className="icon-button"
            onClick={onOpenVerification}
            title="Verify safety number"
            aria-label="Verify safety number"
          >
            🛡
          </button>
        </div>
      </header>

      {trust === 'changed' && (
        <div style={{ padding: '10px 16px 0' }}>
          <div className="notice" data-tone="danger">
            <strong>{conversation.peerUsername}&rsquo;s security code has changed.</strong> This
            happens when they reinstall the app or switch devices — and it is also what an
            interception attempt looks like. Messages are held until you review it.{' '}
            <button className="link-button" onClick={onOpenVerification}>
              Review now
            </button>
          </div>
        </div>
      )}

      <div className="message-scroll" ref={scrollRef}>
        {conversationMessages.length === 0 && (
          <div className="empty-state">
            <div className="empty-state-inner">
              <p>No messages yet.</p>
              <p style={{ fontSize: 13 }}>
                Everything you send is encrypted on this device first. Before trusting this
                conversation with anything sensitive, compare safety numbers with{' '}
                {conversation.peerUsername}.
              </p>
            </div>
          </div>
        )}
        {conversationMessages.map((message, index) => (
          <MessageRow
            key={message.id}
            message={message}
            previous={conversationMessages[index - 1]}
          />
        ))}
      </div>

      {error && (
        <div style={{ padding: '0 12px' }}>
          <p className="form-error">{error}</p>
        </div>
      )}

      {files.length > 0 && (
        <div className="pending-files">
          {files.map((file, index) => (
            <span className="pending-file" key={`${file.name}-${index}`}>
              📎 {file.name}
              <button
                className="link-button"
                onClick={() => setFiles((current) => current.filter((_, i) => i !== index))}
                aria-label={`Remove ${file.name}`}
              >
                ✕
              </button>
            </span>
          ))}
        </div>
      )}

      <div className="composer">
        <input
          ref={fileInputRef}
          type="file"
          multiple
          hidden
          onChange={(event) => {
            setFiles((current) => [...current, ...Array.from(event.target.files ?? [])]);
            event.target.value = '';
          }}
        />
        <button
          className="icon-button"
          onClick={() => fileInputRef.current?.click()}
          title="Attach a file. It is encrypted on this device before upload; the server stores only ciphertext."
          aria-label="Attach a file"
        >
          📎
        </button>
        <textarea
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={onKeyDown}
          placeholder={`Message ${conversation.peerUsername}…`}
          rows={1}
          aria-label="Message"
        />
        <button
          className="send-button"
          onClick={() => void submit()}
          disabled={sending || (!draft.trim() && files.length === 0)}
          aria-label="Send"
        >
          {sending ? <span className="spinner" /> : '➤'}
        </button>
      </div>
    </section>
  );
}

function MessageRow({
  message,
  previous,
}: {
  message: StoredMessage;
  previous: StoredMessage | undefined;
}): JSX.Element {
  const showDivider =
    !previous || new Date(previous.receivedAt).toDateString() !== new Date(message.receivedAt).toDateString();

  return (
    <>
      {showDivider && <div className="day-divider">{formatDay(message.receivedAt)}</div>}
      <div className="message-row" data-outgoing={message.outgoing}>
        <div className="bubble">
          {!message.outgoing && message.senderTrustAtReceipt === 'changed' && (
            <div className="bubble-warning">
              Received after this contact&rsquo;s security code changed
            </div>
          )}
          {message.body && <div className="bubble-body">{message.body}</div>}
          {message.attachments.map((attachment) => (
            <AttachmentRow key={attachment.blobId} attachment={attachment} />
          ))}
          <div className="bubble-footer">
            {message.transport === 'relay' && (
              <span title="Delivered through the server relay because a direct connection was not available. Still end-to-end encrypted.">
                ↻
              </span>
            )}
            <time dateTime={new Date(message.sentAt).toISOString()}>
              {formatTime(message.sentAt)}
            </time>
            {message.outgoing && <DeliveryIndicator status={message.status} />}
          </div>
        </div>
      </div>
    </>
  );
}

function AttachmentRow({ attachment }: { attachment: AttachmentDescriptor }): JSX.Element {
  const { ready } = useSession();
  const [state, setState] = useState<'idle' | 'loading' | 'error'>('idle');

  const download = async (): Promise<void> => {
    if (!ready) return;
    setState('loading');
    try {
      const bytes = await ready.messaging.fetchAttachment(attachment);
      const blob = new Blob([bytes as BlobPart], { type: attachment.mimeType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = attachment.filename;
      anchor.click();
      URL.revokeObjectURL(url);
      setState('idle');
    } catch {
      // Covers both a tampered blob and a missing one; either way the user
      // must not be handed bytes that failed authentication.
      setState('error');
    }
  };

  return (
    <div className="attachment">
      <span aria-hidden="true">📎</span>
      <span className="attachment-name" title={attachment.filename}>
        {attachment.filename}
      </span>
      <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>
        {formatBytes(attachment.size)}
      </span>
      <button className="link-button" onClick={() => void download()} disabled={state === 'loading'}>
        {state === 'loading' ? 'Decrypting…' : state === 'error' ? 'Failed' : 'Download'}
      </button>
    </div>
  );
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDay(timestamp: number): string {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86_400_000);
  if (date.toDateString() === today.toDateString()) return 'Today';
  if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return date.toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' });
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
