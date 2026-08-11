/**
 * Status indicators.
 *
 * Wording rules these components follow, and that the rest of the UI must too:
 *   - Never say "secure", "anonymous", "unhackable" or "100% private".
 *   - Say what is actually true and scoped: "Encrypted end-to-end" describes
 *     the transport of message content, nothing more.
 *   - Distinguish "encrypted" (always true) from "verified" (true only after
 *     the user compares a safety number). Conflating them is the single most
 *     common way messaging UIs mislead people.
 */
import type { TrustState } from '../../identity/trustStore.js';
import type { ConnectionState, TransportKind } from '../../p2p/types.js';
import type { DeliveryStatus } from '../../storage/models.js';

type Tone = 'ok' | 'warn' | 'danger' | 'neutral';

export function Pill({
  tone,
  children,
  title,
}: {
  tone: Tone;
  children: React.ReactNode;
  title?: string;
}): JSX.Element {
  return (
    <span className="pill" data-tone={tone} title={title}>
      {children}
    </span>
  );
}

/**
 * Always-on indicator that message content is end-to-end encrypted. This is a
 * property of the protocol and does not depend on verification or on whether
 * the connection is direct.
 */
export function EncryptionBadge(): JSX.Element {
  return (
    <Pill
      tone="ok"
      title="Message content is encrypted on this device and decrypted on your contact's device. The server relays ciphertext it cannot read."
    >
      🔒 Encrypted end-to-end
    </Pill>
  );
}

export function TrustBadge({ state }: { state: TrustState }): JSX.Element {
  switch (state) {
    case 'verified':
      return (
        <Pill tone="ok" title="You compared this contact's safety number in person or over another channel.">
          ✓ Verified
        </Pill>
      );
    case 'changed':
      return (
        <Pill
          tone="danger"
          title="This contact's identity key is different from the one you saw before. This happens after a reinstall — or if someone is intercepting. Check the safety number before continuing."
        >
          ⚠ Security code changed
        </Pill>
      );
    default:
      return (
        <Pill
          tone="warn"
          title="Encryption is active, but you have not yet confirmed you are talking to the right person. Compare safety numbers to be sure."
        >
          Not verified
        </Pill>
      );
  }
}

const CONNECTION_COPY: Record<
  ConnectionState,
  { tone: Tone; label: string; title: string }
> = {
  idle: { tone: 'neutral', label: 'Not connected', title: 'No connection attempt yet.' },
  connecting: {
    tone: 'neutral',
    label: 'Connecting…',
    title: 'Trying to reach your contact directly.',
  },
  connected: {
    tone: 'ok',
    label: 'Direct',
    title: 'Connected peer-to-peer. Messages do not pass through the server.',
  },
  reconnecting: {
    tone: 'warn',
    label: 'Reconnecting…',
    title: 'The direct connection dropped and is being re-established.',
  },
  'relay-only': {
    tone: 'warn',
    label: 'Via relay',
    title:
      'A direct connection was not possible, so encrypted messages are passing through the server. The server still cannot read them, but it can see that you are exchanging messages.',
  },
  failed: {
    tone: 'danger',
    label: 'Offline',
    title: 'No route to your contact is currently available.',
  },
  closed: { tone: 'neutral', label: 'Closed', title: 'This connection has been closed.' },
};

export function ConnectionBadge({
  state,
  transport,
}: {
  state: ConnectionState;
  transport: TransportKind | null;
}): JSX.Element {
  const copy = CONNECTION_COPY[state];
  // A "direct" connection carried over TURN is still relayed at the network
  // layer, and saying otherwise would overstate the privacy on offer.
  const label =
    state === 'connected' && transport === 'p2p-turn' ? 'Direct (via TURN)' : copy.label;
  const title =
    state === 'connected' && transport === 'p2p-turn'
      ? 'Peer-to-peer, but routed through a TURN server because a direct path was unavailable. Content is still end-to-end encrypted; the TURN operator sees traffic timing and volume.'
      : copy.title;

  return (
    <Pill tone={copy.tone} title={title}>
      <span className="dot" aria-hidden="true" />
      {label}
    </Pill>
  );
}

const DELIVERY_GLYPH: Record<DeliveryStatus, { glyph: string; label: string }> = {
  pending: { glyph: '◌', label: 'Sending' },
  sent: { glyph: '✓', label: 'Sent' },
  delivered: { glyph: '✓✓', label: 'Delivered' },
  read: { glyph: '✓✓', label: 'Read' },
  failed: { glyph: '!', label: 'Not sent' },
};

export function DeliveryIndicator({ status }: { status: DeliveryStatus }): JSX.Element {
  const { glyph, label } = DELIVERY_GLYPH[status];
  return (
    <span
      title={label}
      style={{
        color:
          status === 'failed'
            ? 'var(--danger)'
            : status === 'read'
              ? 'var(--accent)'
              : undefined,
      }}
    >
      {glyph}
      <span className="visually-hidden">{label}</span>
    </span>
  );
}

export function SignalingBadge({ state }: { state: string }): JSX.Element {
  const ready = state === 'ready';
  return (
    <Pill
      tone={ready ? 'ok' : 'warn'}
      title={
        ready
          ? 'Connected to the signaling server, which coordinates connections and holds encrypted messages when your contact is offline.'
          : 'Not connected to the signaling server. New conversations and relayed delivery are unavailable until this reconnects.'
      }
    >
      <span className="dot" aria-hidden="true" />
      {ready ? 'Online' : 'Reconnecting…'}
    </Pill>
  );
}
