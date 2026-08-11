/**
 * Settings, including the privacy and security controls.
 *
 * Every toggle explains its actual trade-off. Where a setting cannot deliver
 * what a user might assume (relay fallback does not weaken encryption; direct-
 * only does not hide your IP from your contact), the help text says so.
 */
import { useEffect, useState } from 'react';
import { useSession } from '../SessionContext.js';
import type { DeviceInfo } from '@p2pchat/shared';

type Tab = 'general' | 'privacy' | 'devices' | 'about';

export function SettingsModal({ onClose }: { onClose: () => void }): JSX.Element {
  const [tab, setTab] = useState<Tab>('general');

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Settings">
      <div className="modal">
        <h2>Settings</h2>
        <div className="icon-row" style={{ margin: '12px 0 20px', flexWrap: 'wrap' }}>
          {(['general', 'privacy', 'devices', 'about'] as Tab[]).map((name) => (
            <button
              key={name}
              className="secondary-button"
              aria-pressed={tab === name}
              style={
                tab === name
                  ? { borderColor: 'var(--accent)', color: 'var(--accent)' }
                  : undefined
              }
              onClick={() => setTab(name)}
            >
              {name[0]!.toUpperCase() + name.slice(1)}
            </button>
          ))}
        </div>

        {tab === 'general' && <GeneralTab />}
        {tab === 'privacy' && <PrivacyTab />}
        {tab === 'devices' && <DevicesTab />}
        {tab === 'about' && <AboutTab />}

        <div className="modal-actions">
          <button className="secondary-button" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function Toggle({
  label,
  help,
  checked,
  onChange,
}: {
  label: string;
  help: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}): JSX.Element {
  return (
    <div className="toggle-row">
      <div>
        <div className="toggle-label">{label}</div>
        <div className="toggle-help">{help}</div>
      </div>
      <button
        className="switch"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
      />
    </div>
  );
}

function GeneralTab(): JSX.Element {
  const { settings, updateSettings } = useSession();
  if (!settings) return <p className="notice">Loading…</p>;

  return (
    <div className="settings-section">
      <h3>Appearance & session</h3>
      <div className="toggle-row">
        <div>
          <div className="toggle-label">Theme</div>
          <div className="toggle-help">Applies immediately.</div>
        </div>
        <select
          value={settings.theme}
          onChange={(event) => {
            const theme = event.target.value as 'dark' | 'light';
            document.documentElement.dataset.theme = theme;
            void updateSettings({ theme });
          }}
          style={{
            padding: '8px 10px',
            borderRadius: 8,
            background: 'var(--bg-input)',
            border: '1px solid var(--border-strong)',
          }}
        >
          <option value="dark">Dark</option>
          <option value="light">Light</option>
        </select>
      </div>

      <div className="toggle-row">
        <div>
          <div className="toggle-label">Lock after inactivity</div>
          <div className="toggle-help">
            Locking clears the decryption key from memory. Anyone with access to this device
            afterwards needs your passphrase again.
          </div>
        </div>
        <select
          value={settings.autoLockMinutes}
          onChange={(event) => void updateSettings({ autoLockMinutes: Number(event.target.value) })}
          style={{
            padding: '8px 10px',
            borderRadius: 8,
            background: 'var(--bg-input)',
            border: '1px solid var(--border-strong)',
          }}
        >
          <option value={0}>Never</option>
          <option value={5}>5 minutes</option>
          <option value={15}>15 minutes</option>
          <option value={60}>1 hour</option>
        </select>
      </div>
    </div>
  );
}

function PrivacyTab(): JSX.Element {
  const { settings, updateSettings, changePassphrase, destroyLocalData } = useSession();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [confirmWipe, setConfirmWipe] = useState(false);

  if (!settings) return <p className="notice">Loading…</p>;

  return (
    <>
      <div className="settings-section">
        <h3>Security</h3>
        <Toggle
          label="Hold messages when a security code changes"
          help="If a contact's identity key changes, outgoing messages are blocked until you review it. Turning this off means messages could be encrypted to a key you have not checked."
          checked={settings.blockOnIdentityChange}
          onChange={(value) => void updateSettings({ blockOnIdentityChange: value })}
        />
        <Toggle
          label="Allow relaying through the server"
          help="When a direct connection is impossible, send encrypted messages via the server instead. The server still cannot read them, but it learns when you are exchanging messages and roughly how much. Turning this off means messages fail rather than being relayed."
          checked={settings.allowRelayFallback}
          onChange={(value) => void updateSettings({ allowRelayFallback: value })}
        />
        <Toggle
          label="Require a direct connection (no TURN)"
          help="Refuses connections routed through a TURN server. This keeps the operator off your media path, but it will fail on many restrictive networks. It does not hide your IP address from your contact — a direct connection reveals it by design."
          checked={settings.preferDirectOnly}
          onChange={(value) => void updateSettings({ preferDirectOnly: value })}
        />
      </div>

      <div className="settings-section">
        <h3>Metadata you send</h3>
        <Toggle
          label="Send read receipts"
          help="Tells your contact when you have opened their messages. Sent inside the encrypted channel, so only they learn it."
          checked={settings.sendReadReceipts}
          onChange={(value) => void updateSettings({ sendReadReceipts: value })}
        />
        <Toggle
          label="Send typing indicators"
          help="Reveals when you are composing. Also encrypted, but it is more information about your activity than most conversations need."
          checked={settings.sendTypingIndicators}
          onChange={(value) => void updateSettings({ sendTypingIndicators: value })}
        />
      </div>

      <div className="settings-section">
        <h3>Passphrase</h3>
        {message && <p className="notice">{message}</p>}
        <label className="field">
          <span>Current passphrase</span>
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="field">
          <span>New passphrase</span>
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <button
          className="secondary-button"
          disabled={!current || next.length < 10}
          onClick={() => {
            setMessage(null);
            void changePassphrase(current, next)
              .then(() => {
                setMessage('Passphrase changed. Your messages did not need re-encrypting.');
                setCurrent('');
                setNext('');
              })
              .catch((error: unknown) =>
                setMessage(error instanceof Error ? error.message : 'Could not change passphrase.'),
              );
          }}
        >
          Change passphrase
        </button>
      </div>

      <div className="settings-section">
        <h3>Danger zone</h3>
        <p className="toggle-help" style={{ marginBottom: 10 }}>
          Deletes this device&rsquo;s identity key, message history and encrypted database. Messages
          already delivered to your contacts are not affected — nothing here can reach them.
        </p>
        {confirmWipe ? (
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="danger-button" onClick={() => void destroyLocalData()}>
              Yes, erase everything
            </button>
            <button className="secondary-button" onClick={() => setConfirmWipe(false)}>
              Cancel
            </button>
          </div>
        ) : (
          <button className="danger-button" onClick={() => setConfirmWipe(true)}>
            Erase local data
          </button>
        )}
      </div>
    </>
  );
}

function DevicesTab(): JSX.Element {
  const { ready } = useSession();
  const [devices, setDevices] = useState<DeviceInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ready) return;
    ready.api
      .listOwnDevices()
      .then(setDevices)
      .catch(() => setError('Could not reach the server to list your devices.'));
  }, [ready]);

  const revoke = async (deviceId: string): Promise<void> => {
    if (!ready) return;
    await ready.api.revokeDevice(deviceId);
    setDevices(await ready.api.listOwnDevices());
  };

  return (
    <div className="settings-section">
      <h3>Your devices</h3>
      <p className="toggle-help" style={{ marginBottom: 8 }}>
        Each device has its own identity key. Adding a device does not copy keys between them:
        contacts see a separate entry, with its own safety number, for every device you use.
      </p>
      {error && <p className="form-error">{error}</p>}
      {!devices && !error && <p className="notice">Loading…</p>}
      {devices?.map((device) => (
        <div className="device-row" key={device.deviceId}>
          <div>
            <div className="toggle-label">
              {device.label}
              {device.deviceId === ready?.self.deviceId && (
                <span style={{ color: 'var(--text-faint)', fontWeight: 400 }}> · this device</span>
              )}
            </div>
            <div className="toggle-help">
              Added {new Date(device.createdAt).toLocaleDateString()}
              {device.lastSeenAt
                ? ` · last seen ${new Date(device.lastSeenAt).toLocaleDateString()}`
                : ''}
            </div>
          </div>
          {device.deviceId !== ready?.self.deviceId && (
            <button className="danger-button" onClick={() => void revoke(device.deviceId)}>
              Revoke
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function AboutTab(): JSX.Element {
  return (
    <div className="settings-section">
      <h3>How this app protects your messages</h3>
      <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
        Messages are end-to-end encrypted with <strong>MLS (RFC 9420)</strong>, using X25519 key
        agreement, Ed25519 signatures, ChaCha20-Poly1305 authenticated encryption and HKDF-SHA-256.
        Keys are generated on this device and the private ones never leave it.
      </p>
      <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
        Messages travel directly between devices when that is possible. When it is not, the server
        forwards encrypted data it cannot read.
      </p>
      <div className="notice" data-tone="warn">
        <strong>What this does not protect against.</strong> Anything that can see your screen or
        keyboard — malware, a compromised operating system, someone reading over your shoulder — sees
        your messages after they are decrypted. The server also learns who talks to whom and when,
        and your IP address is visible to the server and, on a direct connection, to your contact.
        This app is not anonymity software.
      </div>
    </div>
  );
}
