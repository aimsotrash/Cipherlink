/**
 * Registration and unlock.
 *
 * Two honest points are made here rather than buried in a help page: the
 * passphrase cannot be reset (there is no server-side copy to reset it with),
 * and encryption alone does not tell you who you are talking to.
 */
import { useState, type FormEvent } from 'react';
import { useSession } from '../SessionContext.js';

export function RegistrationScreen(): JSX.Element {
  const { register, busy } = useSession();
  const [username, setUsername] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [deviceLabel, setDeviceLabel] = useState(defaultDeviceLabel());
  const [additionalDevice, setAdditionalDevice] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setError(null);

    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      setError('Usernames are 3–32 characters: lowercase letters, digits, dot, underscore, hyphen.');
      return;
    }
    if (passphrase.length < 10) {
      setError('Use a passphrase of at least 10 characters. Longer is better than complicated.');
      return;
    }
    if (!additionalDevice && passphrase !== confirm) {
      setError('The two passphrases do not match.');
      return;
    }

    try {
      await register({ username, passphrase, deviceLabel, additionalDevice });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Registration failed.');
    }
  };

  return (
    <div className="centered-screen">
      <form className="card" onSubmit={submit}>
        <h1>{additionalDevice ? 'Add this device' : 'Create your account'}</h1>
        <p className="lede">
          Your keys are generated here and stay here. The server never receives your passphrase or
          any private key.
        </p>

        {error && <p className="form-error">{error}</p>}

        <label className="field">
          <span>Username</span>
          <input
            value={username}
            onChange={(event) => setUsername(event.target.value.toLowerCase().trim())}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
          />
          <span className="hint">Visible to anyone who looks you up on this server.</span>
        </label>

        <label className="field">
          <span>Passphrase</span>
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            autoComplete={additionalDevice ? 'current-password' : 'new-password'}
            required
          />
          <span className="hint">
            Unlocks the encrypted database on this device. There is no recovery — if you forget it,
            the messages stored here cannot be read by anyone, including us.
          </span>
        </label>

        {!additionalDevice && (
          <label className="field">
            <span>Confirm passphrase</span>
            <input
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
        )}

        <label className="field">
          <span>Device name</span>
          <input
            value={deviceLabel}
            onChange={(event) => setDeviceLabel(event.target.value)}
            maxLength={64}
            required
          />
          <span className="hint">Helps you recognise this device in your device list.</span>
        </label>

        <button className="primary-button" type="submit" disabled={busy}>
          {busy
            ? 'Generating keys…'
            : additionalDevice
              ? 'Add device'
              : 'Create account'}
        </button>

        <p style={{ marginTop: 16, textAlign: 'center', fontSize: 13 }}>
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setAdditionalDevice((value) => !value);
              setError(null);
            }}
          >
            {additionalDevice
              ? 'Create a new account instead'
              : 'I already have an account — add this device'}
          </button>
        </p>
      </form>
    </div>
  );
}

export function UnlockScreen(): JSX.Element {
  const { unlock, busy } = useSession();
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setError(null);
    try {
      await unlock(passphrase);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not unlock.');
      setPassphrase('');
    }
  };

  return (
    <div className="centered-screen">
      <form className="card" onSubmit={submit}>
        <h1>Unlock</h1>
        <p className="lede">
          Enter your passphrase to decrypt this device&rsquo;s message database and identity keys.
        </p>

        {error && <p className="form-error">{error}</p>}

        <label className="field">
          <span>Passphrase</span>
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            autoComplete="current-password"
            autoFocus
            required
          />
        </label>

        <button className="primary-button" type="submit" disabled={busy || !passphrase}>
          {busy ? 'Deriving key…' : 'Unlock'}
        </button>

        <p className="notice" style={{ marginTop: 16 }}>
          Key derivation is deliberately slow (Argon2id). A few seconds here is what makes guessing
          your passphrase expensive for someone who copies this device&rsquo;s storage.
        </p>
      </form>
    </div>
  );
}

function defaultDeviceLabel(): string {
  if (typeof navigator === 'undefined') return 'This device';
  const ua = navigator.userAgent;
  if (/android/i.test(ua)) return 'Android device';
  if (/iphone|ipad/i.test(ua)) return 'iOS device';
  if (/mac/i.test(ua)) return 'Mac';
  if (/windows/i.test(ua)) return 'Windows PC';
  if (/linux/i.test(ua)) return 'Linux desktop';
  return 'This device';
}
