/**
 * Safety-number verification.
 *
 * The point of this screen is to let two people confirm, over a channel an
 * attacker does not control, that their apps hold each other's real signature
 * keys. Without it, encryption protects against a passive server but not
 * against one that substitutes its own key package when introducing you.
 *
 * Marking "verified" is therefore a deliberate, explicit act. Nothing in this
 * screen sets it automatically, and a key change clears it.
 */
import { useCallback, useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { useSession } from '../SessionContext.js';
import { Field } from '../components/Field.js';
import {
  deriveSafetyNumber,
  qrPayloadMatches,
  safetyNumberMatches,
  type SafetyNumber,
} from '../../identity/safetyNumber.js';
import type { MlsMemberIdentity } from '../../crypto/mls.js';
import type { Conversation } from '../../storage/models.js';
import type { IdentityRecord } from '../../identity/trustStore.js';

interface DeviceVerification {
  readonly identity: MlsMemberIdentity;
  /** The device's name, if the directory gave one when we added the contact. */
  readonly label: string | undefined;
  readonly safetyNumber: SafetyNumber;
  readonly record: IdentityRecord | undefined;
  readonly qrDataUrl: string;
}

export function VerificationModal({
  conversation,
  onClose,
}: {
  conversation: Conversation;
  onClose: () => void;
}): JSX.Element {
  const { ready } = useSession();
  const [devices, setDevices] = useState<DeviceVerification[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [typed, setTyped] = useState('');
  const [compareResult, setCompareResult] = useState<'match' | 'mismatch' | null>(null);
  const [version, setVersion] = useState(0);

  const load = useCallback(async () => {
    if (!ready) return;
    try {
      const members = ready.messaging.membersFor(conversation.id);
      if (members.length === 0) {
        setError('This conversation has no other devices to verify yet.');
        setDevices([]);
        return;
      }

      // Read identities from live group state — including our own — so the
      // comparison is over what MLS actually holds, not what the server said.
      const identities = await ready.engine.memberIdentities(conversation.id, [
        ready.self,
        ...members,
      ]);
      const local = identities.find(
        (identity) =>
          identity.address.userId === ready.self.userId &&
          identity.address.deviceId === ready.self.deviceId,
      );
      if (!local) {
        setError('Could not read this device’s own identity from the session.');
        return;
      }

      const remotes = identities.filter((identity) => identity !== local);
      const contact = await ready.repository.getContact(conversation.peerUserId);
      const built = await Promise.all(
        remotes.map(async (identity) => {
          const safetyNumber = await deriveSafetyNumber(local, identity);
          const qrDataUrl = await QRCode.toDataURL(safetyNumber.qrPayload, {
            errorCorrectionLevel: 'M',
            margin: 1,
            width: 400,
          });
          return {
            identity,
            label: contact?.deviceLabels?.[identity.address.deviceId],
            safetyNumber,
            record: ready.trustStore.get(identity.address),
            qrDataUrl,
          } satisfies DeviceVerification;
        }),
      );
      setDevices(built);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not build the safety number.');
    }
  }, [ready, conversation.id, conversation.peerUserId, version]);

  useEffect(() => {
    void load();
  }, [load]);

  const markVerified = async (device: DeviceVerification): Promise<void> => {
    if (!ready) return;
    await ready.trustStore.markVerified(device.identity.address, device.identity.thumbprint);
    setVersion((v) => v + 1);
  };

  const clearVerification = async (device: DeviceVerification): Promise<void> => {
    if (!ready) return;
    await ready.trustStore.clearVerification(device.identity.address);
    setVersion((v) => v + 1);
  };

  const acknowledgeChange = async (device: DeviceVerification): Promise<void> => {
    if (!ready) return;
    await ready.trustStore.acknowledgeChange(device.identity.address);
    setVersion((v) => v + 1);
  };

  const compare = (device: DeviceVerification): void => {
    const trimmed = typed.trim();
    if (!trimmed) return;
    const matches = trimmed.startsWith('{')
      ? qrPayloadMatches(device.safetyNumber, trimmed)
      : safetyNumberMatches(device.safetyNumber, trimmed);
    setCompareResult(matches ? 'match' : 'mismatch');
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Verify safety number">
      <div className="modal">
        <h2>Verify {conversation.peerUsername}</h2>
        <p className="lede">
          Compare this number with {conversation.peerUsername} in person, on a video call, or over
          another channel you already trust. If both sides see the same number, no one is sitting
          between you.
        </p>

        {error && <p className="form-error">{error}</p>}
        {!devices && !error && <p className="notice">Reading identity keys…</p>}

        {devices?.map((device) => (
          <section key={`${device.identity.address.userId}:${device.identity.address.deviceId}`}>
            <h3 style={{ fontSize: 13, color: 'var(--text-faint)' }}>
              {device.label ? (
                <>
                  <bdi>{device.label}</bdi> · {device.identity.address.deviceId}
                </>
              ) : (
                `Device ${device.identity.address.deviceId}`
              )}
            </h3>

            {device.record?.state === 'changed' && (
              <div className="notice" data-tone="danger" style={{ marginBottom: 12 }}>
                <strong>This device&rsquo;s key changed.</strong>{' '}
                {device.record.wasVerifiedBeforeChange
                  ? 'You had previously verified it, which makes this worth checking carefully.'
                  : 'It was not previously verified.'}{' '}
                Compare the new number below before you accept it.
              </div>
            )}

            <div className="verify-codes">
              <div className="safety-number">{device.safetyNumber.formatted}</div>
              <div className="qr-holder">
                <img src={device.qrDataUrl} alt="QR code encoding this conversation's safety number" />
              </div>
            </div>

            <Field
              label="Check their number"
              value={typed}
              onChange={(event) => {
                setTyped(event.target.value);
                setCompareResult(null);
              }}
              placeholder="Paste their number or scanned QR contents"
              hint={`Type or paste what ${conversation.peerUsername} reads out, then compare.`}
            />
            <button className="secondary-button" onClick={() => compare(device)}>
              Compare
            </button>

            {compareResult === 'match' && (
              <p className="notice" data-tone="warn" style={{ marginTop: 12 }}>
                The numbers match. Only mark this verified if you got the number from{' '}
                {conversation.peerUsername} directly — not from a message in this app.
              </p>
            )}
            {compareResult === 'mismatch' && (
              <p className="notice" data-tone="danger" style={{ marginTop: 12 }}>
                These do not match. Do not mark this verified. Someone may be intercepting, or one
                of you may be reading the wrong device&rsquo;s number.
              </p>
            )}

            <div className="modal-actions">
              {device.record?.state === 'changed' && (
                <button className="secondary-button" onClick={() => void acknowledgeChange(device)}>
                  Accept change (still unverified)
                </button>
              )}
              {device.record?.state === 'verified' ? (
                <button className="danger-button" onClick={() => void clearVerification(device)}>
                  Remove verification
                </button>
              ) : (
                <button className="primary-button" style={{ width: 'auto' }} onClick={() => void markVerified(device)}>
                  Mark as verified
                </button>
              )}
            </div>
          </section>
        ))}

        <div className="modal-actions">
          <button className="secondary-button" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
