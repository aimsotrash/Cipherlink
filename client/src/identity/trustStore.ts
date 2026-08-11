/**
 * Trust state for peer device identities.
 *
 * The policy this implements:
 *
 *  - First sighting of a device is recorded trust-on-first-use and marked
 *    `unverified`. The UI must say so; it is not a security guarantee.
 *  - A device whose signature key later differs from the recorded one is moved
 *    to `changed` — never silently accepted, and never left looking verified.
 *    A key change is exactly what a server-side man-in-the-middle looks like,
 *    and also what a legitimate reinstall looks like; only the user can tell
 *    those apart, so only the user can clear it.
 *  - `verified` is set solely by an explicit out-of-band safety-number or QR
 *    comparison. Nothing automatic ever sets it.
 */
import type { MlsClientAddress } from '../crypto/mls.js';
import { formatClientAddress } from '../crypto/mls.js';

export type TrustState = 'unverified' | 'verified' | 'changed';

export interface IdentityRecord {
  readonly userId: string;
  readonly deviceId: string;
  /** JWK thumbprint of the device's MLS signature public key. */
  readonly thumbprint: string;
  readonly state: TrustState;
  readonly firstSeenAt: number;
  readonly verifiedAt: number | null;
  /** Set when `state === 'changed'`: what we used to see for this device. */
  readonly previousThumbprint: string | null;
  readonly changedAt: number | null;
  /** True if the device was verified *before* its key changed — the loud case. */
  readonly wasVerifiedBeforeChange: boolean;
}

export interface IdentityChangeEvent {
  readonly address: MlsClientAddress;
  readonly previousThumbprint: string;
  readonly newThumbprint: string;
  readonly wasVerified: boolean;
  readonly at: number;
}

/** Storage backend; the app supplies the encrypted implementation. */
export interface TrustPersistence {
  loadAll(): Promise<IdentityRecord[]>;
  save(record: IdentityRecord): Promise<void>;
  remove(key: string): Promise<void>;
}

export class InMemoryTrustPersistence implements TrustPersistence {
  private readonly records = new Map<string, IdentityRecord>();

  async loadAll(): Promise<IdentityRecord[]> {
    return [...this.records.values()];
  }

  async save(record: IdentityRecord): Promise<void> {
    this.records.set(identityKey(record), record);
  }

  async remove(key: string): Promise<void> {
    this.records.delete(key);
  }
}

export function identityKey(address: { userId: string; deviceId: string }): string {
  return formatClientAddress(address);
}

export type IdentityChangeListener = (event: IdentityChangeEvent) => void;

export class TrustStore {
  private readonly records = new Map<string, IdentityRecord>();
  private readonly listeners = new Set<IdentityChangeListener>();

  constructor(
    private readonly persistence: TrustPersistence,
    private readonly now: () => number = Date.now,
  ) {}

  async load(): Promise<void> {
    this.records.clear();
    for (const record of await this.persistence.loadAll()) {
      this.records.set(identityKey(record), record);
    }
  }

  onIdentityChange(listener: IdentityChangeListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  get(address: MlsClientAddress): IdentityRecord | undefined {
    return this.records.get(identityKey(address));
  }

  all(): IdentityRecord[] {
    return [...this.records.values()];
  }

  /** Every device we hold state for that belongs to this account. */
  forUser(userId: string): IdentityRecord[] {
    return this.all().filter((record) => record.userId === userId);
  }

  /**
   * Record the signature key observed for a device.
   *
   * Returns an {@link IdentityChangeEvent} when the key differs from what we
   * had recorded, and `null` otherwise. Callers must treat a non-null result
   * as a security-relevant event: show it, and do not quietly continue.
   */
  async observe(
    address: MlsClientAddress,
    thumbprint: string,
  ): Promise<IdentityChangeEvent | null> {
    if (!thumbprint) throw new Error('refusing to record an empty identity thumbprint');

    const key = identityKey(address);
    const existing = this.records.get(key);
    const at = this.now();

    if (!existing) {
      const record: IdentityRecord = {
        userId: address.userId,
        deviceId: address.deviceId,
        thumbprint,
        state: 'unverified',
        firstSeenAt: at,
        verifiedAt: null,
        previousThumbprint: null,
        changedAt: null,
        wasVerifiedBeforeChange: false,
      };
      this.records.set(key, record);
      await this.persistence.save(record);
      return null;
    }

    if (existing.thumbprint === thumbprint) {
      return null;
    }

    const wasVerified = existing.state === 'verified';
    const record: IdentityRecord = {
      ...existing,
      thumbprint,
      state: 'changed',
      verifiedAt: null,
      previousThumbprint: existing.thumbprint,
      changedAt: at,
      wasVerifiedBeforeChange: wasVerified,
    };
    this.records.set(key, record);
    await this.persistence.save(record);

    const event: IdentityChangeEvent = {
      address,
      previousThumbprint: existing.thumbprint,
      newThumbprint: thumbprint,
      wasVerified,
      at,
    };
    for (const listener of this.listeners) listener(event);
    return event;
  }

  /**
   * Mark a device verified after a successful out-of-band comparison.
   *
   * `thumbprint` must match what we currently observe; passing a stale value
   * fails rather than verifying the wrong key.
   */
  async markVerified(address: MlsClientAddress, thumbprint: string): Promise<void> {
    const key = identityKey(address);
    const existing = this.records.get(key);
    if (!existing) throw new Error('cannot verify a device that has not been seen');
    if (existing.thumbprint !== thumbprint) {
      throw new Error('identity changed during verification; re-check the safety number');
    }
    const record: IdentityRecord = {
      ...existing,
      state: 'verified',
      verifiedAt: this.now(),
      previousThumbprint: null,
      changedAt: null,
      wasVerifiedBeforeChange: false,
    };
    this.records.set(key, record);
    await this.persistence.save(record);
  }

  /** Drop a device back to unverified (user revoked their verification). */
  async clearVerification(address: MlsClientAddress): Promise<void> {
    const key = identityKey(address);
    const existing = this.records.get(key);
    if (!existing) return;
    const record: IdentityRecord = { ...existing, state: 'unverified', verifiedAt: null };
    this.records.set(key, record);
    await this.persistence.save(record);
  }

  /**
   * User has seen and accepted a key change. The device becomes `unverified`,
   * NOT `verified` — accepting a change is not the same as checking it.
   */
  async acknowledgeChange(address: MlsClientAddress): Promise<void> {
    const key = identityKey(address);
    const existing = this.records.get(key);
    if (!existing || existing.state !== 'changed') return;
    const record: IdentityRecord = {
      ...existing,
      state: 'unverified',
      previousThumbprint: null,
      changedAt: null,
      wasVerifiedBeforeChange: false,
    };
    this.records.set(key, record);
    await this.persistence.save(record);
  }

  async forget(address: MlsClientAddress): Promise<void> {
    const key = identityKey(address);
    this.records.delete(key);
    await this.persistence.remove(key);
  }

  /**
   * Whether outbound messages to this device should be held.
   *
   * With `blockOnIdentityChange` enabled (the safer default in settings), an
   * unacknowledged key change stops messages being encrypted to a key the user
   * has not accepted.
   */
  isSendBlocked(address: MlsClientAddress, blockOnIdentityChange: boolean): boolean {
    if (!blockOnIdentityChange) return false;
    return this.get(address)?.state === 'changed';
  }

  /** Worst state across a user's devices, for the conversation-level badge. */
  summaryForUser(userId: string): TrustState {
    const records = this.forUser(userId);
    if (records.length === 0) return 'unverified';
    if (records.some((r) => r.state === 'changed')) return 'changed';
    return records.every((r) => r.state === 'verified') ? 'verified' : 'unverified';
  }
}
