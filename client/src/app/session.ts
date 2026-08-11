/**
 * Application session: the object that turns a passphrase into a running,
 * connected, unlocked client.
 *
 * Startup states:
 *   loading -> needs-registration        (no device record on this machine)
 *   loading -> locked -> ready           (device record present, vault sealed)
 *
 * One passphrase does two independent jobs, with different salts so the
 * outputs are unrelated:
 *   - Argon2id(passphrase, server salt) -> the proof sent to the server to
 *     authorise creating a device on the account. The server never sees the
 *     passphrase itself.
 *   - Argon2id(passphrase, local salt) -> the key wrapping the local vault
 *     master key. This never leaves the device in any form.
 *
 * After registration the passphrase is not used to authenticate to the server
 * at all: the device signs a challenge with its own Ed25519 key.
 */
import { argon2id } from '@noble/hashes/argon2';
import {
  KEY_PACKAGE_LOW_WATERMARK,
  TARGET_KEY_PACKAGE_COUNT,
  createLogger,
  fromBase64,
  toBase64,
  utf8Encode,
  type Logger,
  type PasswordKdfParams,
  type PeerAddress,
} from '@p2pchat/shared';
import { MlsEngine } from '../crypto/mls.js';
import { randomBytes, wipe } from '../crypto/random.js';
import {
  generateDeviceAuthKey,
  devicePublicKeyFrom,
} from '../identity/deviceKey.js';
import { TrustStore } from '../identity/trustStore.js';
import { EncryptedStore } from '../storage/encryptedStore.js';
import { createDefaultKeyValueStore, type KeyValueStore } from '../storage/kv.js';
import { Repository } from '../storage/repository.js';
import {
  DEFAULT_ARGON2_PARAMS,
  KEY_PURPOSE,
  createVault,
  rewrapVault,
  unlockVault,
  type Argon2Params,
  type UnlockedVault,
  type VaultHeader,
} from '../storage/vault.js';
import type { AccountProfile, AppSettings } from '../storage/models.js';
import { DEFAULT_SETTINGS } from '../storage/models.js';
import { ApiClient } from '../p2p/apiClient.js';
import { SignalingClient, asSignalTransport } from '../p2p/signalingClient.js';
import { TransportManager } from '../p2p/transportManager.js';
import { WebRtcChannelFactory } from '../p2p/webrtc.js';
import type { DirectChannelFactory } from '../p2p/types.js';
import { MessagingService } from '../messaging/messagingService.js';

export type SessionPhase = 'loading' | 'needs-registration' | 'locked' | 'ready';

/** Unencrypted local record, written before the vault exists. Holds no secret. */
export interface DeviceRecord {
  readonly profile: AccountProfile;
  readonly vaultHeader: VaultHeader;
  /** Salt+params used to derive the server proof from the passphrase. */
  readonly serverKdfParams: PasswordKdfParams;
}

const DEVICE_RECORD_KEY = 'p2pchat.device.v1';

export interface SessionConfig {
  readonly apiBaseUrl: string;
  readonly wsUrl: string;
  readonly logger?: Logger;
  /** Overridden in tests to avoid needing a real WebRTC stack. */
  readonly channelFactory?: DirectChannelFactory;
  readonly keyValueStoreFactory?: (name: string) => KeyValueStore;
  readonly argon2Params?: Argon2Params;
  /** In-memory MLS store; used by tests so nothing touches IndexedDB. */
  readonly ephemeralMlsStorage?: boolean;
  readonly wasmUrl?: string;
  readonly deviceRecordStore?: DeviceRecordStore;
}

/** Where the pre-unlock device record lives. localStorage in the browser. */
export interface DeviceRecordStore {
  read(): DeviceRecord | null;
  write(record: DeviceRecord): void;
  clear(): void;
}

export function localStorageDeviceRecordStore(): DeviceRecordStore {
  return {
    read(): DeviceRecord | null {
      try {
        const raw = globalThis.localStorage?.getItem(DEVICE_RECORD_KEY);
        return raw ? (JSON.parse(raw) as DeviceRecord) : null;
      } catch {
        return null;
      }
    },
    write(record: DeviceRecord): void {
      globalThis.localStorage?.setItem(DEVICE_RECORD_KEY, JSON.stringify(record));
    },
    clear(): void {
      globalThis.localStorage?.removeItem(DEVICE_RECORD_KEY);
    },
  };
}

export function memoryDeviceRecordStore(): DeviceRecordStore {
  let record: DeviceRecord | null = null;
  return {
    read: () => record,
    write: (value) => {
      record = value;
    },
    clear: () => {
      record = null;
    },
  };
}

export interface ReadySession {
  readonly profile: AccountProfile;
  readonly self: PeerAddress;
  readonly repository: Repository;
  readonly trustStore: TrustStore;
  readonly messaging: MessagingService;
  readonly engine: MlsEngine;
  readonly transport: TransportManager;
  readonly signaling: SignalingClient;
  readonly api: ApiClient;
  readonly settings: AppSettings;
}

export class SessionError extends Error {
  constructor(
    readonly code: 'bad-passphrase' | 'registration-failed' | 'login-failed' | 'not-registered',
    message: string,
  ) {
    super(message);
    this.name = 'SessionError';
  }
}

export class AppSession {
  private vault: UnlockedVault | null = null;
  private ready: ReadySession | null = null;
  private settings: AppSettings = DEFAULT_SETTINGS;
  private readonly logger: Logger;
  private readonly recordStore: DeviceRecordStore;
  private lockTimer: ReturnType<typeof setTimeout> | null = null;

  private constructor(
    private readonly config: SessionConfig,
    private phase: SessionPhase,
  ) {
    this.logger = config.logger ?? createLogger('client', { level: 'info' });
    this.recordStore = config.deviceRecordStore ?? localStorageDeviceRecordStore();
  }

  static async bootstrap(config: SessionConfig): Promise<AppSession> {
    const session = new AppSession(config, 'loading');
    session.phase = session.recordStore.read() ? 'locked' : 'needs-registration';
    return session;
  }

  get currentPhase(): SessionPhase {
    return this.phase;
  }

  get deviceRecord(): DeviceRecord | null {
    return this.recordStore.read();
  }

  get session(): ReadySession | null {
    return this.ready;
  }

  get currentSettings(): AppSettings {
    return this.settings;
  }

  // -- registration ---------------------------------------------------------

  /**
   * Create an account (or add this device to an existing one) and open a
   * session. All key generation happens locally, before anything is sent.
   */
  async register(params: {
    username: string;
    passphrase: string;
    deviceLabel: string;
    /** True when joining an account that already exists. */
    additionalDevice?: boolean;
  }): Promise<ReadySession> {
    const api = new ApiClient(this.config.apiBaseUrl);
    const argonParams = this.config.argon2Params ?? DEFAULT_ARGON2_PARAMS;

    const serverKdfParams: PasswordKdfParams = params.additionalDevice
      ? await api.getPasswordKdfParams(params.username)
      : {
          algorithm: 'argon2id',
          salt: toBase64(randomBytes(16)),
          memoryKiB: argonParams.memoryKiB,
          iterations: argonParams.iterations,
          parallelism: argonParams.parallelism,
        };

    const clientProof = deriveServerProof(params.passphrase, serverKdfParams);
    const deviceKey = generateDeviceAuthKey();

    let registration: { userId: string; deviceId: string };
    try {
      registration = params.additionalDevice
        ? await api.registerDevice({
            username: params.username,
            clientProof,
            deviceAuthPublicKey: deviceKey.publicKey,
            deviceLabel: params.deviceLabel,
          })
        : await api.registerAccount({
            username: params.username,
            clientProof,
            kdfParams: serverKdfParams,
            deviceAuthPublicKey: deviceKey.publicKey,
            deviceLabel: params.deviceLabel,
          });
    } catch (error) {
      wipe(clientProof);
      wipe(deviceKey.privateKey);
      throw new SessionError(
        'registration-failed',
        error instanceof Error ? error.message : 'registration failed',
      );
    }
    wipe(clientProof);

    const { header, vault } = await createVault(params.passphrase, argonParams);
    const profile: AccountProfile = {
      userId: registration.userId,
      deviceId: registration.deviceId,
      username: params.username,
      deviceLabel: params.deviceLabel,
      registeredAt: Date.now(),
    };

    this.recordStore.write({ profile, vaultHeader: header, serverKdfParams });

    const repository = await this.openRepository(vault, profile);
    await repository.saveProfile(profile);
    await repository.saveSecretBytes('device-auth-key', deviceKey.privateKey);
    wipe(deviceKey.privateKey);

    this.vault = vault;
    this.logger.info('device registered', {
      userId: profile.userId,
      deviceId: profile.deviceId,
    });
    return this.activate(vault, profile, repository, api);
  }

  // -- unlock ---------------------------------------------------------------

  async unlock(passphrase: string): Promise<ReadySession> {
    const record = this.recordStore.read();
    if (!record) throw new SessionError('not-registered', 'no device is registered here');

    let vault: UnlockedVault;
    try {
      vault = await unlockVault(record.vaultHeader, passphrase);
    } catch {
      // Wrong passphrase and a corrupt header are deliberately indistinguishable.
      throw new SessionError('bad-passphrase', 'incorrect passphrase');
    }

    const repository = await this.openRepository(vault, record.profile);
    const api = new ApiClient(this.config.apiBaseUrl);
    this.vault = vault;
    return this.activate(vault, record.profile, repository, api);
  }

  private async openRepository(
    vault: UnlockedVault,
    profile: AccountProfile,
  ): Promise<Repository> {
    const storeName = `p2pchat-records-${profile.userId}-${profile.deviceId}`;
    const backend = (this.config.keyValueStoreFactory ?? createDefaultKeyValueStore)(storeName);
    const recordsKey = await vault.deriveAesKey(KEY_PURPOSE.records);
    return new Repository(new EncryptedStore(backend, recordsKey, this.logger));
  }

  /** Bring up crypto, transport and messaging for an unlocked vault. */
  private async activate(
    vault: UnlockedVault,
    profile: AccountProfile,
    repository: Repository,
    api: ApiClient,
  ): Promise<ReadySession> {
    const self: PeerAddress = { userId: profile.userId, deviceId: profile.deviceId };
    this.settings = await repository.getSettings();

    const devicePrivateKey = await repository.getSecretBytes('device-auth-key');
    if (!devicePrivateKey) {
      throw new SessionError('login-failed', 'device authentication key is missing');
    }

    try {
      await api.login({
        userId: profile.userId,
        deviceId: profile.deviceId,
        devicePrivateKey,
      });
    } catch (error) {
      wipe(devicePrivateKey);
      throw new SessionError(
        'login-failed',
        error instanceof Error ? error.message : 'could not authenticate this device',
      );
    }
    // Keep a copy for re-authentication after token expiry, then scrub ours.
    const deviceKeyCopy = Uint8Array.from(devicePrivateKey);
    wipe(devicePrivateKey);

    const trustStore = new TrustStore(repository.trustPersistence());
    await trustStore.load();

    const signaling = new SignalingClient({
      url: this.config.wsUrl,
      getToken: () => api.currentSession?.token ?? null,
      logger: this.logger,
    });

    const channelFactory =
      this.config.channelFactory ?? new WebRtcChannelFactory({ logger: this.logger });

    const transport = new TransportManager({
      self,
      channelFactory,
      signal: asSignalTransport(signaling),
      relay: { send: (peer, frame) => signaling.relay(peer, frame) },
      getIceServers: async () => {
        try {
          const config = await api.getIceConfig();
          return config.iceServers as RTCIceServer[];
        } catch {
          return [];
        }
      },
      policy: () => ({
        allowRelayFallback: this.settings.allowRelayFallback,
        preferDirectOnly: this.settings.preferDirectOnly,
      }),
      logger: this.logger,
    });

    signaling.onRelayFrame.subscribe((delivery) => {
      transport.deliverRelayFrame(delivery.from, delivery.frame);
      signaling.acknowledgeRelay([delivery.envelopeId]);
    });

    // The engine needs a commit router, and the router needs the engine, so
    // the callback is bound after both exist.
    let messaging: MessagingService | undefined;
    const engine = await MlsEngine.create({
      address: self,
      storage: this.config.ephemeralMlsStorage
        ? { kind: 'memory' }
        : {
            kind: 'persistent',
            location: `p2pchat-mls-${profile.userId}-${profile.deviceId}`,
            databaseKey: await vault.deriveKey(KEY_PURPOSE.mlsDatabase, 32),
          },
      onOutboundCommit: async (bundle) => {
        await messaging?.handleOutboundCommit(bundle);
      },
      logger: this.logger,
      ...(this.config.wasmUrl ? { wasmUrl: this.config.wasmUrl } : {}),
    });

    messaging = new MessagingService({
      self,
      engine,
      transport,
      repository,
      trustStore,
      api,
      settings: () => this.settings,
      logger: this.logger,
    });
    await messaging.start();

    signaling.start();

    const ready: ReadySession = {
      profile,
      self,
      repository,
      trustStore,
      messaging,
      engine,
      transport,
      signaling,
      api,
      settings: this.settings,
    };
    this.ready = ready;
    this.phase = 'ready';
    wipe(deviceKeyCopy);

    await this.replenishKeyPackages(ready);
    this.scheduleAutoLock();
    return ready;
  }

  /**
   * Keep a supply of one-time key packages on the directory so contacts can
   * start a conversation while this device is offline.
   */
  async replenishKeyPackages(ready: ReadySession = this.requireReady()): Promise<void> {
    try {
      const count = await ready.api.keyPackageCount();
      if (count >= KEY_PACKAGE_LOW_WATERMARK) return;
      const packages = await ready.engine.generateKeyPackages(TARGET_KEY_PACKAGE_COUNT - count);
      await ready.api.publishKeyPackages(packages);
      this.logger.info('published key packages', { published: packages.length });
    } catch (error) {
      this.logger.warn('could not replenish key packages', {
        reason: error instanceof Error ? error.name : 'unknown',
      });
    }
  }

  // -- settings & lifecycle -------------------------------------------------

  async updateSettings(patch: Partial<AppSettings>): Promise<AppSettings> {
    const ready = this.requireReady();
    this.settings = { ...this.settings, ...patch };
    await ready.repository.saveSettings(this.settings);
    this.scheduleAutoLock();
    return this.settings;
  }

  async changePassphrase(current: string, next: string): Promise<void> {
    const record = this.recordStore.read();
    if (!record) throw new SessionError('not-registered', 'no device is registered here');
    // Prove the caller knows the current passphrase before re-wrapping.
    await unlockVault(record.vaultHeader, current).catch(() => {
      throw new SessionError('bad-passphrase', 'incorrect passphrase');
    });
    const vault = this.vault;
    if (!vault) throw new SessionError('bad-passphrase', 'vault is locked');
    const header = await rewrapVault(
      vault,
      next,
      this.config.argon2Params ?? DEFAULT_ARGON2_PARAMS,
    );
    this.recordStore.write({ ...record, vaultHeader: header });
    this.logger.info('vault passphrase changed');
  }

  /** Note user activity, restarting the idle auto-lock countdown. */
  noteActivity(): void {
    if (this.phase === 'ready') this.scheduleAutoLock();
  }

  private scheduleAutoLock(): void {
    if (this.lockTimer) clearTimeout(this.lockTimer);
    this.lockTimer = null;
    const minutes = this.settings.autoLockMinutes;
    if (!minutes || minutes <= 0) return;
    this.lockTimer = setTimeout(() => void this.lock(), minutes * 60 * 1000);
  }

  /** Tear down live state and zero the master key. */
  async lock(): Promise<void> {
    const ready = this.ready;
    this.ready = null;
    if (this.lockTimer) clearTimeout(this.lockTimer);
    this.lockTimer = null;

    if (ready) {
      ready.signaling.stop();
      ready.transport.closeAll();
      await ready.engine.close();
    }
    this.vault?.lock();
    this.vault = null;
    this.phase = this.recordStore.read() ? 'locked' : 'needs-registration';
    this.logger.info('session locked');
  }

  /**
   * Remove this device's local data entirely.
   *
   * The MLS key store and the record store are both dropped, so the private
   * signature key and every group secret are gone from this machine. Messages
   * already delivered to peers are unaffected — nothing here can reach them.
   */
  async destroyLocalData(): Promise<void> {
    const ready = this.ready;
    if (ready) await ready.repository.wipeEverything();
    await this.lock();
    this.recordStore.clear();
    this.phase = 'needs-registration';
    this.logger.info('local data destroyed');
  }

  private requireReady(): ReadySession {
    if (!this.ready) throw new SessionError('not-registered', 'session is not ready');
    return this.ready;
  }
}

/** Argon2id over the passphrase using the server-supplied salt and parameters. */
export function deriveServerProof(
  passphrase: string,
  params: PasswordKdfParams,
): Uint8Array {
  return argon2id(utf8Encode(passphrase), fromBase64(params.salt), {
    t: params.iterations,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: 32,
  });
}

export { devicePublicKeyFrom };
