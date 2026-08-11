/**
 * REST client for the signaling/identity/relay server.
 *
 * Everything sent through here is either public (usernames, key packages,
 * device authentication public keys) or already encrypted (attachment blobs).
 * No private key, session secret or plaintext ever crosses this boundary —
 * `tests/security/serverBlindness.test.ts` asserts that on real traffic.
 */
import {
  AUTH_CHALLENGE_CONTEXT,
  fromBase64,
  toBase64,
  authChallengeResponseSchema,
  authVerifyResponseSchema,
  blobUploadResponseSchema,
  claimKeyPackagesResponseSchema,
  deviceListResponseSchema,
  directoryEntrySchema,
  iceConfigResponseSchema,
  kdfParamsResponseSchema,
  keyPackageCountResponseSchema,
  registerAccountResponseSchema,
  type ClaimKeyPackagesResponse,
  type DeviceInfo,
  type DirectoryEntry,
  type IceConfigResponse,
  type PasswordKdfParams,
} from '@p2pchat/shared';
import { buildChallengeMessage, signChallenge } from '../identity/deviceKey.js';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface AuthSession {
  readonly token: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly expiresAt: number;
}

export class ApiClient {
  private session: AuthSession | null = null;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  get currentSession(): AuthSession | null {
    return this.session;
  }

  setSession(session: AuthSession | null): void {
    this.session = session;
  }

  private async request<T>(
    path: string,
    init: RequestInit & { authenticated?: boolean } = {},
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body && !headers.has('content-type')) {
      headers.set('content-type', 'application/json');
    }
    if (init.authenticated !== false && this.session) {
      headers.set('authorization', `Bearer ${this.session.token}`);
    }

    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers });
    const text = await response.text();
    const parsed: unknown = text ? safeJsonParse(text) : undefined;

    if (!response.ok) {
      const error = (parsed as { error?: { code?: string; message?: string } } | undefined)?.error;
      throw new ApiError(
        response.status,
        error?.code ?? 'http_error',
        error?.message ?? `request failed with status ${response.status}`,
      );
    }
    return parsed as T;
  }

  // -- registration & authentication ---------------------------------------

  /** Fetch the Argon2id parameters to stretch a password with, by username. */
  async getPasswordKdfParams(username: string): Promise<PasswordKdfParams> {
    const body = await this.request<unknown>(
      `/api/v1/account/kdf-params?username=${encodeURIComponent(username)}`,
      { authenticated: false },
    );
    return kdfParamsResponseSchema.parse(body).kdfParams;
  }

  async registerAccount(params: {
    username: string;
    clientProof: Uint8Array;
    kdfParams: PasswordKdfParams;
    deviceAuthPublicKey: Uint8Array;
    deviceLabel: string;
  }): Promise<{ userId: string; deviceId: string }> {
    const body = await this.request<unknown>('/api/v1/account/register', {
      method: 'POST',
      authenticated: false,
      body: JSON.stringify({
        username: params.username,
        clientProof: toBase64(params.clientProof),
        kdfParams: params.kdfParams,
        deviceAuthPublicKey: toBase64(params.deviceAuthPublicKey),
        deviceLabel: params.deviceLabel,
      }),
    });
    return registerAccountResponseSchema.parse(body);
  }

  /** Register an additional device on an existing account. */
  async registerDevice(params: {
    username: string;
    clientProof: Uint8Array;
    deviceAuthPublicKey: Uint8Array;
    deviceLabel: string;
  }): Promise<{ userId: string; deviceId: string }> {
    const body = await this.request<unknown>('/api/v1/device/register', {
      method: 'POST',
      authenticated: false,
      body: JSON.stringify({
        username: params.username,
        clientProof: toBase64(params.clientProof),
        deviceAuthPublicKey: toBase64(params.deviceAuthPublicKey),
        deviceLabel: params.deviceLabel,
      }),
    });
    return registerAccountResponseSchema.parse(body);
  }

  /**
   * Authenticate by signing a server nonce with the device key.
   *
   * The account password is not involved: it only ever gated device
   * *registration*. A device proves who it is with a key it holds locally.
   */
  async login(params: {
    userId: string;
    deviceId: string;
    devicePrivateKey: Uint8Array;
  }): Promise<AuthSession> {
    const challengeBody = await this.request<unknown>('/api/v1/auth/challenge', {
      method: 'POST',
      authenticated: false,
      body: JSON.stringify({ userId: params.userId, deviceId: params.deviceId }),
    });
    const challenge = authChallengeResponseSchema.parse(challengeBody);

    const message = buildChallengeMessage({
      context: AUTH_CHALLENGE_CONTEXT,
      userId: params.userId,
      deviceId: params.deviceId,
      nonce: fromBase64(challenge.nonce),
    });
    const signature = signChallenge(params.devicePrivateKey, message);

    const verifyBody = await this.request<unknown>('/api/v1/auth/verify', {
      method: 'POST',
      authenticated: false,
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        signature: toBase64(signature),
      }),
    });
    const verified = authVerifyResponseSchema.parse(verifyBody);
    this.session = verified;
    return verified;
  }

  // -- key package directory ------------------------------------------------

  async publishKeyPackages(keyPackages: Uint8Array[]): Promise<void> {
    await this.request('/api/v1/keypackages', {
      method: 'POST',
      body: JSON.stringify({ keyPackages: keyPackages.map(toBase64) }),
    });
  }

  async keyPackageCount(): Promise<number> {
    const body = await this.request<unknown>('/api/v1/keypackages/count');
    return keyPackageCountResponseSchema.parse(body).count;
  }

  /**
   * Claim one key package per device for `userId`.
   *
   * The server chooses which key packages to hand over, and could hand over
   * one it generated itself. That is precisely why safety numbers exist; see
   * SECURITY.md.
   */
  async claimKeyPackages(userId: string): Promise<ClaimKeyPackagesResponse> {
    const body = await this.request<unknown>('/api/v1/keypackages/claim', {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
    return claimKeyPackagesResponseSchema.parse(body);
  }

  // -- directory & devices --------------------------------------------------

  async lookupUser(username: string): Promise<DirectoryEntry> {
    const body = await this.request<unknown>(
      `/api/v1/directory/${encodeURIComponent(username)}`,
    );
    return directoryEntrySchema.parse(body);
  }

  async listOwnDevices(): Promise<DeviceInfo[]> {
    const body = await this.request<unknown>('/api/v1/devices');
    return deviceListResponseSchema.parse(body).devices;
  }

  async revokeDevice(deviceId: string): Promise<void> {
    await this.request(`/api/v1/devices/${encodeURIComponent(deviceId)}`, { method: 'DELETE' });
  }

  // -- ICE / TURN -----------------------------------------------------------

  async getIceConfig(): Promise<IceConfigResponse> {
    const body = await this.request<unknown>('/api/v1/ice');
    return iceConfigResponseSchema.parse(body);
  }

  // -- encrypted attachment blobs ------------------------------------------

  /** Upload an already-encrypted blob. The server never receives the key. */
  async uploadBlob(ciphertext: Uint8Array): Promise<{ blobId: string; expiresAt: number }> {
    const body = await this.request<unknown>('/api/v1/blobs', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: ciphertext.slice().buffer as ArrayBuffer,
    });
    return blobUploadResponseSchema.parse(body);
  }

  async downloadBlob(blobId: string): Promise<Uint8Array> {
    const headers = new Headers();
    if (this.session) headers.set('authorization', `Bearer ${this.session.token}`);
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/blobs/${encodeURIComponent(blobId)}`,
      { headers },
    );
    if (!response.ok) {
      throw new ApiError(response.status, 'blob_fetch_failed', 'failed to download attachment');
    }
    return new Uint8Array(await response.arrayBuffer());
  }
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
