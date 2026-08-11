/**
 * Accounts, devices, authentication and the key-package directory.
 *
 * Three identities are kept deliberately separate here:
 *
 *  1. Account identity  — username + password-derived proof. Gates *creating*
 *     devices, nothing else.
 *  2. Device identity   — an Ed25519 key the device generated locally. This is
 *     what authenticates every subsequent request.
 *  3. Messaging identity — the device's MLS signature key. The server only
 *     ever sees it embedded in key packages it cannot forge a signature for,
 *     and plays no part in validating it; users do that with safety numbers.
 */
import { randomBytes, randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2';
import { ed25519 } from '@noble/curves/ed25519';
import {
  AUTH_CHALLENGE_CONTEXT,
  AUTH_CHALLENGE_TTL_MS,
  AUTH_TOKEN_TTL_MS,
  type PasswordKdfParams,
  type DeviceInfo,
} from '@p2pchat/shared';
import type { Db } from '../db.js';

/**
 * Server-side stretching of the already-stretched client proof.
 *
 * The client sends Argon2id(password, client_salt); we hash that again with a
 * per-account server salt before storage, so a stolen database still forces an
 * attacker back through a memory-hard function.
 */
const SERVER_ARGON2 = { t: 2, m: 32 * 1024, p: 1, dkLen: 32 } as const;

export interface AuthenticatedDevice {
  readonly userId: string;
  readonly deviceId: string;
}

export class RegistryError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'RegistryError';
  }
}

export class Registry {
  constructor(
    private readonly db: Db,
    private readonly now: () => number = Date.now,
  ) {}

  // -- accounts -------------------------------------------------------------

  /**
   * Return the client-side KDF parameters for a username.
   *
   * Unauthenticated by necessity: a device needs these before it can compute
   * the proof. That makes username existence probeable — an accepted, and
   * documented, metadata leak. Unknown usernames get deterministic decoy
   * parameters so the response does not itself distinguish the two cases.
   */
  passwordKdfParams(username: string): PasswordKdfParams {
    const row = this.db
      .prepare('SELECT kdf_params FROM accounts WHERE username = ?')
      .get(username) as { kdf_params: string } | undefined;
    if (row) return JSON.parse(row.kdf_params) as PasswordKdfParams;

    // Decoy: stable per username so repeated probes look like a real account.
    const salt = createHash('sha256').update(`decoy:${username}`).digest().subarray(0, 16);
    return {
      algorithm: 'argon2id',
      salt: salt.toString('base64'),
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
    };
  }

  registerAccount(params: {
    username: string;
    clientProof: Uint8Array;
    kdfParams: PasswordKdfParams;
    deviceAuthPublicKey: Uint8Array;
    deviceLabel: string;
  }): { userId: string; deviceId: string } {
    const existing = this.db
      .prepare('SELECT user_id FROM accounts WHERE username = ?')
      .get(params.username);
    if (existing) throw new RegistryError(409, 'username_taken', 'that username is taken');

    if (params.deviceAuthPublicKey.length !== 32) {
      throw new RegistryError(400, 'bad_key', 'device authentication key must be 32 bytes');
    }

    const userId = randomUUID();
    const proofSalt = randomBytes(16);
    const proofHash = argon2id(params.clientProof, proofSalt, SERVER_ARGON2);
    const now = this.now();

    const deviceId = this.newDeviceId();
    const insertAccount = this.db.prepare(
      `INSERT INTO accounts (user_id, username, proof_hash, proof_salt, kdf_params, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    const insertDevice = this.db.prepare(
      `INSERT INTO devices (user_id, device_id, label, auth_public_key, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, NULL)`,
    );

    this.db.transaction(() => {
      insertAccount.run(
        userId,
        params.username,
        proofHash,
        proofSalt,
        JSON.stringify(params.kdfParams),
        now,
      );
      insertDevice.run(
        userId,
        deviceId,
        params.deviceLabel,
        Buffer.from(params.deviceAuthPublicKey),
        now,
      );
    })();

    return { userId, deviceId };
  }

  /** Add a device to an existing account, gated by the password proof. */
  registerDevice(params: {
    username: string;
    clientProof: Uint8Array;
    deviceAuthPublicKey: Uint8Array;
    deviceLabel: string;
  }): { userId: string; deviceId: string } {
    const account = this.db
      .prepare('SELECT user_id, proof_hash, proof_salt FROM accounts WHERE username = ?')
      .get(params.username) as
      | { user_id: string; proof_hash: Buffer; proof_salt: Buffer }
      | undefined;

    if (!account) {
      // Spend comparable effort on a miss so timing does not reveal existence.
      argon2id(params.clientProof, randomBytes(16), SERVER_ARGON2);
      throw new RegistryError(401, 'invalid_credentials', 'invalid credentials');
    }

    const candidate = argon2id(params.clientProof, account.proof_salt, SERVER_ARGON2);
    if (!timingSafeEqual(Buffer.from(candidate), account.proof_hash)) {
      throw new RegistryError(401, 'invalid_credentials', 'invalid credentials');
    }
    if (params.deviceAuthPublicKey.length !== 32) {
      throw new RegistryError(400, 'bad_key', 'device authentication key must be 32 bytes');
    }

    const deviceId = this.newDeviceId();
    this.db
      .prepare(
        `INSERT INTO devices (user_id, device_id, label, auth_public_key, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        account.user_id,
        deviceId,
        params.deviceLabel,
        Buffer.from(params.deviceAuthPublicKey),
        this.now(),
      );

    return { userId: account.user_id, deviceId };
  }

  private newDeviceId(): string {
    // 48 bits is ample for per-account uniqueness and fits the u64 MLS device
    // id without needing BigInt gymnastics on the client.
    return randomBytes(6).toString('hex');
  }

  // -- device authentication ------------------------------------------------

  createChallenge(userId: string, deviceId: string): {
    challengeId: string;
    nonce: Buffer;
    expiresAt: number;
  } {
    const device = this.db
      .prepare('SELECT device_id FROM devices WHERE user_id = ? AND device_id = ?')
      .get(userId, deviceId);
    if (!device) throw new RegistryError(404, 'unknown_device', 'unknown device');

    const challengeId = randomUUID();
    const nonce = randomBytes(32);
    const expiresAt = this.now() + AUTH_CHALLENGE_TTL_MS;
    this.db
      .prepare(
        'INSERT INTO auth_challenges (id, user_id, device_id, nonce, expires_at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(challengeId, userId, deviceId, nonce, expiresAt);
    return { challengeId, nonce, expiresAt };
  }

  /**
   * Verify a challenge signature and mint a session token.
   *
   * The challenge row is deleted before the signature is checked, so a nonce
   * can only ever be used once regardless of the outcome.
   */
  verifyChallenge(challengeId: string, signature: Uint8Array): {
    token: string;
    userId: string;
    deviceId: string;
    expiresAt: number;
  } {
    const row = this.db
      .prepare('SELECT user_id, device_id, nonce, expires_at FROM auth_challenges WHERE id = ?')
      .get(challengeId) as
      | { user_id: string; device_id: string; nonce: Buffer; expires_at: number }
      | undefined;
    if (!row) throw new RegistryError(401, 'unknown_challenge', 'unknown or spent challenge');

    this.db.prepare('DELETE FROM auth_challenges WHERE id = ?').run(challengeId);

    if (row.expires_at < this.now()) {
      throw new RegistryError(401, 'challenge_expired', 'challenge expired');
    }

    const device = this.db
      .prepare('SELECT auth_public_key FROM devices WHERE user_id = ? AND device_id = ?')
      .get(row.user_id, row.device_id) as { auth_public_key: Buffer } | undefined;
    if (!device) throw new RegistryError(401, 'unknown_device', 'unknown device');

    const message = Buffer.concat([
      Buffer.from(`${AUTH_CHALLENGE_CONTEXT}\n${row.user_id}\n${row.device_id}\n`, 'utf8'),
      row.nonce,
    ]);

    let valid = false;
    try {
      valid = ed25519.verify(signature, message, new Uint8Array(device.auth_public_key));
    } catch {
      valid = false;
    }
    if (!valid) throw new RegistryError(401, 'bad_signature', 'signature verification failed');

    const token = randomBytes(32).toString('base64url');
    const expiresAt = this.now() + AUTH_TOKEN_TTL_MS;
    this.db
      .prepare(
        'INSERT INTO auth_tokens (token_hash, user_id, device_id, expires_at) VALUES (?, ?, ?, ?)',
      )
      .run(hashToken(token), row.user_id, row.device_id, expiresAt);
    this.db
      .prepare('UPDATE devices SET last_seen_at = ? WHERE user_id = ? AND device_id = ?')
      .run(this.now(), row.user_id, row.device_id);

    return { token, userId: row.user_id, deviceId: row.device_id, expiresAt };
  }

  /** Resolve a bearer token. Returns null for unknown, expired or malformed. */
  authenticate(token: string | undefined): AuthenticatedDevice | null {
    if (!token) return null;
    const row = this.db
      .prepare('SELECT user_id, device_id, expires_at FROM auth_tokens WHERE token_hash = ?')
      .get(hashToken(token)) as
      | { user_id: string; device_id: string; expires_at: number }
      | undefined;
    if (!row || row.expires_at < this.now()) return null;
    return { userId: row.user_id, deviceId: row.device_id };
  }

  revokeTokensForDevice(userId: string, deviceId: string): void {
    this.db
      .prepare('DELETE FROM auth_tokens WHERE user_id = ? AND device_id = ?')
      .run(userId, deviceId);
  }

  // -- directory ------------------------------------------------------------

  lookupByUsername(username: string): { userId: string; username: string; devices: DeviceInfo[] } {
    const account = this.db
      .prepare('SELECT user_id, username FROM accounts WHERE username = ?')
      .get(username) as { user_id: string; username: string } | undefined;
    if (!account) throw new RegistryError(404, 'unknown_user', 'no such user');
    return {
      userId: account.user_id,
      username: account.username,
      devices: this.listDevices(account.user_id),
    };
  }

  listDevices(userId: string): DeviceInfo[] {
    const rows = this.db
      .prepare(
        'SELECT device_id, label, created_at, last_seen_at FROM devices WHERE user_id = ? ORDER BY created_at',
      )
      .all(userId) as {
      device_id: string;
      label: string;
      created_at: number;
      last_seen_at: number | null;
    }[];
    return rows.map((row) => ({
      deviceId: row.device_id,
      label: row.label,
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
    }));
  }

  /** Remove a device, its key packages, tokens and undelivered envelopes. */
  removeDevice(userId: string, deviceId: string): void {
    this.db.transaction(() => {
      this.db.prepare('DELETE FROM devices WHERE user_id = ? AND device_id = ?').run(userId, deviceId);
      this.db
        .prepare('DELETE FROM key_packages WHERE user_id = ? AND device_id = ?')
        .run(userId, deviceId);
      this.db.prepare('DELETE FROM auth_tokens WHERE user_id = ? AND device_id = ?').run(userId, deviceId);
      this.db
        .prepare('DELETE FROM relay_envelopes WHERE to_user_id = ? AND to_device_id = ?')
        .run(userId, deviceId);
    })();
  }

  // -- key packages ---------------------------------------------------------

  publishKeyPackages(device: AuthenticatedDevice, packages: Uint8Array[]): void {
    const insert = this.db.prepare(
      'INSERT INTO key_packages (user_id, device_id, data, created_at) VALUES (?, ?, ?, ?)',
    );
    const now = this.now();
    this.db.transaction(() => {
      for (const data of packages) {
        insert.run(device.userId, device.deviceId, Buffer.from(data), now);
      }
    })();
  }

  countKeyPackages(device: AuthenticatedDevice): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS n FROM key_packages WHERE user_id = ? AND device_id = ?')
      .get(device.userId, device.deviceId) as { n: number };
    return row.n;
  }

  /**
   * Consume one key package per device of `userId`.
   *
   * Each package is deleted as it is handed out: reusing one would let two
   * different groups be created against the same init key.
   */
  claimKeyPackages(userId: string): { deviceId: string; keyPackage: Buffer }[] {
    const devices = this.db
      .prepare('SELECT device_id FROM devices WHERE user_id = ?')
      .all(userId) as { device_id: string }[];

    const claimed: { deviceId: string; keyPackage: Buffer }[] = [];
    this.db.transaction(() => {
      for (const device of devices) {
        const row = this.db
          .prepare(
            'SELECT id, data FROM key_packages WHERE user_id = ? AND device_id = ? ORDER BY id LIMIT 1',
          )
          .get(userId, device.device_id) as { id: number; data: Buffer } | undefined;
        if (!row) continue;
        this.db.prepare('DELETE FROM key_packages WHERE id = ?').run(row.id);
        claimed.push({ deviceId: device.device_id, keyPackage: row.data });
      }
    })();
    return claimed;
  }
}

export function hashToken(token: string): Buffer {
  // Tokens are 256-bit random values, so a fast hash is sufficient here; the
  // point is that a stolen database yields no usable bearer token.
  return createHash('sha256').update(token, 'utf8').digest();
}
