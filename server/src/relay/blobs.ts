/**
 * Encrypted attachment storage.
 *
 * The server receives an opaque byte string and returns an identifier. It has
 * no filename, no MIME type, no content key, and no record of which account
 * uploaded which blob — the client encrypts before upload and sends the key
 * through the MLS channel.
 *
 * Upload volume is rate-limited per account over a rolling window, which is
 * why the quota table exists and why it stores a counter rather than an
 * ownership list.
 */
import { randomBytes } from 'node:crypto';
import { BLOB_RETENTION_MS } from '@p2pchat/shared';
import { BLOB_QUOTA_WINDOW_MS, type Db } from '../db.js';

export class QuotaExceededError extends Error {
  constructor() {
    super('upload allowance exhausted');
    this.name = 'QuotaExceededError';
  }
}

export class BlobStore {
  constructor(
    private readonly db: Db,
    private readonly quotaBytes: number,
    private readonly now: () => number = Date.now,
  ) {}

  put(userId: string, data: Buffer): { blobId: string; expiresAt: number } {
    const now = this.now();
    this.chargeQuota(userId, data.length, now);

    // 128 bits of identifier: unguessable, so possession of the id is itself a
    // weak capability. It is not a substitute for authentication.
    const blobId = randomBytes(16).toString('base64url');
    const expiresAt = now + BLOB_RETENTION_MS;
    this.db
      .prepare('INSERT INTO blobs (id, data, size, expires_at) VALUES (?, ?, ?, ?)')
      .run(blobId, data, data.length, expiresAt);
    return { blobId, expiresAt };
  }

  get(blobId: string): Buffer | null {
    const row = this.db
      .prepare('SELECT data, expires_at FROM blobs WHERE id = ?')
      .get(blobId) as { data: Buffer; expires_at: number } | undefined;
    if (!row || row.expires_at < this.now()) return null;
    return row.data;
  }

  private chargeQuota(userId: string, bytes: number, now: number): void {
    const row = this.db
      .prepare('SELECT bytes_used, window_start FROM blob_quota WHERE user_id = ?')
      .get(userId) as { bytes_used: number; window_start: number } | undefined;

    const windowExpired = !row || now - row.window_start >= BLOB_QUOTA_WINDOW_MS;
    const used = windowExpired ? 0 : row!.bytes_used;
    if (used + bytes > this.quotaBytes) throw new QuotaExceededError();

    this.db
      .prepare(
        `INSERT INTO blob_quota (user_id, bytes_used, window_start) VALUES (?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET bytes_used = ?, window_start = ?`,
      )
      .run(
        userId,
        used + bytes,
        windowExpired ? now : row!.window_start,
        used + bytes,
        windowExpired ? now : row!.window_start,
      );
  }
}
