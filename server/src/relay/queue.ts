/**
 * Store-and-forward queue for encrypted frames.
 *
 * Used only when two devices cannot reach each other directly. The server
 * holds an opaque MLS message, the addresses needed to route it, and a
 * timestamp — and nothing else. It cannot decrypt, cannot forge (frames are
 * signed and AEAD-protected inside MLS), and cannot replay usefully (MLS
 * rejects duplicate application messages at the recipient).
 *
 * Envelopes are deleted as soon as the recipient acknowledges them, and expire
 * regardless after {@link RELAY_RETENTION_MS}.
 */
import { randomUUID } from 'node:crypto';
import { RELAY_MAX_QUEUE_PER_DEVICE, RELAY_RETENTION_MS } from '@p2pchat/shared';
import type { Db } from '../db.js';

export interface QueuedEnvelope {
  readonly id: string;
  readonly from: { userId: string; deviceId: string };
  readonly frame: Buffer;
  readonly receivedAt: number;
}

export class RelayQueue {
  constructor(
    private readonly db: Db,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Accept a frame for later delivery.
   *
   * Returns false when the recipient's queue is full — backpressure rather
   * than unbounded growth, so one sender cannot exhaust the server's disk.
   */
  enqueue(params: {
    to: { userId: string; deviceId: string };
    from: { userId: string; deviceId: string };
    frame: Buffer;
  }): string | null {
    const depth = this.db
      .prepare('SELECT COUNT(*) AS n FROM relay_envelopes WHERE to_user_id = ? AND to_device_id = ?')
      .get(params.to.userId, params.to.deviceId) as { n: number };
    if (depth.n >= RELAY_MAX_QUEUE_PER_DEVICE) return null;

    const id = randomUUID();
    const receivedAt = this.now();
    this.db
      .prepare(
        `INSERT INTO relay_envelopes
           (id, to_user_id, to_device_id, from_user_id, from_device_id, frame, received_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        params.to.userId,
        params.to.deviceId,
        params.from.userId,
        params.from.deviceId,
        params.frame,
        receivedAt,
        receivedAt + RELAY_RETENTION_MS,
      );
    return id;
  }

  pending(to: { userId: string; deviceId: string }, limit = 100): QueuedEnvelope[] {
    const rows = this.db
      .prepare(
        `SELECT id, from_user_id, from_device_id, frame, received_at
           FROM relay_envelopes
          WHERE to_user_id = ? AND to_device_id = ? AND expires_at > ?
          ORDER BY received_at
          LIMIT ?`,
      )
      .all(to.userId, to.deviceId, this.now(), limit) as {
      id: string;
      from_user_id: string;
      from_device_id: string;
      frame: Buffer;
      received_at: number;
    }[];

    return rows.map((row) => ({
      id: row.id,
      from: { userId: row.from_user_id, deviceId: row.from_device_id },
      frame: row.frame,
      receivedAt: row.received_at,
    }));
  }

  /** Delete acknowledged envelopes, scoped to the acknowledging device. */
  acknowledge(to: { userId: string; deviceId: string }, envelopeIds: string[]): number {
    if (envelopeIds.length === 0) return 0;
    const statement = this.db.prepare(
      'DELETE FROM relay_envelopes WHERE id = ? AND to_user_id = ? AND to_device_id = ?',
    );
    let deleted = 0;
    this.db.transaction(() => {
      for (const id of envelopeIds) {
        deleted += statement.run(id, to.userId, to.deviceId).changes;
      }
    })();
    return deleted;
  }

  depth(to: { userId: string; deviceId: string }): number {
    const row = this.db
      .prepare('SELECT COUNT(*) AS n FROM relay_envelopes WHERE to_user_id = ? AND to_device_id = ?')
      .get(to.userId, to.deviceId) as { n: number };
    return row.n;
  }
}
