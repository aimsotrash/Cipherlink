/**
 * SQLite storage for the signaling/relay server.
 *
 * Design rule for this schema: if the server does not need a column to route a
 * frame, enforce a quota, or authenticate a device, it should not exist.
 *
 * What is deliberately absent:
 *   - any column that could hold message text (there is nowhere to put it),
 *   - a link from an attachment blob to the account that uploaded it (quota is
 *     tracked as a running total instead, so the blob table has no owner),
 *   - message history: relay envelopes are deleted the moment they are
 *     acknowledged by the recipient device.
 *
 * What is unavoidably present, and documented in THREAT_MODEL.md: usernames,
 * account and device identifiers, device public keys, key packages, envelope
 * routing metadata with timestamps, and blob sizes.
 */
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';

export type Db = Database.Database;

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
  user_id       TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  -- Argon2id over the client-stretched proof. The password itself never
  -- reaches this server.
  proof_hash    BLOB NOT NULL,
  proof_salt    BLOB NOT NULL,
  -- Client-side Argon2id parameters, echoed back so any device can recompute
  -- the same proof. Not secret.
  kdf_params    TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  user_id           TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
  device_id         TEXT NOT NULL,
  label             TEXT NOT NULL,
  -- Ed25519 public key used to authenticate this device to the server.
  -- The device's MLS signature private key is NOT here and never will be.
  auth_public_key   BLOB NOT NULL,
  created_at        INTEGER NOT NULL,
  last_seen_at      INTEGER,
  PRIMARY KEY (user_id, device_id)
);

-- One-time MLS key packages: the public half of a device's offer to join a
-- group. Consumed on claim so each is used once.
CREATE TABLE IF NOT EXISTS key_packages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  data        BLOB NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS key_packages_owner ON key_packages(user_id, device_id);

CREATE TABLE IF NOT EXISTS auth_challenges (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  nonce       BLOB NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash  BLOB PRIMARY KEY,
  user_id     TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_tokens_expiry ON auth_tokens(expires_at);

-- Store-and-forward queue used only when direct P2P is unavailable.
-- 'frame' is an opaque MLS message; this server holds no key that can open it.
CREATE TABLE IF NOT EXISTS relay_envelopes (
  id             TEXT PRIMARY KEY,
  to_user_id     TEXT NOT NULL,
  to_device_id   TEXT NOT NULL,
  from_user_id   TEXT NOT NULL,
  from_device_id TEXT NOT NULL,
  frame          BLOB NOT NULL,
  received_at    INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS relay_recipient ON relay_envelopes(to_user_id, to_device_id, received_at);

-- Encrypted attachment blobs. No owner column by design.
CREATE TABLE IF NOT EXISTS blobs (
  id          TEXT PRIMARY KEY,
  data        BLOB NOT NULL,
  size        INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

-- Upload allowance per account over a rolling window.
--
-- This is a rate limit, not a storage ledger, precisely so that no row links
-- an account to a blob. The counter resets with the window, which also means
-- expiring a blob needs no owner lookup to reclaim quota.
CREATE TABLE IF NOT EXISTS blob_quota (
  user_id       TEXT PRIMARY KEY,
  bytes_used    INTEGER NOT NULL DEFAULT 0,
  window_start  INTEGER NOT NULL
);
`;

/** Length of the rolling upload-allowance window. */
export const BLOB_QUOTA_WINDOW_MS = 24 * 60 * 60 * 1000;

export function openDatabase(path: string): Db {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new Database(path);
  db.exec(SCHEMA);
  return db;
}

/** Delete expired rows. Called on a timer and at startup. */
export function pruneExpired(db: Db, now: number): void {
  db.prepare('DELETE FROM auth_challenges WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM auth_tokens WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM relay_envelopes WHERE expires_at < ?').run(now);

  db.prepare('DELETE FROM blobs WHERE expires_at < ?').run(now);
  db.prepare('DELETE FROM blob_quota WHERE window_start < ?').run(now - BLOB_QUOTA_WINDOW_MS);
}
