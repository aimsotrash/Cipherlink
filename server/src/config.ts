/**
 * Server configuration.
 *
 * Defaults are chosen so a developer can run the stack with no environment
 * setup, while every value that matters in production is overridable.
 */
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

const iceServerListSchema = z.array(
  z.object({
    urls: z.array(z.string()).min(1),
    username: z.string().optional(),
    credential: z.string().optional(),
  }),
);

export interface ServerConfig {
  readonly host: string;
  readonly port: number;
  /** SQLite path, or ':memory:' for an ephemeral instance. */
  readonly databasePath: string;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly corsOrigins: string[];
  /** STUN/TURN servers handed to clients for WebRTC. */
  readonly iceServers: { urls: string[]; username?: string; credential?: string }[];
  readonly maxBlobBytes: number;
  /** Per-account encrypted-blob storage quota, in bytes. */
  readonly blobQuotaBytes: number;
  readonly trustProxy: boolean;
}

function parseIceServers(raw: string | undefined): ServerConfig['iceServers'] {
  if (!raw) {
    // Public STUN only by default. Operators who need TURN must configure it
    // explicitly, because TURN puts the operator on the media path.
    return [{ urls: ['stun:stun.l.google.com:19302'] }];
  }
  return iceServerListSchema.parse(JSON.parse(raw));
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  return {
    host: env.HOST ?? '127.0.0.1',
    port: Number(env.PORT ?? 8787),
    // Anchored to this package, so it lands in server/data/ whatever the working
    // directory (npm workspace scripts run in server/).
    databasePath:
      env.DATABASE_PATH ?? fileURLToPath(new URL('../data/p2pchat.sqlite', import.meta.url)),
    logLevel: (env.LOG_LEVEL as ServerConfig['logLevel']) ?? 'info',
    corsOrigins: (env.CORS_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
    iceServers: parseIceServers(env.ICE_SERVERS),
    maxBlobBytes: Number(env.MAX_BLOB_BYTES ?? 32 * 1024 * 1024),
    blobQuotaBytes: Number(env.BLOB_QUOTA_BYTES ?? 512 * 1024 * 1024),
    trustProxy: env.TRUST_PROXY === 'true',
  };
}
