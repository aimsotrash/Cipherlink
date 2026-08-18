/**
 * Structured, redaction-first logging.
 *
 * The logging policy for this project is that secrets must be *structurally*
 * impossible to log, not merely absent from the call sites we happened to
 * review. Two mechanisms enforce that:
 *
 *  1. Field names matching {@link SENSITIVE_KEY_PATTERN} are replaced with
 *     are replaced with `[redacted]` regardless of what the caller passed.
 *  2. Raw binary (`Uint8Array`/`ArrayBuffer`) is never rendered. Byte arrays
 *     are the shape every key, nonce and ciphertext takes in this codebase, so
 *     they are summarised as `<bytes:N>` — length only.
 *
 * Message *bodies* are never passed to the logger at all; the redaction list
 * is a backstop, not the primary control. `tests/security/logging.test.ts`
 * asserts both properties.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/**
 * Words that make a field's value secret. Deliberately broad: a false positive
 * costs a debugging session, a false negative costs a user's privacy.
 */
const SENSITIVE_TOKENS = new Set([
  'key',
  'keys',
  'secret',
  'secrets',
  'token',
  'tokens',
  'password',
  'passwords',
  'passphrase',
  'proof',
  'seed',
  'nonce',
  'iv',
  'plaintext',
  'body',
  'text',
  'message',
  'content',
  'payload',
  'ciphertext',
  'signature',
  'credential',
  'credentials',
  'salt',
  'digest',
  'sdp',
  'candidate',
  'frame',
]);

/**
 * Split an identifier into lowercase words, handling camelCase, snake_case,
 * kebab-case and dotted paths alike.
 *
 * Getting this wrong is not a cosmetic issue: an earlier version only matched
 * separator-delimited words, which silently failed to redact `privateKey` and
 * every other camelCase field in a codebase written entirely in camelCase.
 */
function tokenizeFieldName(field: string): string[] {
  return field
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((token) => token.toLowerCase())
    .filter(Boolean);
}

export function isSensitiveFieldName(field: string): boolean {
  return tokenizeFieldName(field).some((token) => SENSITIVE_TOKENS.has(token));
}

/** @deprecated Kept for compatibility; prefer {@link isSensitiveFieldName}. */
export const SENSITIVE_KEY_PATTERN = {
  test: (field: string): boolean => isSensitiveFieldName(field),
};

export const REDACTED = '[redacted]';

export interface LogFields {
  readonly [field: string]: unknown;
}

export interface LogRecord {
  readonly time: string;
  readonly level: LogLevel;
  readonly logger: string;
  readonly msg: string;
  readonly [field: string]: unknown;
}

export type LogSink = (record: LogRecord) => void;

export interface Logger {
  debug(msg: string, fields?: LogFields): void;
  info(msg: string, fields?: LogFields): void;
  warn(msg: string, fields?: LogFields): void;
  error(msg: string, fields?: LogFields): void;
  child(name: string, fields?: LogFields): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  sink?: LogSink;
  /** Fields merged into every record emitted by this logger. */
  base?: LogFields;
}

/**
 * Recursively sanitise a value for logging.
 *
 * - Sensitive keys (by name) become `[redacted]`.
 * - Binary becomes `<bytes:N>`.
 * - Strings are truncated so an accidental large payload cannot be dumped.
 * - Cycles and over-deep structures are collapsed.
 */
export function sanitiseValue(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined) return value;
  if (depth > 4) return '[truncated:depth]';

  if (value instanceof Uint8Array) return `<bytes:${value.length}>`;
  if (value instanceof ArrayBuffer) return `<bytes:${value.byteLength}>`;
  if (ArrayBuffer.isView(value)) return `<bytes:${value.byteLength}>`;

  switch (typeof value) {
    case 'string':
      return value.length > 512 ? `${value.slice(0, 512)}…[truncated:${value.length}]` : value;
    case 'number':
    case 'boolean':
      return value;
    case 'bigint':
      return value.toString();
    case 'function':
      return '[function]';
    case 'symbol':
      return '[symbol]';
    default:
      break;
  }

  if (value instanceof Error) {
    // Stacks can embed argument values in some engines; keep name + message only.
    return { name: value.name, message: sanitiseValue(value.message, depth + 1, seen) };
  }

  if (typeof value === 'object') {
    if (seen.has(value)) return '[circular]';
    seen.add(value);

    if (Array.isArray(value)) {
      const capped = value.slice(0, 32).map((item) => sanitiseValue(item, depth + 1, seen));
      if (value.length > 32) capped.push(`…[${value.length - 32} more]`);
      return capped;
    }

    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = isSensitiveFieldName(key) ? REDACTED : sanitiseValue(item, depth + 1, seen);
    }
    return out;
  }

  return '[unknown]';
}

/** Sanitise a top-level field bag, applying the sensitive-key rule at depth 0. */
export function sanitiseFields(fields: LogFields | undefined): Record<string, unknown> {
  if (!fields) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = isSensitiveFieldName(key) ? REDACTED : sanitiseValue(value);
  }
  return out;
}

export const jsonSink: LogSink = (record) => {
  const line = JSON.stringify(record);
  if (record.level === 'error' || record.level === 'warn') console.error(line);
  else console.log(line);
};

export function createLogger(name: string, options: LoggerOptions = {}): Logger {
  const level = options.level ?? 'info';
  const sink = options.sink ?? jsonSink;
  const base = sanitiseFields(options.base);

  const emit = (recordLevel: LogLevel, msg: string, fields?: LogFields): void => {
    if (LEVEL_ORDER[recordLevel] < LEVEL_ORDER[level]) return;
    sink({
      time: new Date().toISOString(),
      level: recordLevel,
      logger: name,
      // The message itself is a developer-authored constant, but truncate
      // defensively in case a caller interpolates something large.
      msg: typeof msg === 'string' && msg.length > 512 ? `${msg.slice(0, 512)}…` : msg,
      ...base,
      ...sanitiseFields(fields),
    });
  };

  return {
    debug: (msg, fields) => emit('debug', msg, fields),
    info: (msg, fields) => emit('info', msg, fields),
    warn: (msg, fields) => emit('warn', msg, fields),
    error: (msg, fields) => emit('error', msg, fields),
    child: (childName, childFields) =>
      createLogger(`${name}.${childName}`, {
        level,
        sink,
        base: { ...base, ...sanitiseFields(childFields) },
      }),
  };
}

/** A logger that discards everything, for tests and for privacy-strict builds. */
export const silentLogger: Logger = createLogger('silent', { level: 'error', sink: () => {} });
