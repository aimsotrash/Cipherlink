/**
 * Logging must never leak message content or key material.
 *
 * Two layers are checked: the logger's own redaction rules, and the real logs
 * produced by a full end-to-end exchange.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createLogger,
  REDACTED,
  sanitiseValue,
  type LogRecord,
} from '@p2pchat/shared';
import { startHarness, waitFor, type Harness, type TestUser } from '../helpers/e2e.js';
import type { StoredMessage } from '../../client/src/storage/models.js';

describe('structured logger redaction', () => {
  function capture(): { logger: ReturnType<typeof createLogger>; records: LogRecord[] } {
    const records: LogRecord[] = [];
    return {
      logger: createLogger('test', { level: 'debug', sink: (record) => records.push(record) }),
      records,
    };
  }

  it('redacts sensitive field names at the top level', () => {
    const { logger, records } = capture();
    logger.info('event', {
      privateKey: 'super-secret',
      sessionSecret: 'another',
      messageBody: 'hello world',
      plaintext: 'hello world',
      token: 'abc',
      conversationId: 'safe-to-log',
    });

    const record = records[0]!;
    expect(record.privateKey).toBe(REDACTED);
    expect(record.sessionSecret).toBe(REDACTED);
    expect(record.messageBody).toBe(REDACTED);
    expect(record.plaintext).toBe(REDACTED);
    expect(record.token).toBe(REDACTED);
    expect(record.conversationId).toBe('safe-to-log');
  });

  it('redacts sensitive field names nested inside objects', () => {
    const { logger, records } = capture();
    logger.info('event', { envelope: { id: 'e1', payload: 'ciphertext-here', nested: { key: 'k' } } });
    const envelope = records[0]!.envelope as Record<string, unknown>;
    expect(envelope.id).toBe('e1');
    expect(envelope.payload).toBe(REDACTED);
    expect((envelope.nested as Record<string, unknown>).key).toBe(REDACTED);
  });

  it('never renders raw bytes, only their length', () => {
    const { logger, records } = capture();
    const secret = new Uint8Array([1, 2, 3, 4, 5]);
    logger.info('event', { blob: secret });
    expect(records[0]!.blob).toBe('<bytes:5>');
    expect(JSON.stringify(records[0])).not.toContain('1,2,3');
  });

  it('truncates long strings so a payload cannot be dumped whole', () => {
    const { logger, records } = capture();
    logger.info('event', { note: 'x'.repeat(5000) });
    expect(String(records[0]!.note).length).toBeLessThan(600);
  });

  it('does not include an error stack, which can embed argument values', () => {
    const { logger, records } = capture();
    logger.error('failed', { cause: new Error('boom') });
    expect(JSON.stringify(records[0])).not.toContain('at ');
  });

  it('survives circular structures', () => {
    const cyclic: Record<string, unknown> = { name: 'a' };
    cyclic.self = cyclic;
    expect(() => sanitiseValue(cyclic)).not.toThrow();
  });
});

describe('logs from a real exchange contain no plaintext', () => {
  let harness: Harness;
  let alice: TestUser;
  let bob: TestUser;
  const SECRET = 'the eagle lands at dawn on platform nine';

  beforeEach(async () => {
    harness = await startHarness();
    harness.network.mode = 'fail'; // force relay so the server logs the most
    alice = await harness.createClient('alice');
    bob = await harness.createClient('bob');
  });

  afterEach(async () => {
    await harness.stop();
  });

  it('keeps the message body out of both client and server logs', async () => {
    const conversation = await alice.ready.messaging.startConversation('bob');
    await waitFor(
      async () => (await bob.ready.repository.getConversation(conversation.id)) !== undefined,
      15_000,
      'bob to join',
    );

    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));
    await alice.ready.messaging.sendText(conversation.id, SECRET);
    await waitFor(() => received.some((m) => m.body === SECRET), 15_000, 'delivery');

    const allLogs = JSON.stringify([...harness.serverLogs, ...alice.logs, ...bob.logs]);

    expect(allLogs).not.toContain(SECRET);
    expect(allLogs).not.toContain('eagle');
    // The passphrase must never appear either.
    expect(allLogs).not.toContain('correct-horse-battery');
  });

  it('logs routing facts without logging the frames themselves', async () => {
    const conversation = await alice.ready.messaging.startConversation('bob');
    await waitFor(
      async () => (await bob.ready.repository.getConversation(conversation.id)) !== undefined,
      15_000,
      'bob to join',
    );
    await alice.ready.messaging.sendText(conversation.id, SECRET);

    // Something was logged (so the assertion above is not vacuous)...
    expect(harness.serverLogs.length).toBeGreaterThan(0);

    // ...but no log record carries a frame payload.
    for (const record of harness.serverLogs) {
      expect(record).not.toHaveProperty('frame');
      const serialised = JSON.stringify(record);
      expect(serialised).not.toContain(SECRET);
    }
  });
});
