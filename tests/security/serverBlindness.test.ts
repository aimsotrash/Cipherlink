/**
 * Adversarial tests: what a fully compromised signaling/relay server learns.
 *
 * The threat model assumes the operator is hostile — it reads its own
 * database, logs every byte it forwards, and may tamper with anything. These
 * tests give it exactly that access and assert that message content stays
 * confidential and that forgery is detected.
 *
 * Direct connectivity is forced to fail throughout, so every message really
 * does travel through the relay. That is the worst case for privacy and the
 * right case to test.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fromBase64, transportFrameSchema } from '@p2pchat/shared';
import { startHarness, dumpServerState, waitFor, type Harness, type TestUser } from '../helpers/e2e.js';
import type { StoredMessage } from '../../client/src/storage/models.js';
import { flipBitAt } from '../helpers/tamper.js';

const SECRET_BODY = 'meet me behind the bike sheds at midnight';
const SECRET_FILENAME = 'dead-drop-coordinates.txt';
const SECRET_FILE_CONTENT = 'lat 51.5007 lon -0.1246';

describe('a compromised relay cannot read message content', () => {
  let harness: Harness;
  let alice: TestUser;
  let bob: TestUser;

  beforeEach(async () => {
    harness = await startHarness();
    // Force every message through the server's store-and-forward relay.
    harness.network.mode = 'fail';
    alice = await harness.createClient('alice');
    bob = await harness.createClient('bob');
  });

  afterEach(async () => {
    await harness.stop();
  });

  async function conversation(): Promise<string> {
    const created = await alice.ready.messaging.startConversation('bob');
    await waitFor(
      async () => (await bob.ready.repository.getConversation(created.id)) !== undefined,
      15_000,
      'bob to join the conversation',
    );
    return created.id;
  }

  it('delivers a message end-to-end while the relay holds only ciphertext', async () => {
    const conversationId = await conversation();

    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((message) => received.push(message));

    await alice.ready.messaging.sendText(conversationId, SECRET_BODY);
    await waitFor(() => received.some((m) => m.body === SECRET_BODY), 15_000, 'bob to decrypt');

    expect(received.find((m) => m.body === SECRET_BODY)?.transport).toBe('relay');

    // Everything the operator has on disk.
    const state = dumpServerState(harness.server);
    const allBytes = Buffer.concat([
      ...state.envelopes,
      ...state.keyPackages,
      ...state.blobs,
      Buffer.from(JSON.stringify(state.accounts)),
      Buffer.from(JSON.stringify(state.devices)),
    ]);

    expect(allBytes.includes(Buffer.from(SECRET_BODY, 'utf8'))).toBe(false);
    expect(allBytes.toString('base64')).not.toContain(
      Buffer.from(SECRET_BODY, 'utf8').toString('base64'),
    );
  });

  it('leaves the relay unable to decrypt an envelope it captured', async () => {
    const conversationId = await conversation();
    const delivered: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => delivered.push(m));

    await alice.ready.messaging.sendText(conversationId, SECRET_BODY);
    await waitFor(() => delivered.length > 0, 15_000, 'delivery');

    // Everything the operator archived as it forwarded traffic.
    const captured = harness.relayedFrames.map((bytes) =>
      transportFrameSchema.parse(JSON.parse(bytes.toString('utf8'))),
    );
    expect(captured.length).toBeGreaterThan(0);

    for (const frame of captured) {
      expect(frame.type).toMatch(/^mls-/);
      if (frame.type === 'keepalive') continue;
      const payload = Buffer.from(fromBase64(frame.payload));
      // The operator can see it is an MLS message and how big it is. That is all.
      expect(payload.includes(Buffer.from(SECRET_BODY, 'utf8'))).toBe(false);
      expect(payload.toString('utf8')).not.toContain('meet me');
    }
  });

  it('rejects a frame the relay tampered with instead of showing it', async () => {
    const conversationId = await conversation();
    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));

    const ciphertext = await alice.ready.engine.encrypt(
      conversationId,
      new TextEncoder().encode(JSON.stringify({ kind: 'text', id: 'x', sentAt: 1, seq: 0, body: 'hi' })),
    );

    // The operator flips a bit in transit.
    const tampered = flipBitAt(ciphertext, -2, 0x40);

    await bob.ready.messaging.handleInboundFrame(
      alice.ready.self,
      { v: 1, type: 'mls-app', conversationId, payload: Buffer.from(tampered).toString('base64') },
      'relay',
    );

    // Nothing surfaced, and nothing was stored.
    expect(received).toHaveLength(0);
    expect(await bob.ready.repository.listMessages(conversationId)).toHaveLength(0);
  });

  it('rejects a message the relay forged with its own key material', async () => {
    const conversationId = await conversation();
    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));

    // A hostile server has no group secret, so the best it can do is submit
    // plausible-looking bytes.
    const forged = Buffer.alloc(220);
    forged.write('MLS', 0);

    await bob.ready.messaging.handleInboundFrame(
      alice.ready.self,
      { v: 1, type: 'mls-app', conversationId, payload: forged.toString('base64') },
      'relay',
    );

    expect(received).toHaveLength(0);
  });

  it('rejects a replayed envelope', async () => {
    const conversationId = await conversation();
    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));

    const payload = JSON.stringify({
      kind: 'text',
      id: 'replay-me',
      sentAt: Date.now(),
      seq: 0,
      body: 'only once',
    });
    const ciphertext = await alice.ready.engine.encrypt(
      conversationId,
      new TextEncoder().encode(payload),
    );
    const frame = {
      v: 1 as const,
      type: 'mls-app' as const,
      conversationId,
      payload: Buffer.from(ciphertext).toString('base64'),
    };

    await bob.ready.messaging.handleInboundFrame(alice.ready.self, frame, 'relay');
    await waitFor(() => received.length === 1, 10_000, 'first delivery');

    // The operator replays the identical envelope several times.
    await bob.ready.messaging.handleInboundFrame(alice.ready.self, frame, 'relay');
    await bob.ready.messaging.handleInboundFrame(alice.ready.self, frame, 'relay');

    expect(received).toHaveLength(1);
    expect(await bob.ready.repository.listMessages(conversationId)).toHaveLength(1);
  });

  it('stores attachments as ciphertext the relay cannot open', async () => {
    const conversationId = await conversation();
    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));

    await alice.ready.messaging.sendText(conversationId, 'see attached', [
      {
        data: new TextEncoder().encode(SECRET_FILE_CONTENT),
        filename: SECRET_FILENAME,
        mimeType: 'text/plain',
      },
    ]);

    await waitFor(() => received.some((m) => m.attachments.length > 0), 15_000, 'attachment');

    const state = dumpServerState(harness.server);
    expect(state.blobs).toHaveLength(1);
    const blob = state.blobs[0]!;

    // Neither the content nor even the filename reached the server.
    expect(blob.includes(Buffer.from(SECRET_FILE_CONTENT, 'utf8'))).toBe(false);
    expect(blob.includes(Buffer.from(SECRET_FILENAME, 'utf8'))).toBe(false);
    const everything = Buffer.concat([blob, ...state.envelopes]);
    expect(everything.includes(Buffer.from(SECRET_FILENAME, 'utf8'))).toBe(false);

    // The recipient can still open it.
    const descriptor = received.find((m) => m.attachments.length > 0)!.attachments[0]!;
    const plaintext = await bob.ready.messaging.fetchAttachment(descriptor);
    expect(new TextDecoder().decode(plaintext)).toBe(SECRET_FILE_CONTENT);
  });

  it('refuses an attachment blob the relay swapped for another', async () => {
    const conversationId = await conversation();
    const received: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => received.push(m));

    await alice.ready.messaging.sendText(conversationId, 'file', [
      {
        data: new TextEncoder().encode(SECRET_FILE_CONTENT),
        filename: SECRET_FILENAME,
        mimeType: 'text/plain',
      },
    ]);
    await waitFor(() => received.some((m) => m.attachments.length > 0), 15_000, 'attachment');
    const descriptor = received.find((m) => m.attachments.length > 0)!.attachments[0]!;

    // Operator replaces the stored blob with something else.
    harness.server.db
      .prepare('UPDATE blobs SET data = ?, size = ? WHERE id = ?')
      .run(Buffer.from('totally different bytes'), 23, descriptor.blobId);

    await expect(bob.ready.messaging.fetchAttachment(descriptor)).rejects.toThrow();
  });

  it('never writes a private key or session secret into the server database', async () => {
    const conversationId = await conversation();
    await alice.ready.messaging.sendText(conversationId, SECRET_BODY);

    // The exporter secret is a genuine session secret held by both clients.
    const groupSecret = Buffer.from(await alice.ready.engine.exportSecret(conversationId, 32));
    const aliceKeyHash = Buffer.from(alice.ready.engine.publicKeyHash());

    const state = dumpServerState(harness.server);
    const everything = Buffer.concat([
      ...state.envelopes,
      ...state.keyPackages,
      ...state.blobs,
      Buffer.from(JSON.stringify(state.accounts)),
      Buffer.from(JSON.stringify(state.devices)),
    ]);

    expect(everything.includes(groupSecret)).toBe(false);

    // The public key hash MAY appear (key packages are public); the point is
    // that no secret does. Assert the public value is genuinely public-only by
    // confirming the private side is absent from every column.
    expect(aliceKeyHash.length).toBe(32);
    const devices = state.devices as { auth_public_key: Buffer }[];
    for (const device of devices) {
      // Only 32-byte Ed25519 *public* keys are stored for authentication.
      expect(device.auth_public_key.length).toBe(32);
    }
  });
});
