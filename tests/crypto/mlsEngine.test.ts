import { describe, expect, it } from 'vitest';
import { MlsEngineError, newConversationId } from '../../client/src/crypto/mls.js';
import {
  TestNetwork,
  createTestClient,
  deliverCommits,
  establishConversation,
  exchange,
} from '../helpers/mlsHarness.js';
import { flipBitAt } from '../helpers/tamper.js';

describe('MLS session engine', () => {
  it('establishes a session and round-trips a message', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();

    await establishConversation(alice, bob, conversationId);

    const { received } = await exchange(network, alice, bob, conversationId, 'hello bob');
    expect(received).toBe('hello bob');

    const reply = await exchange(network, bob, alice, conversationId, 'hello alice');
    expect(reply.received).toBe('hello alice');
  });

  it('produces ciphertext that does not contain the plaintext', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const secret = 'attack at dawn';
    const { ciphertext } = await exchange(network, alice, bob, conversationId, secret);

    const haystack = Buffer.from(ciphertext).toString('latin1');
    expect(haystack).not.toContain(secret);
  });

  it('rejects tampered ciphertext instead of returning garbage', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const ciphertext = await alice.engine.encrypt(
      conversationId,
      new TextEncoder().encode('genuine message'),
    );

    // Flip a bit in the AEAD-protected region.
    const tampered = flipBitAt(ciphertext, -4);

    await expect(bob.engine.decrypt(conversationId, tampered)).rejects.toBeInstanceOf(
      MlsEngineError,
    );
  });

  it('rejects a replayed message', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const ciphertext = await alice.engine.encrypt(
      conversationId,
      new TextEncoder().encode('only once'),
    );
    const first = await bob.engine.decrypt(conversationId, ciphertext);
    expect(first.kind).toBe('application');

    await expect(bob.engine.decrypt(conversationId, ciphertext)).rejects.toMatchObject({
      name: 'MlsEngineError',
    });
  });

  it('rotates keying material and keeps the session usable', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const epochBefore = await alice.engine.epoch(conversationId);
    const secretBefore = await alice.engine.exportSecret(conversationId, 32);

    await alice.engine.rotateKeys(conversationId);
    await deliverCommits(alice, [bob]);

    const epochAfter = await alice.engine.epoch(conversationId);
    const secretAfter = await alice.engine.exportSecret(conversationId, 32);

    expect(epochAfter).toBeGreaterThan(epochBefore);
    expect(Buffer.from(secretAfter)).not.toEqual(Buffer.from(secretBefore));
    expect(await bob.engine.epoch(conversationId)).toBe(epochAfter);

    const { received } = await exchange(network, alice, bob, conversationId, 'after rotation');
    expect(received).toBe('after rotation');
  });

  it('derives identical exporter secrets on both peers', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const a = await alice.engine.exportSecret(conversationId, 32);
    const b = await bob.engine.exportSecret(conversationId, 32);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });

  it('reports member identities that both sides agree on', async () => {
    const network = new TestNetwork();
    const alice = await createTestClient(network);
    const bob = await createTestClient(network);
    const conversationId = newConversationId();
    await establishConversation(alice, bob, conversationId);

    const fromAlice = await alice.engine.memberIdentities(conversationId, [bob.address]);
    const fromBob = await bob.engine.memberIdentities(conversationId, [bob.address]);

    expect(fromAlice).toHaveLength(1);
    expect(fromAlice[0]!.thumbprint).toBeTruthy();
    expect(fromAlice[0]!.thumbprint).toBe(fromBob[0]!.thumbprint);
  });
});
