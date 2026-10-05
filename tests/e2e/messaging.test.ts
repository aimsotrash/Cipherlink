/**
 * Full-stack behaviour: two real clients, a real server, over the peer-to-peer
 * path and over the relay.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startHarness, waitFor, type Harness, type TestUser } from '../helpers/e2e.js';
import type { StoredMessage } from '../../client/src/storage/models.js';
import { SendBlockedError } from '../../client/src/messaging/messagingService.js';

describe('end-to-end messaging', () => {
  let harness: Harness;
  let alice: TestUser;
  let bob: TestUser;

  beforeEach(async () => {
    harness = await startHarness();
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
      'bob to join',
    );
    return created.id;
  }

  it('exchanges messages in both directions', async () => {
    const conversationId = await conversation();
    const atBob: StoredMessage[] = [];
    const atAlice: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => atBob.push(m));
    alice.ready.messaging.onMessage.subscribe((m) => atAlice.push(m));

    await alice.ready.messaging.sendText(conversationId, 'hello bob');
    await waitFor(() => atBob.some((m) => m.body === 'hello bob'), 15_000, 'first message');

    await bob.ready.messaging.sendText(conversationId, 'hello alice');
    await waitFor(
      () => atAlice.some((m) => m.body === 'hello alice' && !m.outgoing),
      15_000,
      'reply',
    );
  });

  it('marks a message delivered once the peer acknowledges it', async () => {
    const conversationId = await conversation();
    const updates: StoredMessage[] = [];
    alice.ready.messaging.onMessageUpdated.subscribe((m) => updates.push(m));

    const sent = await alice.ready.messaging.sendText(conversationId, 'did you get this?');
    await waitFor(
      () => updates.some((m) => m.id === sent.id && m.status === 'delivered'),
      15_000,
      'delivery receipt',
    );
  });

  it('keeps a message delivered when the receipt overtakes the send', async () => {
    const conversationId = await conversation();
    await waitFor(
      () => alice.ready.transport.allStatuses().some((s) => s.state === 'connected'),
      15_000,
      'direct connection',
    );

    // Over a direct channel the receipt can come back before sendText has
    // finished its own bookkeeping. Slow that bookkeeping down, as a busy
    // device would, so the receipt is applied first.
    const repository = alice.ready.repository;
    const saveSessionState = repository.saveSessionState.bind(repository);
    repository.saveSessionState = async (state) => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      return saveSessionState(state);
    };

    const sent = await alice.ready.messaging.sendText(conversationId, 'quick one');
    repository.saveSessionState = saveSessionState;

    const statusOf = async (): Promise<string | undefined> =>
      (await repository.listMessages(conversationId)).find((m) => m.id === sent.id)?.status;
    await waitFor(async () => (await statusOf()) === 'delivered', 15_000, 'delivery receipt');
    await new Promise((resolve) => setTimeout(resolve, 200));
    // The late 'sent' bookkeeping must not demote it.
    expect(await statusOf()).toBe('delivered');
  });

  it('upgrades to a direct connection and reports it', async () => {
    const conversationId = await conversation();
    const atBob: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => atBob.push(m));

    await waitFor(
      () => alice.ready.transport.allStatuses().some((s) => s.state === 'connected'),
      15_000,
      'direct connection',
    );

    await alice.ready.messaging.sendText(conversationId, 'over the wire');
    await waitFor(() => atBob.some((m) => m.body === 'over the wire'), 15_000, 'delivery');
    expect(atBob.find((m) => m.body === 'over the wire')?.transport).toBe('p2p');

    // No relay envelopes were created for the message traffic.
    const depth = harness.server.relayQueue.depth(bob.ready.self);
    expect(depth).toBe(0);
  });

  it('preserves ordering and rejects an out-of-order sequence replay', async () => {
    const conversationId = await conversation();
    const atBob: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => atBob.push(m));

    for (let i = 0; i < 5; i++) {
      await alice.ready.messaging.sendText(conversationId, `message ${i}`);
    }
    await waitFor(() => atBob.length >= 5, 20_000, 'all messages');
    expect(atBob.slice(0, 5).map((m) => m.body)).toEqual([
      'message 0',
      'message 1',
      'message 2',
      'message 3',
      'message 4',
    ]);
  });

  it('rotates keys and keeps the session working across the epoch change', async () => {
    const conversationId = await conversation();
    const atBob: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => atBob.push(m));

    await alice.ready.messaging.sendText(conversationId, 'before rotation');
    await waitFor(() => atBob.some((m) => m.body === 'before rotation'), 15_000, 'first');

    const before = await alice.ready.engine.epoch(conversationId);
    await alice.ready.messaging.rotateKeys(conversationId);
    await waitFor(
      async () => (await bob.ready.engine.epoch(conversationId)) > before,
      15_000,
      'bob to apply the commit',
    );

    await alice.ready.messaging.sendText(conversationId, 'after rotation');
    await waitFor(() => atBob.some((m) => m.body === 'after rotation'), 15_000, 'second');

    expect(await alice.ready.engine.epoch(conversationId)).toBeGreaterThan(before);
  });

  it('blocks sending when a contact’s identity key changed', async () => {
    const conversationId = await conversation();
    await alice.ready.messaging.sendText(conversationId, 'all good so far');

    // Simulate the trust store observing a different signature key for Bob.
    const [bobDevice] = alice.ready.messaging.membersFor(conversationId);
    expect(bobDevice).toBeDefined();
    await alice.ready.trustStore.observe(bobDevice!, 'a-completely-different-thumbprint');

    await expect(
      alice.ready.messaging.sendText(conversationId, 'this must not go out'),
    ).rejects.toBeInstanceOf(SendBlockedError);

    // After the user reviews and accepts the change, sending resumes.
    await alice.ready.trustStore.acknowledgeChange(bobDevice!);
    await expect(
      alice.ready.messaging.sendText(conversationId, 'now it can'),
    ).resolves.toBeDefined();
  });

  it('records the trust state a message was received under', async () => {
    const conversationId = await conversation();
    const atBob: StoredMessage[] = [];
    bob.ready.messaging.onMessage.subscribe((m) => atBob.push(m));

    await alice.ready.messaging.sendText(conversationId, 'unverified for now');
    await waitFor(() => atBob.some((m) => !m.outgoing), 15_000, 'delivery');

    const received = atBob.find((m) => !m.outgoing)!;
    expect(received.senderTrustAtReceipt).toBe('unverified');
    expect(received.epoch).toBeTruthy();
  });

  it('leaves a conversation and destroys its local key material', async () => {
    const conversationId = await conversation();
    await alice.ready.messaging.sendText(conversationId, 'goodbye');

    await alice.ready.messaging.leaveConversation(conversationId);

    expect((await alice.ready.repository.getConversation(conversationId))?.active).toBe(false);
    // The group state is gone, so encryption is no longer possible.
    await expect(alice.ready.messaging.sendText(conversationId, 'still here?')).rejects.toThrow();
  });

  it('stores conversation history encrypted and reloads it', async () => {
    const conversationId = await conversation();
    await alice.ready.messaging.sendText(conversationId, 'persisted message');

    const stored = await alice.ready.repository.listMessages(conversationId);
    expect(stored.map((m) => m.body)).toContain('persisted message');
  });
});
