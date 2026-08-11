/**
 * Test harness that wires two or more {@link MlsEngine} instances together
 * through an in-memory "network" we fully control.
 *
 * The network stands in for the untrusted transport (DataChannel or relay).
 * Because every frame passes through `TestNetwork`, tests can inspect, drop,
 * duplicate, reorder or tamper with exactly the bytes a hostile relay would
 * see — which is how the server-cannot-decrypt tests are written.
 */
import { randomUUID } from 'node:crypto';
import {
  MlsEngine,
  type MlsClientAddress,
  type OutboundCommitBundle,
} from '../../client/src/crypto/mls.js';

export interface CapturedFrame {
  readonly from: MlsClientAddress;
  readonly kind: 'commit' | 'welcome' | 'application';
  readonly conversationId: string;
  readonly bytes: Uint8Array;
}

/** Records every byte that would have crossed the untrusted network. */
export class TestNetwork {
  readonly frames: CapturedFrame[] = [];

  record(frame: CapturedFrame): void {
    this.frames.push(frame);
  }

  /** Everything a relay operator would have on disk. */
  allBytes(): Uint8Array[] {
    return this.frames.map((f) => f.bytes);
  }

  clear(): void {
    this.frames.length = 0;
  }
}

export interface TestClient {
  readonly address: MlsClientAddress;
  readonly engine: MlsEngine;
  /** Commits/welcomes this client emitted and that have not yet been delivered. */
  readonly outbox: OutboundCommitBundle[];
}

let deviceCounter = 1;

export async function createTestClient(
  network: TestNetwork,
  options: { userId?: string; deviceId?: string } = {},
): Promise<TestClient> {
  const address: MlsClientAddress = {
    userId: options.userId ?? randomUUID(),
    deviceId: options.deviceId ?? (deviceCounter++).toString(16),
  };
  const outbox: OutboundCommitBundle[] = [];

  const engine = await MlsEngine.create({
    address,
    storage: { kind: 'memory' },
    onOutboundCommit: async (bundle) => {
      outbox.push(bundle);
      network.record({
        from: address,
        kind: 'commit',
        conversationId: bundle.conversationId,
        bytes: bundle.commit,
      });
      if (bundle.welcome) {
        network.record({
          from: address,
          kind: 'welcome',
          conversationId: bundle.conversationId,
          bytes: bundle.welcome,
        });
      }
    },
  });

  return { address, engine, outbox };
}

/**
 * Establish a two-party conversation: `initiator` claims a key package from
 * `responder`, creates the group, and the Welcome is delivered.
 */
export async function establishConversation(
  initiator: TestClient,
  responder: TestClient,
  conversationId: string,
): Promise<void> {
  const [keyPackage] = await responder.engine.generateKeyPackages(1);
  await initiator.engine.createConversation(conversationId, [keyPackage!]);

  const bundle = initiator.outbox.shift();
  if (!bundle?.welcome) throw new Error('expected a Welcome message from the Add commit');
  const joined = await responder.engine.joinFromWelcome(bundle.welcome);
  if (joined !== conversationId) {
    throw new Error(`responder joined ${joined}, expected ${conversationId}`);
  }
}

/** Send an application message and return the ciphertext plus the decrypted result. */
export async function exchange(
  network: TestNetwork,
  sender: TestClient,
  receiver: TestClient,
  conversationId: string,
  plaintext: string,
): Promise<{ ciphertext: Uint8Array; received: string }> {
  const ciphertext = await sender.engine.encrypt(
    conversationId,
    new TextEncoder().encode(plaintext),
  );
  network.record({
    from: sender.address,
    kind: 'application',
    conversationId,
    bytes: ciphertext,
  });
  const outcome = await receiver.engine.decrypt(conversationId, ciphertext);
  if (outcome.kind !== 'application') {
    throw new Error(`expected an application message, got ${outcome.kind}`);
  }
  return { ciphertext, received: new TextDecoder().decode(outcome.plaintext) };
}

/** Deliver every pending commit from `from` to each of `to`. */
export async function deliverCommits(from: TestClient, to: TestClient[]): Promise<void> {
  let bundle = from.outbox.shift();
  while (bundle) {
    for (const peer of to) {
      await peer.engine.decrypt(bundle.conversationId, bundle.commit);
    }
    bundle = from.outbox.shift();
  }
}
