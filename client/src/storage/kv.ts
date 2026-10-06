/**
 * Key/value persistence backends.
 *
 * These store *ciphertext only*. Encryption happens one layer up in
 * {@link EncryptedStore}, so a backend implementation can never accidentally
 * be given plaintext to persist.
 */

export interface KeyValueStore {
  get(key: string): Promise<Uint8Array | undefined>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  /** Keys beginning with `prefix`, in lexicographic order. */
  keys(prefix: string): Promise<string[]>;
  clear(): Promise<void>;
}

export class MemoryKeyValueStore implements KeyValueStore {
  private readonly data = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | undefined> {
    const value = this.data.get(key);
    return value ? Uint8Array.from(value) : undefined;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.data.set(key, Uint8Array.from(value));
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  async keys(prefix: string): Promise<string[]> {
    return [...this.data.keys()].filter((k) => k.startsWith(prefix)).sort();
  }

  async clear(): Promise<void> {
    this.data.clear();
  }
}

/** IndexedDB-backed store for the browser. */
export class IndexedDbKeyValueStore implements KeyValueStore {
  private db: IDBDatabase | null = null;

  constructor(
    private readonly databaseName: string,
    private readonly storeName = 'records',
  ) {}

  private async open(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    this.db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('failed to open IndexedDB'));
    });
    return this.db;
  }

  private async transaction<T>(
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await this.open();
    return new Promise<T>((resolve, reject) => {
      const tx = db.transaction(this.storeName, mode);
      const request = run(tx.objectStore(this.storeName));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
    });
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    const value = await this.transaction<ArrayBuffer | undefined>('readonly', (store) =>
      store.get(key),
    );
    return value ? new Uint8Array(value) : undefined;
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    // Store a copy of the exact bytes; a view over a larger buffer would leak
    // neighbouring data into the database.
    const buffer = value.slice().buffer;
    await this.transaction('readwrite', (store) => store.put(buffer, key));
  }

  async delete(key: string): Promise<void> {
    await this.transaction('readwrite', (store) => store.delete(key));
  }

  async keys(prefix: string): Promise<string[]> {
    const all = await this.transaction<IDBValidKey[]>('readonly', (store) => store.getAllKeys());
    return all
      .map(String)
      .filter((k) => k.startsWith(prefix))
      .sort();
  }

  async clear(): Promise<void> {
    await this.transaction('readwrite', (store) => store.clear());
  }
}

/**
 * Delete every IndexedDB database the app creates: the record stores and
 * core-crypto's per-device databases (`p2pchat-*`), and `core-crypto`, the one
 * database where core-crypto keeps the pages of every MLS key store.
 *
 * Call this before core-crypto starts in the page. core-crypto keeps
 * `core-crypto` open until the page unloads, so a delete issued later stays
 * pending, and would run after a new registration had stored its keys there.
 */
export async function deleteAppDatabases(
  factory: IDBFactory | undefined = globalThis.indexedDB,
): Promise<string[]> {
  if (!factory) return [];
  // Older browsers cannot list databases; the MLS key store's name is fixed.
  const listed =
    typeof factory.databases === 'function' ? await factory.databases() : [{ name: 'core-crypto' }];
  const names = listed
    .map((database) => database.name ?? '')
    .filter((name) => name.startsWith('p2pchat-') || name === 'core-crypto');
  await Promise.all(
    names.map(
      (name) =>
        new Promise<void>((resolve) => {
          const request = factory.deleteDatabase(name);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          // Another tab still has it open. The delete stays queued, and
          // IndexedDB runs it before any later open of the same database.
          request.onblocked = () => resolve();
        }),
    ),
  );
  return names;
}

/**
 * Pick the best available backend: IndexedDB in a browser, memory otherwise.
 * A memory store means nothing survives a reload — acceptable for tests, and
 * the app surfaces it as "this session only" rather than pretending otherwise.
 */
export function createDefaultKeyValueStore(databaseName: string): KeyValueStore {
  if (typeof indexedDB !== 'undefined') {
    return new IndexedDbKeyValueStore(databaseName);
  }
  return new MemoryKeyValueStore();
}
