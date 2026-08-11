/**
 * Binding to the core-crypto MLS implementation.
 *
 * `@corecrypto` is an alias resolved per platform:
 *   - browser build (Vite):  `@wireapp/core-crypto/browser`  (Rust -> WASM)
 *   - Node build (Vitest):   `@wireapp/core-crypto/native`   (Rust -> N-API)
 *
 * Both are generated from the same Rust source by uniffi and expose an
 * identical API, so the protocol code under test in Node is the same code the
 * browser executes. Only the WASM build needs an explicit module init step.
 *
 * We never reimplement any primitive here. X25519, Ed25519, ChaCha20-Poly1305,
 * HKDF-SHA-256 and the MLS key schedule all live inside core-crypto (which
 * itself builds on RustCrypto/OpenMLS); this file only wires it up.
 */
import * as CoreCryptoModule from '@corecrypto';

export type CoreCryptoApi = typeof CoreCryptoModule;

let initPromise: Promise<CoreCryptoApi> | null = null;

export interface CryptoBackendOptions {
  /**
   * URL of `index_bg.wasm`. Required in the browser, ignored by the native
   * build. The browser entry point resolves this with Vite's `?url` import so
   * the asset is fingerprinted and served from the app's own origin.
   */
  wasmUrl?: string;
}

/**
 * Load and initialise the MLS backend exactly once per process/tab.
 *
 * Safe to call concurrently: callers share a single in-flight promise, so we
 * never race two WASM instantiations.
 */
export function initCryptoBackend(options: CryptoBackendOptions = {}): Promise<CoreCryptoApi> {
  if (!initPromise) {
    initPromise = (async () => {
      const api = CoreCryptoModule as CoreCryptoApi & {
        initWasmModule?: (path?: string) => Promise<void>;
      };
      if (typeof api.initWasmModule === 'function') {
        await api.initWasmModule(options.wasmUrl);
      }
      return api as CoreCryptoApi;
    })().catch((error) => {
      // Allow a retry after a transient failure (e.g. the wasm fetch failed).
      initPromise = null;
      throw error;
    });
  }
  return initPromise;
}

/** Test/teardown helper: forget the cached backend handle. */
export function resetCryptoBackendForTests(): void {
  initPromise = null;
}
