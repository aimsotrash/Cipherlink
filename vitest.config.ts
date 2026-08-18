import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts', '{client,server,shared}/src/**/*.test.ts'],
    environment: 'node',
    globals: false,
    // core-crypto's native binding loads a shared library and MLS operations are
    // genuinely expensive; give the suite room rather than papering over it.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // The uniffi native binding keeps process-global state, so give each test
    // file its own process rather than sharing one worker.
    pool: 'forks',
    isolate: true,
  },
  resolve: {
    alias: {
      // Tests exercise the same protocol code the browser runs, but bound to the
      // Node-native core-crypto build instead of the WASM one.
      '@corecrypto': '@wireapp/core-crypto/native',
    },
  },
});
