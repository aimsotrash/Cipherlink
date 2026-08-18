import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Browser builds always bind to the WASM implementation of core-crypto.
      '@corecrypto': '@wireapp/core-crypto/browser',
      '@p2pchat/shared': fileURLToPath(new URL('../shared/src/index.ts', import.meta.url)),
    },
  },
  optimizeDeps: {
    // The WASM glue must not be pre-bundled or the asset URL breaks.
    exclude: ['@wireapp/core-crypto'],
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8787', changeOrigin: true },
      '/ws': { target: 'ws://127.0.0.1:8787', ws: true },
    },
  },
  build: {
    target: 'es2022',
    sourcemap: true,
  },
  worker: { format: 'es' },
});
