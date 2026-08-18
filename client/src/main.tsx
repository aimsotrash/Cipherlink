/**
 * Browser entry point.
 *
 * The core-crypto WASM module is staged into `public/` by
 * `scripts/stage-wasm.mjs` and loaded from this app's own origin, which is what
 * the Content-Security-Policy in index.html allows. Cryptographic code is never
 * fetched from a third-party origin.
 */
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './ui/App.js';
import { SessionProvider } from './ui/SessionContext.js';
import './ui/styles.css';

const wasmUrl = `${import.meta.env.BASE_URL}corecrypto.wasm`;
const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? '';
const wsUrl =
  import.meta.env.VITE_WS_URL ??
  `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

const container = document.getElementById('root');
if (!container) throw new Error('missing #root');

createRoot(container).render(
  <StrictMode>
    <SessionProvider config={{ apiBaseUrl, wsUrl, wasmUrl }}>
      <App />
    </SessionProvider>
  </StrictMode>,
);
