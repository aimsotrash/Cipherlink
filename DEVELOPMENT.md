# Development

## Requirements

- **Node 22 or newer.** The server runs TypeScript directly via `tsx`, and the
  test suite relies on Node's global `WebSocket` and `crypto.subtle`.
- No system dependencies beyond a C toolchain for `better-sqlite3`, which ships
  prebuilt binaries for common platforms.

## Setup

```bash
npm install
npm run dev
```

`npm run dev` starts both processes:

| Process | Port | Notes |
| --- | --- | --- |
| Signaling + relay server | 8787 | SQLite at `server/data/p2pchat.sqlite` |
| Client (Vite) | 5173 | Proxies `/api` and `/ws` to the server |

To exercise two users on one machine, open the client in two browser profiles,
or one normal and one private window — they need separate `localStorage` and
IndexedDB.

## Commands

```bash
npm test              # full suite (127 tests)
npm run test:watch
npm run typecheck     # every workspace
npm run build         # production client bundle
npm run lint
npm run format
```

Individual suites:

```bash
npx vitest run tests/crypto        # MLS, attachments, vault, identity
npx vitest run tests/networking    # transport state machine, fallback
npx vitest run tests/server        # registry, signaling hub
npx vitest run tests/security      # adversarial server, logging, API auth
npx vitest run tests/e2e           # full stack, real server
```

### Real-browser smoke test

Not part of `npm test`, because it needs Playwright and a running dev stack:

```bash
npm run dev            # terminal 1
npm i -D playwright    # once
npm run test:browser   # terminal 2
```

It registers two accounts in separate browser contexts, exchanges messages,
and asserts both sides derive the same safety number. Worth running before any
release: it exercises the WASM crypto path, which the Node suite does not.

## Project layout

```
shared/src/           protocol schemas (zod), byte helpers, redacting logger
client/src/
  crypto/             MLS engine, attachments, AEAD, RNG, core-crypto binding
  identity/           device auth key, safety numbers, trust store
  messaging/          message lifecycle and policy
  p2p/                WebRTC, peer link, transport manager, signaling, REST
  storage/            vault, encrypted store, KV backends, repositories, models
  ui/                 React components and screens
  app/                session assembly
server/src/
  identity/           registry: accounts, devices, auth, key packages
  signaling/          WebSocket hub
  relay/              queue and blob store
  app.ts              routes and middleware
tests/
  helpers/            E2E harness, simulated WebRTC, MLS harness, tamper utils
```

## The core-crypto binding

`@corecrypto` is a path alias resolved differently per environment:

| Environment | Resolves to | Configured in |
| --- | --- | --- |
| Browser (Vite) | `@wireapp/core-crypto/browser` (WASM) | `client/vite.config.ts` |
| Tests (Vitest/Node) | `@wireapp/core-crypto/native` (N-API) | `vitest.config.ts` |
| TypeScript | the browser `.d.ts` | `client/tsconfig.json` paths |

Both builds are generated from the same Rust source by uniffi and expose the
same API, so tests exercise the protocol code the browser runs.

The Node build needs `@ubjs/core` and `@ubjs/node` (uniffi's N-API runtime);
they are devDependencies of the client workspace.

The WASM asset is **not** exported from the package's `exports` map, so
`client/scripts/stage-wasm.mjs` copies it into `client/public/corecrypto.wasm`
on `predev` and `prebuild`. This keeps cryptographic code same-origin, which
the app's Content-Security-Policy requires. Do not load it from a CDN.

## Configuration

Server, via environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8787` | |
| `DATABASE_PATH` | `server/data/p2pchat.sqlite` | `:memory:` for ephemeral |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `CORS_ORIGINS` | localhost dev origins | Comma-separated |
| `ICE_SERVERS` | Google STUN | JSON array of `RTCIceServer` |
| `MAX_BLOB_BYTES` | 33554432 | Per-attachment ceiling |
| `BLOB_QUOTA_BYTES` | 536870912 | Per-account, per 24h |
| `TRUST_PROXY` | `false` | Set when behind a reverse proxy |

Client, via Vite env:

| Variable | Default |
| --- | --- |
| `VITE_API_BASE_URL` | `''` (same origin) |
| `VITE_WS_URL` | `ws(s)://<host>/ws` |

## Testing approach

**Nothing on the security path is stubbed.** The end-to-end harness
(`tests/helpers/e2e.ts`) boots the real Fastify app with the real SQLite schema
and runs real client sessions — real MLS engine, real vault, real trust store —
over a real WebSocket.

The one simulated component is WebRTC, because Node has no implementation and
because the tests need to *force* direct connectivity to fail, drop
mid-session, or recover. `tests/helpers/fakeTransport.ts` provides a rendezvous
that drives the same `PeerLink` state machine the browser uses.

`tests/helpers/e2e.ts` also taps the relay queue to archive every frame that
passes through, modelling an operator who logs everything — otherwise the
adversary would be under-modelled, since envelopes are deleted on
acknowledgement.

### Writing security tests

Assert on what an attacker *has*, not on what the code does. The pattern used
throughout `tests/security/serverBlindness.test.ts`:

```ts
const state = dumpServerState(harness.server);
const everything = Buffer.concat([...state.envelopes, ...state.blobs, /* ... */]);
expect(everything.includes(Buffer.from(SECRET))).toBe(false);
```

## Deployment notes

This has not been deployed. Before it is:

- **Terminate TLS properly** and set HSTS. The security model assumes an
  authenticated channel to the server.
- **Send the Content-Security-Policy as a response header**, not only the
  `<meta>` tag in `index.html`. `frame-ancestors` is ignored in a meta element,
  so clickjacking protection needs the header. Narrow `connect-src` to your own
  origins at the same time.
- **Add an edge rate limiter.** The in-process token bucket in
  `server/src/rateLimit.ts` is per-instance and per-IP; it is not a substitute.
- **Move blobs out of SQLite.** Attachments in a `BLOB` column will not scale;
  object storage with the same "opaque bytes, no owner column" property is the
  right shape.
- **Run TURN if you need connectivity behind restrictive NATs** — and document
  it, because a TURN server is on the media path.
- **Back up nothing you do not need.** The relay's value as a target is
  proportional to what it retains.
- **Establish a security contact and disclosure process.**
- **Get an audit** before real users depend on it.

## Contributing rules

1. Do not implement a cryptographic primitive. If you think you need one, you
   need a library.
2. Do not pass a message body, key, or secret to the logger. The redaction
   layer is a backstop.
3. Authenticate before you parse, store or display.
4. New security-relevant behaviour needs a test that would fail without it.
5. Keep security copy in the UI accurate. Never "secure", "anonymous",
   "unhackable" or "100% private"; distinguish "encrypted" from "verified".
