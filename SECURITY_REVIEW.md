# Security review

Review of the Cipherlink codebase, conducted after implementation was complete.
This is a self-review by the implementer, not an independent audit — it is
subject to exactly the blind spots you would expect from that, and is no
substitute for review by someone who did not write the code.

Scope: the whole repository at the reviewed commit. Method: manual reading of
every security-relevant path (crypto, identity, storage, transport, server
routes, signaling hub), plus adversarial testing.

**Result:** no critical issues. Two high-severity, four medium and five
low-severity issues were found. All high and medium issues, and three of the
low, were fixed; each fix has a regression test. A real-browser smoke test
added during the review found two further defects, recorded below. Remaining limitations are
listed at the end.

---

## Critical

**None found.**

The properties most likely to have been broken were checked adversarially
rather than by inspection alone (`tests/security/serverBlindness.test.ts`): a
hostile operator with the full database, an archive of every relayed frame, and
the ability to tamper, forge, replay and swap attachment blobs recovers no
plaintext and gets nothing accepted by a client.

---

## High

### H1 — Relay accepted envelopes addressed to non-existent devices *(fixed)*

**Where:** `server/src/signaling/hub.ts`, `handleRelaySend`

**Problem:** the relay queue enforced a depth limit *per recipient device*, but
never checked that the recipient device existed. An authenticated client could
invent unlimited recipient addresses and enqueue against each, growing the
server's storage without bound — a straightforward denial-of-service against
the operator, and one that costs the attacker almost nothing.

**Fix:** the hub now verifies the recipient device is registered
(`Registry.deviceExists`) and returns `unknown_device` otherwise.

**Regression test:** `tests/security/hardening.test.ts` — "does not let one
client grow the queue with fabricated recipients".

### H2 — No session re-authentication; dead code implied otherwise *(fixed)*

**Where:** `client/src/app/session.ts`, `client/src/p2p/apiClient.ts`,
`client/src/p2p/signalingClient.ts`

**Problem:** session tokens expire after 12 hours and nothing renewed them.
Once a token expired the WebSocket reconnected in a loop forever and every API
call failed, with no path back short of restarting the app. Worse, the code
*looked* like it handled this: it copied the device authentication private key
into a variable commented "keep a copy for re-authentication after token
expiry", then wiped it without ever using it. A misleading comment over a
long-lived copy of a private key is the kind of thing that survives review
because it reads as if the work was done.

**Fix:** removed the unused key copy. Added `ApiClient.setUnauthorizedHandler`,
which re-authenticates once on a 401 and retries (exactly once, so a genuinely
rejected credential cannot loop), with concurrent 401s coalesced into a single
re-authentication. `SignalingClient.getToken` is now async and refreshes five
minutes before expiry. The private key is re-read from the encrypted store for
each signing operation and wiped immediately, so it is in memory only while in
use.

**Regression tests:** `tests/security/hardening.test.ts` — three tests covering
retry, non-looping, and coalescing.

---

## Medium

### M1 — Conversation peer identity taken from the server-asserted sender *(fixed)*

**Where:** `client/src/messaging/messagingService.ts`, `handleWelcome`

**Problem:** when joining a conversation from a Welcome, the peer's identity
was taken from the transport frame's `from` address, which the server asserts.
A hostile server could therefore label a conversation with one contact's name
while the actual MLS group member was someone else. Safety-number verification
would eventually expose it, but the UI would be actively misleading until then
— and misleading UI is what makes users skip verification.

**Fix:** the peer identity is now read from MLS group state, and a mismatch
between the frame sender and the group membership is logged as a warning.

### M2 — No per-socket rate limiting on the signaling hub *(fixed)*

**Where:** `server/src/signaling/hub.ts`

**Problem:** HTTP routes were rate-limited but the WebSocket was not. One
authenticated client could flood the hub with signaling messages aimed at
another device, or with relay sends, consuming server CPU and spamming a
victim's socket.

**Fix:** a per-connection token bucket (120 burst, 20/second refill) applied
before parsing. The allowance is generous enough for a client draining a large
relay queue and far above interactive use.

**Regression tests:** `tests/security/hardening.test.ts` — allowance exhaustion
and refill.

### M3 — Global body limit sized for attachments *(fixed)*

**Where:** `server/src/app.ts`

**Problem:** the Fastify `bodyLimit` was set to the maximum attachment size
(32 MiB) globally, so a 32 MiB body could be aimed at any JSON endpoint,
including unauthenticated registration — memory amplification for free.

**Fix:** the global limit is 256 KiB; only the blob upload route raises its own
limit.

### M4 — No path to add a contact's new device to an existing conversation *(fixed)*

**Where:** `client/src/messaging/messagingService.ts`

**Problem:** `MlsEngine.addMembers` existed but nothing called it, and the
commit-routing logic depended on `pendingAdds`, which was only set during
initial conversation creation. Had `addMembers` been called, the resulting
Welcome would have been produced and silently dropped — so a contact's new
device would never receive messages, with no error anywhere. A multi-device
system that quietly fails to deliver to a device is a correctness problem that
users experience as lost messages.

**Fix:** added `MessagingService.addDevicesToConversation`, which claims key
packages for devices not already in the group, sets `pendingAdds` around the
call so the Welcome is routed correctly, and warms up the new peer links.

---

## Low

### L1 — Delivery receipts leaked past the identity-change block *(fixed)*

**Where:** `client/src/messaging/messagingService.ts`, `sendControl`

**Problem:** when a contact's identity key changed, outgoing *messages* were
held, but delivery receipts, read receipts and typing indicators were not. A
delivery receipt would confirm to a possible man-in-the-middle that their
injected message had been received — precisely the signal the block exists to
withhold.

**Fix:** `sendControl` applies the same block.

### L2 — Peer-supplied attachment filenames used unsanitised *(fixed)*

**Where:** `client/src/ui/screens/ChatScreen.tsx`

**Problem:** attachment filenames come from the peer (authenticated, but a peer
can be malicious) and were used directly for display and for the download
`download` attribute. Browsers sanitise that attribute, so this was not
directly exploitable, but path components and control characters — including
right-to-left overrides used to disguise a file extension — were passed
through.

**Fix:** `safeFilename()` reduces a name to a basename, strips control
characters and leading dots, caps length, and falls back rather than producing
an empty name. Applied on display and on save, never before encryption, so it
cannot change the AAD the sender committed to.

**Regression tests:** `tests/crypto/attachments.test.ts` — five tests.

### L3 — Misleading no-op in the WebRTC transport policy *(fixed)*

**Where:** `client/src/p2p/webrtc.ts`

`iceTransportPolicy: options.directOnly ? 'all' : 'all'` read like a bug. It
was intentional — WebRTC has no "everything except relay" policy, and `'relay'`
would force the opposite — but code that looks broken invites a "fix" that
would break the direct-only guarantee. Replaced with a constant and an
explanation of how direct-only is actually enforced.

### L4 — A tampered trust record silently downgrades to trust-on-first-use *(not fixed)*

**Where:** `client/src/storage/encryptedStore.ts`, `get`

`EncryptedStore.get` treats a record that fails authentication as absent, so
one corrupt row cannot make the app unopenable. For trust records this means an
attacker with local database *write* access can delete a `verified` marking and
have the device silently revert to unverified trust-on-first-use, losing the
"security code changed" warning for that contact.

**Not fixed** because the alternative is worse: failing closed here means a
single corrupt row locks the user out of the app entirely. An attacker with
local write access also has other, better options. Documented as a limitation;
a production build should distinguish "record missing" from "record failed
authentication" for trust records specifically and surface the latter loudly.

### L5 — Content-Security-Policy `connect-src` is broad *(not fixed)*

**Where:** `client/index.html`

`connect-src` permits `http:`, `https:`, `ws:` and `wss:` generally, because
the server origin is configurable at build time. A deployment should narrow
this to its own origins. Left broad so the development setup works out of the
box; noted in DEVELOPMENT.md deployment notes.

---

## Verified as correct

Checked and found sound, listed so the review's coverage is legible:

- **No primitive is implemented locally.** Every cryptographic operation
  delegates to core-crypto, WebCrypto or `@noble/*`.
- **Nonce handling.** Attachment and vault nonces are generated inside `seal()`
  and cannot be supplied by a caller; attachment keys are single-use. MLS
  handles its own per-message nonces.
- **Randomness.** Only `crypto.getRandomValues`; a missing implementation is a
  hard error, with no `Math.random()` path anywhere.
- **Authentication precedes parsing.** No inbound frame is stored, parsed as an
  application payload, or displayed before MLS authenticates it.
- **Auth challenges are single-use**, deleted before signature verification, so
  a failed attempt still spends the nonce.
- **Signature domain separation** binds a device signature to its purpose, user
  and device, so it cannot be replayed in another context.
- **Timing.** Device registration against an unknown username still performs an
  Argon2id hash; token and digest comparisons are constant-time.
- **Relay acknowledgement is scoped** to the addressed device, so one account
  cannot delete another's queue.
- **`from` is never taken from a payload** in the signaling hub; it comes from
  the authenticated connection.
- **Server schema has nowhere to put plaintext**, and the blob quota is a
  windowed counter specifically so no row links an account to an attachment.
- **Logging.** Redaction is enforced structurally; binary is never rendered.
  Verified against real end-to-end traffic, not just unit tests.
- **XSS.** No `dangerouslySetInnerHTML`; all peer-controlled strings render as
  text through React's escaping.

Two defects found during test development are recorded in the commit history
rather than here, because they were fixed before this review: log redaction did
not match camelCase field names (so it was largely inert), and device
identifiers did not survive a round trip through MLS group state.

A real-browser smoke test (`tests/browser/smoke.mjs`), added while verifying
the review, found two more that the Node suite structurally could not see:

- **Form labels swallowed their help text into the accessible name**, so every
  input announced as e.g. "Passphrase Unlocks the encrypted database on this
  device. There is no recovery…". Fixed with a `Field` component that links
  help text via `aria-describedby`.
- **An invited user saw a raw UUID instead of a username**, because the joining
  side has no contact record and the fix for M1 correctly stopped trusting the
  server-asserted sender for identity. Fixed by resolving the name through a
  public directory lookup by account id — the name is cosmetic and is not what
  safety-number verification checks.

`frame-ancestors` was also removed from the `<meta>` CSP, where browsers ignore
it, and documented as requiring a response header.

---

## Remaining limitations

These are properties the system does not have. They are design limits or
deployment gaps, not bugs.

1. **Not audited.** Self-review and a test suite are not an audit.
2. **Key substitution is undetected until users verify.** The server operates
   the key-package directory and MLS Basic credentials carry no external
   attestation, so a hostile server can man-in-the-middle an unverified
   conversation. Safety numbers are the only defence, and they require a human
   to act. This is the most important limitation in the system.
3. **No post-quantum protection.** X25519 is vulnerable to a future quantum
   adversary, including against recorded traffic.
4. **No browser keychain.** The vault master key sits in JavaScript memory
   while unlocked. Memory zeroing is best-effort — engines copy during garbage
   collection and strings are immutable.
5. **Metadata is exposed to the server**: social graph, timing, volume, IP
   addresses, SDP/ICE. Documented in THREAT_MODEL.md; not mitigated.
6. **No traffic analysis resistance.** No padding, no cover traffic, no delay.
7. **A compromised client build defeats everything.** Reproducible builds and
   binary transparency would be prerequisites for a real deployment.
8. **Rate limiting is per-process.** Both the HTTP limiter and the new socket
   limiter are in-memory and per-instance; a multi-instance deployment needs an
   edge limiter.
9. **Attachments are stored in SQLite.** Correct security properties, wrong
   scaling properties; object storage with the same "opaque bytes, no owner
   column" shape is the right production choice.
10. **MLS commit races are handled by retry, not resolution.** Two peers
    committing simultaneously results in one commit being rejected and retried.
    Correct, but a busy group could see repeated retries.
11. **WebRTC is simulated in tests.** The `PeerLink` state machine is covered
    thoroughly, but real ICE/DTLS negotiation is not exercised by CI. Browser
    testing against a real STUN/TURN deployment is still required.

---

## Conclusion

The system does what it claims within its documented threat model, and the
central claim — that a compromised relay cannot read, forge or usefully replay
message content — is demonstrated by tests that give the adversary its full
capability rather than assumed from the design.

**It is not production-ready, and passing tests does not make it so.** Items
1, 2, 7 and 11 above each need addressing before real users depend on this, and
an independent audit should precede any deployment.
