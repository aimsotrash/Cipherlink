/**
 * Real-browser smoke test.
 *
 * Boots the app in Chromium, registers two accounts in separate browser
 * contexts, exchanges messages in both directions, and checks that both sides
 * derive the *same* safety number — which only holds if the WASM MLS engine,
 * the transport and the fingerprint derivation all agree.
 *
 * Not part of `npm test`: it needs Playwright and two running servers. Run it
 * with the dev stack up:
 *
 *   npm run dev                # in one terminal
 *   npm i -D playwright        # once
 *   npx playwright install chromium
 *   npm run test:browser       # in another
 *
 * SMOKE_BASE_URL overrides the client URL. The default is `localhost`, not
 * 127.0.0.1: Vite listens on whatever `localhost` resolves to, which can be
 * ::1 only. SMOKE_CHROMIUM_PATH runs a Chromium other than Playwright's own.
 *
 * This is worth the setup cost. It has already caught two defects the Node
 * suite could not see: form labels that swallowed their help text into the
 * accessible name, and an invited user seeing a raw UUID instead of a
 * username.
 */
import { chromium } from 'playwright';

const BASE = process.env.SMOKE_BASE_URL ?? 'http://localhost:5173';
const shots = process.argv[2] ?? '/tmp/shots';
// Unique per run: the dev server keeps its database between runs.
const suffix = Math.random().toString(36).slice(2, 8);
const ALICE = `alice${suffix}`;
const BOB = `bob${suffix}`;

const executablePath = process.env.SMOKE_CHROMIUM_PATH;
const browser = await chromium.launch(executablePath ? { executablePath } : {});

async function newClient(name) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console: ${m.text()}`);
  });
  await page.goto(BASE, { waitUntil: 'networkidle' });
  return { name, context, page, errors };
}

async function register(client, username) {
  const { page } = client;
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Passphrase', { exact: true }).fill('a-very-long-test-passphrase');
  await page.getByLabel('Confirm passphrase').fill('a-very-long-test-passphrase');
  await page.getByRole('button', { name: /Create account/i }).click();
  await page.getByRole('navigation', { name: 'Conversations' }).waitFor({ timeout: 120_000 });
  console.log(`[${client.name}] registered as ${username}`);
}

const alice = await newClient('alice');
const bob = await newClient('bob');

await register(alice, ALICE);
await register(bob, BOB);

await alice.page.screenshot({ path: `${shots}/1-registered.png`, fullPage: true });

// Alice starts a conversation with Bob.
await alice.page.getByRole('button', { name: 'New conversation' }).click();
await alice.page.getByLabel('Username').fill(BOB);
await alice.page.getByRole('button', { name: 'Start', exact: true }).click();
await alice.page.getByLabel('Message', { exact: true }).waitFor({ timeout: 120_000 });
console.log('[alice] conversation created');

await alice.page.getByLabel('Message', { exact: true }).fill('hello from a real browser');
await alice.page.getByRole('button', { name: 'Send' }).click();

// Bob's conversation list should show the decrypted preview.
await bob.page.getByText('hello from a real browser').waitFor({ timeout: 120_000 });
console.log('[bob] conversation appeared with a decrypted preview');

// Open it and confirm the message body rendered in the thread.
const listText = await bob.page.locator('.conversation-item').first().innerText();
console.log('[bob] conversation row shows:', JSON.stringify(listText));
await bob.page.locator('.conversation-item').first().click();
await bob.page.locator('.bubble-body', { hasText: 'hello from a real browser' }).waitFor({
  timeout: 120_000,
});
console.log('[bob] read the message in the thread');

await alice.page.screenshot({ path: `${shots}/2-alice-chat.png`, fullPage: true });
await bob.page.screenshot({ path: `${shots}/3-bob-chat.png`, fullPage: true });

// Bob replies.
await bob.page.getByLabel('Message', { exact: true }).fill('and hello back');
await bob.page.getByRole('button', { name: 'Send' }).click();
await alice.page.locator('.bubble-body', { hasText: 'and hello back' }).waitFor({ timeout: 120_000 });
console.log('[alice] received the reply');

// Open the verification screen and confirm both sides derive the same number.
await alice.page.getByRole('button', { name: 'Verify safety number' }).click();
await alice.page.getByText(/^\d{5} \d{5}/).waitFor({ timeout: 60_000 });
const aliceNumber = (await alice.page.locator('.safety-number').first().textContent())?.trim();
await alice.page.screenshot({ path: `${shots}/4-verification.png`, fullPage: true });

await bob.page.getByRole('button', { name: 'Verify safety number' }).click();
await bob.page.getByText(/^\d{5} \d{5}/).waitFor({ timeout: 60_000 });
const bobNumber = (await bob.page.locator('.safety-number').first().textContent())?.trim();

console.log('[alice] safety number:', aliceNumber);
console.log('[bob]   safety number:', bobNumber);
console.log('safety numbers match:', aliceNumber === bobNumber);

const allErrors = [...alice.errors, ...bob.errors];
if (allErrors.length > 0) {
  console.log('--- page errors ---');
  for (const e of allErrors.slice(0, 20)) console.log(e);
}

await browser.close();
if (aliceNumber !== bobNumber) {
  console.error('FAIL: safety numbers differ');
  process.exit(1);
}
console.log('BROWSER SMOKE TEST PASSED');
