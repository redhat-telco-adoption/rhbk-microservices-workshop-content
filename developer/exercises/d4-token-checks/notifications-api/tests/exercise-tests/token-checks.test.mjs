// Exercise D4 for notifications-api: every forged token gets 401, a valid one from the wrong
// client or without the role gets 403. The test starts src/server.js against a mock issuer.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { after, before, test } from 'node:test';
import { FORGERIES, MockIssuer } from './mock-jwks.mjs';

const AUDIENCE = 'notifications-api';
const machine = {
  azp: 'orders-api',
  resource_access: { 'notifications-api': { roles: ['notifier'] } },
};
let issuer;
let server;
let base;

async function freePort() {
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

before(async () => {
  issuer = await MockIssuer.start();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  server = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, ISSUER: issuer.issuer, PORT: String(port), NODE_ENV: 'test' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/health/live`)).ok) return;
    } catch { /* not listening yet */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('src/server.js did not start');
});

after(async () => {
  server?.kill();
  await issuer?.stop();
});

async function notify(token) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${base}/notify`, { method: 'POST', headers, body: '{"orderId":"order-1"}' });
  return response.status;
}

test('a client-credentials token from orders-api is accepted', async () => {
  assert.equal(await notify(await issuer.token(AUDIENCE, machine)), 202);
});

for (const kind of FORGERIES) {
  test(`${kind} is rejected with 401`, async () => {
    assert.equal(await notify(await issuer.forge(kind, AUDIENCE, machine)), 401, `${kind} was accepted`);
  });
}

test('the user token orders-api received is rejected with 401', async () => {
  assert.equal(await notify(await issuer.token('orders-api', machine)), 401);
});

test('no token is 401', async () => {
  assert.equal(await notify(null), 401);
});

test('a valid token from another client, or without the notifier role, is 403', async () => {
  assert.equal(await notify(await issuer.token(AUDIENCE, { ...machine, azp: 'bff' })), 403);
  assert.equal(await notify(await issuer.token(AUDIENCE, { ...machine, resource_access: {} })), 403);
});
