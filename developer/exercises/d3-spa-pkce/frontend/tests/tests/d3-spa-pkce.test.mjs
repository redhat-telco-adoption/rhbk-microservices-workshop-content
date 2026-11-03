// Exercise D3: the SPA signs in with authorization code and PKCE, keeps tokens only in
// memory, and refreshes the access token before it expires. Node runs src/auth.ts directly
// (type stripping) against a minimal window whose storage records every write.
import assert from 'node:assert/strict';
import { before, test } from 'node:test';

function recordingStorage(name, writes) {
  const items = new Map();
  return {
    get length() { return items.size; },
    key: (index) => [...items.keys()][index] ?? null,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => { writes.push(`${name}.setItem(${key})`); items.set(key, String(value)); },
    removeItem: (key) => { items.delete(key); },
    clear: () => { items.clear(); },
  };
}

const writes = [];
let auth;
let manager;
let User;

before(async () => {
  const localStorage = recordingStorage('localStorage', writes);
  const sessionStorage = recordingStorage('sessionStorage', writes);
  globalThis.window = { location: { origin: 'https://spa.example.test', href: 'https://spa.example.test/' },
    localStorage, sessionStorage };
  globalThis.localStorage = localStorage;
  globalThis.sessionStorage = sessionStorage;
  ({ User } = await import('oidc-client-ts'));
  auth = await import('../src/auth.ts');
  manager = auth.configureSpaAuth({
    authMode: 'spa', issuer: 'https://keycloak.example.test/realms/workshop', spaClientId: 'spa',
    ordersBaseUrl: 'https://orders.example.test', legacyBaseUrl: '', legacyEnabled: false,
  });
});

function signedIn(token, secondsLeft) {
  return new User({
    access_token: token, token_type: 'Bearer', scope: 'openid profile email',
    profile: { sub: 'alice', iss: 'https://keycloak.example.test/realms/workshop', aud: 'spa', exp: 0, iat: 0 },
    expires_at: Math.floor(Date.now() / 1000) + secondsLeft,
  });
}

test('sign-in uses the authorization code flow with PKCE', () => {
  assert.equal(manager.settings.response_type, 'code');
  assert.equal(manager.settings.disablePKCE, false, 'PKCE must not be disabled');
});

test('tokens and sign-in state never touch browser storage', async () => {
  await manager.storeUser(signedIn('stored-token', 300));
  await manager.settings.stateStore.set('state-id', '{"code_verifier":"verifier"}');
  assert.deepEqual(writes, [], `browser storage was written: ${writes.join(', ')}`);
  await manager.removeUser();
});

test('a fresh access token is returned as is', async () => {
  manager.signinSilent = async () => assert.fail('refreshed a token that is still fresh');
  await manager.events.load(signedIn('fresh-token', 300));
  assert.equal(await auth.accessToken(), 'fresh-token');
});

test('a token that expires within 30 seconds is refreshed first, once for concurrent calls', async () => {
  let refreshes = 0;
  manager.signinSilent = async () => {
    refreshes += 1;
    await new Promise((resolve) => setTimeout(resolve, 10));
    return signedIn('refreshed-token', 300);
  };
  await manager.events.load(signedIn('expiring-token', 10));
  const tokens = await Promise.all([auth.accessToken(), auth.accessToken()]);
  assert.deepEqual(tokens, ['refreshed-token', 'refreshed-token']);
  assert.equal(refreshes, 1);
});
