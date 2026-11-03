// Tests for mock-jwks, verified the way apps/notifications-api/src/server.js verifies tokens.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import { FORGERIES, MockIssuer } from './mock-jwks.mjs';

const AUDIENCE = 'notifications-api';
let issuer;

before(async () => { issuer = await MockIssuer.start(); });
after(async () => { await issuer.stop(); });

// The notifications-api checks, each of which a test can relax.
function verify(token, { audience = AUDIENCE, iss = issuer.issuer, algorithms = ['RS256'], clockTolerance = 30 } = {}) {
  const jwks = createRemoteJWKSet(new URL(issuer.jwksUri), { timeoutDuration: 3000 });
  return jwtVerify(token, jwks, { issuer: iss, audience, algorithms, clockTolerance });
}

test('serves the JWKS at the Keycloak path with public keys only', async () => {
  const { keys } = await (await fetch(issuer.jwksUri)).json();
  assert.deepEqual(keys.map((k) => [k.kid, k.alg]).sort(), [['mock-es256', 'ES256'], ['mock-rs256', 'RS256']]);
  assert.ok(keys.every((k) => !('d' in k)));
  assert.match(issuer.issuer, /\/realms\/workshop$/);
});

test('a valid token passes the notifications-api checks', async () => {
  const { payload } = await verify(await issuer.token(AUDIENCE, { sub: 'alice' }));
  assert.deepEqual([payload.sub, payload.typ, payload.aud], ['alice', 'Bearer', AUDIENCE]);
});

test('each forgery is rejected with its reason', async () => {
  const expected = {
    wrong_aud: { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED', claim: 'aud' },
    wrong_iss: { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED', claim: 'iss' },
    expired: { code: 'ERR_JWT_EXPIRED' },
    unknown_kid: { code: 'ERR_JWKS_NO_MATCHING_KEY' },
    hs256: { code: 'ERR_JOSE_ALG_NOT_ALLOWED' },
    es256: { code: 'ERR_JOSE_ALG_NOT_ALLOWED' },
    bad_signature: { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' },
  };
  assert.deepEqual(Object.keys(expected).sort(), [...FORGERIES].sort());
  for (const [kind, error] of Object.entries(expected)) {
    await assert.rejects(verify(await issuer.forge(kind, AUDIENCE)), error, kind);
  }
});

test('each forgery differs only in its one property', async () => {
  // Relaxing exactly the check under test lets the token through, so an exercise
  // test fails when that check is missing from the starter.
  await verify(await issuer.forge('wrong_aud', AUDIENCE), { audience: 'another-api' });
  await verify(await issuer.forge('wrong_iss', AUDIENCE), { iss: `${issuer.issuer}-other` });
  await verify(await issuer.forge('expired', AUDIENCE), { clockTolerance: 3600 });
  await verify(await issuer.forge('es256', AUDIENCE), { algorithms: ['RS256', 'ES256'] });
});

test('overrides add and remove claims', async () => {
  const claims = decodeJwt(await issuer.token(AUDIENCE, {
    resource_access: { 'notifications-api': { roles: ['notifier'] } }, azp: undefined,
  }));
  assert.deepEqual(claims.resource_access['notifications-api'].roles, ['notifier']);
  assert.ok(!('azp' in claims));
  assert.throws(() => issuer.forge('nonsense', AUDIENCE), /unknown forgery/);
});
