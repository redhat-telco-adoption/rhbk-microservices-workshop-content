// Sign test JWTs with local keys and serve them from a mock Keycloak JWKS.
//
// Keys are generated in memory when the issuer starts; nothing is written to disk.
// Uses only jose, the library apps/notifications-api pins, and node: built-ins.
//
//   const issuer = await MockIssuer.start();
//   const good = await issuer.token('notifications-api');
//   const bad = await issuer.forge('wrong_aud', 'notifications-api');
//   await issuer.stop();
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

export const FORGERIES = Object.freeze([
  'wrong_aud', 'wrong_iss', 'expired', 'unknown_kid', 'hs256', 'es256', 'bad_signature',
]);

// The JWKS is served at `${issuer}/protocol/openid-connect/certs`, the path the
// APIs derive from ISSUER. It publishes the RS256 key and an ES256 key, as a
// Keycloak realm with both providers would, so an ES256 token carries a valid
// signature and only an algorithm allowlist rejects it.
export class MockIssuer {
  kid = 'mock-rs256';
  ecKid = 'mock-es256';

  static async start({ realm = 'workshop', host = '127.0.0.1', port = 0 } = {}) {
    const issuer = new MockIssuer();
    issuer.realm = realm;
    issuer.rsa = await generateKeyPair('RS256', { modulusLength: 2048 });
    issuer.otherRsa = await generateKeyPair('RS256', { modulusLength: 2048 });
    issuer.ec = await generateKeyPair('ES256');
    issuer.jwks = {
      keys: [
        { ...(await exportJWK(issuer.rsa.publicKey)), kid: issuer.kid, use: 'sig', alg: 'RS256' },
        { ...(await exportJWK(issuer.ec.publicKey)), kid: issuer.ecKid, use: 'sig', alg: 'ES256' },
      ],
    };
    issuer.server = createServer((req, res) => issuer.#handle(req, res));
    issuer.server.listen(port, host);
    await once(issuer.server, 'listening');
    const address = issuer.server.address();
    issuer.issuer = `http://${address.address}:${address.port}/realms/${realm}`;
    issuer.jwksUri = `${issuer.issuer}/protocol/openid-connect/certs`;
    return issuer;
  }

  async stop() {
    this.server.closeAllConnections();
    await new Promise((resolve, reject) => this.server.close((error) => (error ? reject(error) : resolve())));
  }

  #handle(req, res) {
    const prefix = `/realms/${this.realm}`;
    let body;
    if (req.method === 'GET' && req.url === `${prefix}/protocol/openid-connect/certs`) body = this.jwks;
    else if (req.method === 'GET' && req.url === `${prefix}/.well-known/openid-configuration`) {
      body = { issuer: this.issuer, jwks_uri: this.jwksUri };
    }
    if (!body) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  }

  /** Keycloak-shaped access token claims; an override of `undefined` removes a claim. */
  claims(audience, overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: this.issuer,
      aud: audience,
      sub: 'test-user',
      azp: 'test-client',
      typ: 'Bearer',
      iat: now,
      nbf: now,
      exp: now + 300,
      realm_access: { roles: [] },
      resource_access: {},
      ...overrides,
    };
    return Object.fromEntries(Object.entries(claims).filter(([, value]) => value !== undefined));
  }

  /** Sign `claims` as-is. `alg` is RS256, ES256, or HS256. */
  async sign(claims, { alg = 'RS256', kid } = {}) {
    const keys = {
      RS256: [this.rsa.privateKey, this.kid],
      ES256: [this.ec.privateKey, this.ecKid],
      HS256: [randomBytes(32), this.kid],
    };
    if (!keys[alg]) throw new Error(`unsupported alg ${alg}`);
    const [key, defaultKid] = keys[alg];
    return new SignJWT(claims).setProtectedHeader({ alg, kid: kid ?? defaultKid, typ: 'JWT' }).sign(key);
  }

  /** A valid RS256 access token for `audience`. */
  token(audience, overrides = {}) {
    return this.sign(this.claims(audience, overrides));
  }

  /**
   * A token that is valid except for one property, named by `kind`:
   * wrong_aud (aud names another API), wrong_iss (iss names another realm),
   * expired (exp passed ten minutes ago, beyond any 30 s tolerance),
   * unknown_kid (the header kid is not in the JWKS), hs256 (HMAC-signed with a
   * random secret under the RSA kid), es256 (signed by the published EC key: only
   * an RS256 allowlist rejects it), bad_signature (another RSA key, published kid).
   */
  forge(kind, audience, overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    switch (kind) {
      case 'wrong_aud': return this.token('another-api', overrides);
      case 'wrong_iss': return this.token(audience, { iss: `${this.issuer}-other`, ...overrides });
      case 'expired': return this.token(audience, { iat: now - 900, nbf: now - 900, exp: now - 600, ...overrides });
      case 'unknown_kid': return this.sign(this.claims(audience, overrides), { kid: 'unknown-kid' });
      case 'hs256': return this.sign(this.claims(audience, overrides), { alg: 'HS256' });
      case 'es256': return this.sign(this.claims(audience, overrides), { alg: 'ES256' });
      case 'bad_signature':
        return new SignJWT(this.claims(audience, overrides))
          .setProtectedHeader({ alg: 'RS256', kid: this.kid, typ: 'JWT' })
          .sign(this.otherRsa.privateKey);
      default:
        throw new Error(`unknown forgery ${kind}; expected one of ${FORGERIES.join(', ')}`);
    }
  }
}
