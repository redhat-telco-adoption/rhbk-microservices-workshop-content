# Mock-JWKS test helpers

Small helpers for the developer track's token-validation exercises (module D4 in
[the developer variant design](../../../../docs/enhancements/workshop-developer-variant.md)).
Each one generates keys in memory, signs Keycloak-shaped access tokens, and
serves a JWKS at `{issuer}/protocol/openid-connect/certs`, the path the APIs
derive from `ISSUER`. Tests can then check validation without the cluster.

| Language | Helper | Libraries (the app's pins) |
| --- | --- | --- |
| Java | `java/src/main/java/com/example/testing/jwks/MockIssuer.java` | Nimbus, through the `orders-api` Spring Boot parent |
| Python | `python/mock_jwks.py` | PyJWT and cryptography, as `inventory-api` pins them |
| Node | `node/mock-jwks.mjs` | jose, as `notifications-api` pins it |

Every helper offers the same operations:

- start an issuer on a loopback port, and stop it;
- `token(audience, overrides)`: a valid RS256 token; an override of null
  (`None`, `undefined`) removes a claim;
- `forge(kind, audience, overrides)`: a token that is valid except for one
  property;
- `sign(claims, alg, kid)`: sign arbitrary claims.

| Forgery | What is wrong |
| --- | --- |
| `wrong_aud` | `aud` names another API |
| `wrong_iss` | `iss` names another realm |
| `expired` | `exp` passed ten minutes ago, beyond the APIs' 30-second leeway |
| `unknown_kid` | The header `kid` is not in the JWKS |
| `hs256` | HMAC-signed with a random secret under the RSA `kid` |
| `es256` | Signed by the EC key the JWKS also publishes, so only an RS256 allowlist rejects it |
| `bad_signature` | Signed by another RSA key under the published `kid` |

Each helper's tests verify these tokens with the same settings as its app, and
show that relaxing exactly one check accepts the matching forgery. That second
property is what lets an exercise test fail when a check is missing.

## Run the tests

`scripts/check.sh core` runs all three through
`scripts/tests/test_developer_jwks_helpers.py`. To run one inside the
devcontainer:

```bash
scripts/dev 'cd workshop/developer/exercises/test-helpers/python && python3 -B -m unittest -v'
scripts/dev 'cd workshop/developer/exercises/test-helpers/java && mvn -B -ntp -q test'
scripts/dev 'python3 -B -m unittest -v scripts/tests/test_developer_jwks_helpers.py'
```

The Node helper needs `jose`; the repository test links the devcontainer's
`apps/notifications-api/node_modules` into a scratch copy, or you can run
`npm ci` in `node/` where the registry is reachable.
