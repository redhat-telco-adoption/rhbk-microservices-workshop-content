# Developer track exercises

Starters, solutions, and tests for the hands-on modules of the developer track
([design](../../../docs/enhancements/workshop-developer-variant.md)). Each
starter is a copy of a reference app in `apps/` with the security-relevant part
removed or deliberately broken. `apps/` itself never changes.

## Layout

```text
dN-<topic>/<service>/
  exercise.env   what the exercise is, its reference, how to test, package, and roll it out
  starter/       the code you edit: the reference app's files with the defects
  solution/      only the files the exercise changes, as the reference app has them
  tests/         tests added to a scratch copy of the starter when they run
bin/exercise.sh  test, package, and roll out an exercise
test-helpers/    the mock-JWKS issuer in Java, Python, and Node, shared by the tests
devfile.yaml     the Dev Spaces workspace, with a test and a rollout command per exercise
```

| Exercise | Reference | What you fix | Tests |
| --- | --- | --- | --- |
| `d3-spa-pkce/frontend` | `apps/frontend` | `src/auth.ts`: PKCE, in-memory token storage, and refresh before expiry | Node: PKCE is on, no storage writes, one refresh for concurrent calls |
| `d4-token-checks/orders-api` | `apps/orders-api` | Issuer, audience, and RS256-only checks in the JWT decoder (Java) | Every forgery is rejected and gets 401; a reader gets 403 on a write |
| `d4-token-checks/inventory-api` | `apps/inventory-api` | The same checks in `verify_token` (Python) | Every forgery gets 401; the wrong role or client gets 403 |
| `d4-token-checks/notifications-api` | `apps/notifications-api` | The same checks in `jwtVerify` (Node) | Every forgery gets 401; the wrong role or client gets 403 |
| `d5-bff/bff` | `apps/bff` | Header stripping around `TokenRelay`, and CSRF | Each route strips credentials; a write without the CSRF token gets 403 |
| `d6-service-to-service/orders-api` | `apps/orders-api` | Token exchange in `InventoryClient`, client credentials in `NotificationsClient` | Each API receives its own token, never the user's |
| `d8-reports/reports` | The workshop role's `reports-config` | The client request for operations, and the `reports` runtime configuration | The request meets the capstone requirements; Orders allows reads and refuses writes |

Each defect is marked with an `ANTI-PATTERN:` comment, in the file's comment
syntax, as spec section 8 requires. The tests use the forgeries from
`test-helpers/` (`wrong_aud`, `wrong_iss`, `expired`, `unknown_kid`, `hs256`,
`es256`, and `bad_signature`).

## Run an exercise

From this directory, in the container the exercise names (`bin/exercise.sh list`
shows it), or with the matching Dev Spaces command:

```bash
bin/exercise.sh test d4-token-checks/inventory-api              # your starter: fails until you fix it
bin/exercise.sh test d4-token-checks/inventory-api --solution   # the reference solution
bin/exercise.sh package d5-bff/bff                              # only frontend and bff need a package step
bin/exercise.sh rollout d4-token-checks/inventory-api           # build and roll out (oc container)
```

`rollout` builds the starter with an OpenShift binary build (`oc new-build
--binary`, `oc start-build --from-dir`) and points the Deployment at the built
image. It works only in your developer namespace, `<user>-rhbk-dev`, taken from
`DEV_NAMESPACE`, the Dev Spaces workspace namespace, or `oc project`, and refuses
any other. Images stay in that namespace's internal registry; nothing is pushed
to Quay, and the pinned images the operations track uses are unchanged.

For D8, `bin/exercise.sh request d8-reports/reports` files your client request,
with your `reports` address, as ConfigMap `reports-client-request` for the
reservation's ops desk, and prints its answer (`--print` only prints the
request). On approval, the ops desk writes the client secret into Secret
`reports-client`; `status` waits for it, reading only the Secret's annotations.
`rollout` then applies the configuration and restarts `reports`, and refuses to
run before the secret is issued.

## Checks

`scripts/check.sh core` runs `scripts/tests/test_developer_exercises.py`. It
checks that each starter with its solution applied is identical to the
reference, that defects are marked, that every starter fails its tests and every
solution passes them, and that `rollout` refuses other namespaces.
