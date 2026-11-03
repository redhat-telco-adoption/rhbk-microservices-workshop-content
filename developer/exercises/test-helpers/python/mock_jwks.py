"""Sign test JWTs with local keys and serve them from a mock Keycloak JWKS.

Keys are generated in memory when the issuer starts; nothing is written to disk.
Uses only PyJWT and cryptography, the libraries apps/inventory-api pins.

    with MockIssuer() as issuer:
        good = issuer.token("inventory-api")
        bad = issuer.forge("wrong_aud", "inventory-api")
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

FORGERIES = (
    "wrong_aud",
    "wrong_iss",
    "expired",
    "unknown_kid",
    "hs256",
    "es256",
    "bad_signature",
)


class MockIssuer:
    """A local issuer: an RSA signing key, a published EC key, and a JWKS endpoint.

    The JWKS is served at ``{issuer}/protocol/openid-connect/certs``, the path the
    APIs derive from ``ISSUER``. It publishes the RS256 key and an ES256 key, as a
    Keycloak realm with both providers would, so an ES256 token carries a valid
    signature and only an algorithm allowlist rejects it.
    """

    def __init__(self, realm: str = "workshop", host: str = "127.0.0.1", port: int = 0):
        self.realm = realm
        self.kid = "mock-rs256"
        self.ec_kid = "mock-es256"
        self._rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._other_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._ec = ec.generate_private_key(ec.SECP256R1())
        self._server = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    # Lifecycle -----------------------------------------------------------------

    def start(self) -> "MockIssuer":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "MockIssuer":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # Endpoints -----------------------------------------------------------------

    @property
    def issuer(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/realms/{self.realm}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    def jwks(self) -> dict[str, Any]:
        rsa_jwk = json.loads(RSAAlgorithm.to_jwk(self._rsa.public_key()))
        ec_jwk = json.loads(ECAlgorithm.to_jwk(self._ec.public_key()))
        rsa_jwk.update(kid=self.kid, use="sig", alg="RS256")
        ec_jwk.update(kid=self.ec_kid, use="sig", alg="ES256")
        return {"keys": [rsa_jwk, ec_jwk]}

    # Tokens --------------------------------------------------------------------

    def claims(self, audience: str | list[str], **overrides: Any) -> dict[str, Any]:
        """Keycloak-shaped access token claims; a value of ``None`` removes a claim."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": audience,
            "sub": "test-user",
            "azp": "test-client",
            "typ": "Bearer",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "realm_access": {"roles": []},
            "resource_access": {},
        }
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def sign(self, claims: dict[str, Any], alg: str = "RS256", kid: str | None = None) -> str:
        """Sign ``claims`` as-is. ``alg`` is RS256, ES256, or HS256."""
        if alg == "RS256":
            key, default_kid = self._rsa, self.kid
        elif alg == "ES256":
            key, default_kid = self._ec, self.ec_kid
        elif alg == "HS256":
            key, default_kid = secrets.token_bytes(32), self.kid
        else:
            raise ValueError(f"unsupported alg {alg!r}")
        headers = {"kid": kid or default_kid, "typ": "JWT"}
        return jwt.encode(claims, key, algorithm=alg, headers=headers)

    def token(self, audience: str | list[str], **overrides: Any) -> str:
        """A valid RS256 access token for ``audience``."""
        return self.sign(self.claims(audience, **overrides))

    def forge(self, kind: str, audience: str | list[str], **overrides: Any) -> str:
        """A token that is valid except for one property, named by ``kind``.

        wrong_aud      ``aud`` names another API.
        wrong_iss      ``iss`` names another realm.
        expired        ``exp`` passed ten minutes ago, beyond any 30 s leeway.
        unknown_kid    The header ``kid`` is not in the JWKS.
        hs256          HMAC-signed with a random secret, under the RSA ``kid``.
        es256          Signed by the published EC key: only an RS256 allowlist rejects it.
        bad_signature  Signed by another RSA key under the published ``kid``.
        """
        if kind == "wrong_aud":
            return self.token("another-api", **overrides)
        if kind == "wrong_iss":
            return self.token(audience, iss=f"{self.issuer}-other", **overrides)
        if kind == "expired":
            now = int(time.time())
            return self.token(audience, iat=now - 900, nbf=now - 900, exp=now - 600, **overrides)
        if kind == "unknown_kid":
            return self.sign(self.claims(audience, **overrides), kid="unknown-kid")
        if kind == "hs256":
            return self.sign(self.claims(audience, **overrides), alg="HS256")
        if kind == "es256":
            return self.sign(self.claims(audience, **overrides), alg="ES256")
        if kind == "bad_signature":
            headers = {"kid": self.kid, "typ": "JWT"}
            return jwt.encode(self.claims(audience, **overrides), self._other_rsa, algorithm="RS256", headers=headers)
        raise ValueError(f"unknown forgery {kind!r}; expected one of {', '.join(FORGERIES)}")

    # HTTP ----------------------------------------------------------------------

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server API
                prefix = f"/realms/{issuer.realm}"
                if self.path == f"{prefix}/protocol/openid-connect/certs":
                    body: dict[str, Any] | None = issuer.jwks()
                elif self.path == f"{prefix}/.well-known/openid-configuration":
                    body = {"issuer": issuer.issuer, "jwks_uri": issuer.jwks_uri}
                else:
                    body = None
                if body is None:
                    self.send_error(404)
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                pass

        return Handler
