"""Exercise D4 for inventory-api: every forged token gets 401, a valid one without the role 403.

The tests drive the FastAPI app through ASGI directly, so they need neither a server nor httpx.
"""

import asyncio
import importlib
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_jwks import FORGERIES, MockIssuer  # noqa: E402

AUDIENCE = "inventory-api"
RESERVATION = {"orderId": "order-1", "item": "widget", "quantity": 1}


def call(app, token, body=RESERVATION):
    """POST /inventory/reserve through the ASGI interface; return (status, JSON body)."""
    payload = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json")]
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": "/inventory/reserve", "raw_path": b"/inventory/reserve",
             "query_string": b"", "root_path": "", "headers": headers,
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8080)}
    messages = [{"type": "http.request", "body": payload, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body or b"null")


class TokenChecksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = MockIssuer().start()
        # main.py reads ISSUER at import time, as it does from its Deployment's environment.
        os.environ["ISSUER"] = cls.issuer.issuer
        sys.modules.pop("main", None)
        cls.main = importlib.import_module("main")

    @classmethod
    def tearDownClass(cls):
        cls.issuer.stop()

    def caller(self, **overrides):
        claims = {"azp": "orders-api", "realm_access": {"roles": ["user"]}, "preferred_username": "alice"}
        claims.update(overrides)
        return claims

    def test_a_valid_exchanged_token_reserves(self):
        status, body = call(self.main.app, self.issuer.token(AUDIENCE, **self.caller()))
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"reserved": True, "for": "alice"})

    def test_every_forged_token_is_rejected_with_401(self):
        for kind in FORGERIES:
            with self.subTest(forgery=kind):
                status, _ = call(self.main.app, self.issuer.forge(kind, AUDIENCE, **self.caller()))
                self.assertEqual(status, 401, f"{kind} was accepted")

    def test_the_rejection_reason_names_the_failed_check(self):
        expected = {"wrong_aud": "bad_audience", "wrong_iss": "bad_issuer", "expired": "expired",
                    "es256": "invalid_token"}
        for kind, reason in expected.items():
            with self.subTest(forgery=kind):
                with self.assertRaises(self.main.AuthenticationFailure) as failure:
                    self.main.verify_token(self.issuer.forge(kind, AUDIENCE, **self.caller()))
                self.assertEqual(failure.exception.reason, reason)

    def test_the_original_user_token_is_rejected(self):
        # The browser's token is for orders-api; only an exchanged token is valid here.
        status, _ = call(self.main.app, self.issuer.token("orders-api", **self.caller()))
        self.assertEqual(status, 401)

    def test_no_token_is_401(self):
        self.assertEqual(call(self.main.app, None)[0], 401)

    def test_a_valid_token_without_the_role_or_from_another_client_is_403(self):
        no_role = self.issuer.token(AUDIENCE, **self.caller(realm_access={"roles": []}))
        self.assertEqual(call(self.main.app, no_role)[0], 403)
        other_client = self.issuer.token(AUDIENCE, **self.caller(azp="bff"))
        self.assertEqual(call(self.main.app, other_client)[0], 403)


if __name__ == "__main__":
    unittest.main()
