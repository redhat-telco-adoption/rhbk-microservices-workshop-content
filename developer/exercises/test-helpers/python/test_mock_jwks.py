"""Tests for mock_jwks, verified the way apps/inventory-api/main.py verifies tokens."""

import json
import unittest
import urllib.request

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    PyJWKClientError,
)

from mock_jwks import FORGERIES, MockIssuer

AUDIENCE = "inventory-api"


def verify(issuer: MockIssuer, token: str, *, audience=AUDIENCE, iss=None, algorithms=("RS256",), leeway=30):
    """The inventory-api checks, each of which a test can relax."""
    key = PyJWKClient(issuer.jwks_uri, cache_jwk_set=False, timeout=5).get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=list(algorithms),
        audience=audience,
        issuer=iss or issuer.issuer,
        leeway=leeway,
        options={"require": ["exp", "sub"], "verify_nbf": True},
    )


class MockIssuerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = MockIssuer().start()

    @classmethod
    def tearDownClass(cls):
        cls.issuer.stop()

    def test_serves_jwks_at_the_keycloak_path(self):
        with urllib.request.urlopen(self.issuer.jwks_uri, timeout=5) as response:
            keys = json.load(response)["keys"]
        self.assertEqual({(k["kid"], k["alg"]) for k in keys}, {("mock-rs256", "RS256"), ("mock-es256", "ES256")})
        self.assertTrue(all("d" not in k for k in keys), "the JWKS must hold only public keys")
        self.assertTrue(self.issuer.issuer.endswith("/realms/workshop"))

    def test_valid_token_passes_the_inventory_checks(self):
        claims = verify(self.issuer, self.issuer.token(AUDIENCE, sub="alice"))
        self.assertEqual((claims["sub"], claims["typ"], claims["aud"]), ("alice", "Bearer", AUDIENCE))

    def test_each_forgery_is_rejected_with_its_reason(self):
        expected = {
            "wrong_aud": InvalidAudienceError,
            "wrong_iss": InvalidIssuerError,
            "expired": ExpiredSignatureError,
            "unknown_kid": PyJWKClientError,
            "hs256": InvalidAlgorithmError,
            "es256": InvalidAlgorithmError,
            "bad_signature": InvalidSignatureError,
        }
        self.assertEqual(set(expected), set(FORGERIES))
        for kind, error in expected.items():
            with self.subTest(kind=kind), self.assertRaises(error):
                verify(self.issuer, self.issuer.forge(kind, AUDIENCE))

    def test_each_forgery_differs_only_in_its_one_property(self):
        # Relaxing exactly the check under test lets the token through, so an
        # exercise test fails when that check is missing from the starter.
        verify(self.issuer, self.issuer.forge("wrong_aud", AUDIENCE), audience="another-api")
        verify(self.issuer, self.issuer.forge("wrong_iss", AUDIENCE), iss=f"{self.issuer.issuer}-other")
        verify(self.issuer, self.issuer.forge("expired", AUDIENCE), leeway=3600)
        verify(self.issuer, self.issuer.forge("es256", AUDIENCE), algorithms=("RS256", "ES256"))

    def test_overrides_add_and_remove_claims(self):
        token = self.issuer.token(AUDIENCE, realm_access={"roles": ["inventory-reader"]}, azp=None)
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(claims["realm_access"]["roles"], ["inventory-reader"])
        self.assertNotIn("azp", claims)
        with self.assertRaises(ValueError):
            self.issuer.forge("nonsense", AUDIENCE)


if __name__ == "__main__":
    unittest.main()
