"""Exercise D8: the reports client request and runtime configuration meet the capstone requirements.

The last test predicts the manager's token from the request, signs it with the mock issuer, and
checks it with orders-api's rules: Orders accepts it for reads and refuses writes with 403.
"""

import sys
import unittest
from pathlib import Path

import jwt
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mock_jwks import MockIssuer  # noqa: E402

REQUEST = yaml.safe_load((HERE / "client-request.yaml").read_text())
URL = "@REPORTS_URL@"
AUDIENCES = {"orders-api-aud": "orders-api", "inventory-api-aud": "inventory-api",
             "notifications-api-aud": "notifications-api"}
MANAGER_ROLES = ["user", "manager"]


def read_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def predicted_token_claims(request, user_roles):
    """What Keycloak puts in the user's access token for this client."""
    roles = list(user_roles) if request["fullScopeAllowed"] else [
        role for role in user_roles if role in request["realmRoleScopeMappings"]]
    audience = [AUDIENCES[scope] for scope in request["defaultClientScopes"] if scope in AUDIENCES]
    return {"aud": audience, "azp": request["clientId"], "realm_access": {"roles": roles}}


class ClientRequestTest(unittest.TestCase):
    def test_a_confidential_client_named_reports(self):
        self.assertEqual(REQUEST["clientId"], "reports")
        self.assertIs(REQUEST["publicClient"], False)

    def test_only_the_standard_flow_with_pkce(self):
        self.assertIs(REQUEST["standardFlowEnabled"], True)
        for flow in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"):
            with self.subTest(flow=flow):
                self.assertIs(REQUEST[flow], False)
        self.assertEqual(REQUEST["pkceCodeChallengeMethod"], "S256")

    def test_exact_redirect_uris(self):
        self.assertEqual(REQUEST["redirectUris"], [f"{URL}/login/oauth2/code/keycloak"])
        self.assertEqual(REQUEST["postLogoutRedirectUris"], [f"{URL}/"])
        for uri in REQUEST["redirectUris"] + REQUEST["postLogoutRedirectUris"]:
            self.assertNotIn("*", uri)

    def test_least_privilege_scope(self):
        self.assertIs(REQUEST["fullScopeAllowed"], False)
        self.assertEqual(REQUEST["realmRoleScopeMappings"], ["user"])
        self.assertIn("orders-api-aud", REQUEST["defaultClientScopes"])
        self.assertFalse({"inventory-api-aud", "notifications-api-aud"} & set(REQUEST["defaultClientScopes"]))

    def test_the_managers_token_carries_orders_api_and_user_only(self):
        claims = predicted_token_claims(REQUEST, MANAGER_ROLES)
        self.assertEqual(claims["aud"], ["orders-api"])
        self.assertEqual(claims["realm_access"]["roles"], ["user"])


class RuntimeConfigTest(unittest.TestCase):
    config = read_env(HERE / "reports-config.env")

    def test_reports_signs_in_as_its_own_client(self):
        self.assertEqual(self.config.get("SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENTID"),
                         REQUEST["clientId"])
        self.assertEqual(self.config.get("SPRING_APPLICATION_NAME"), "reports")

    def test_the_callback_matches_the_registered_redirect_uri(self):
        # The BFF image's registration ID is "keycloak": its callback is /login/oauth2/code/keycloak.
        self.assertIn(f"{URL}/login/oauth2/code/keycloak", REQUEST["redirectUris"])

    def test_the_issuer_comes_from_the_namespace_and_no_secret_is_in_the_config(self):
        self.assertEqual(self.config.get("OIDC_ISSUER"), "@OIDC_ISSUER@")
        self.assertEqual(self.config.get("ORDERS_BASE_URL"), "http://orders-api:8080")
        self.assertFalse([key for key in self.config if "SECRET" in key.upper()])


class OrdersDecisionTest(unittest.TestCase):
    """Orders' checks applied to the token the request predicts for the manager."""

    def test_orders_accepts_reads_and_refuses_writes(self):
        with MockIssuer() as issuer:
            predicted = predicted_token_claims(REQUEST, MANAGER_ROLES)
            token = issuer.token(predicted["aud"], azp=predicted["azp"],
                                 realm_access=predicted["realm_access"], preferred_username="manager")
            key = jwt.PyJWKClient(issuer.jwks_uri).get_signing_key_from_jwt(token).key
            # orders-api: RS256 only, its own audience, the realm issuer.
            claims = jwt.decode(token, key, algorithms=["RS256"], audience="orders-api", issuer=issuer.issuer)
            roles = claims["realm_access"]["roles"]
            self.assertIn("user", roles, "GET /orders needs user: expected 200")
            self.assertNotIn("manager", roles, "POST /orders needs manager: expected 403")
            self.assertEqual(claims["aud"], ["orders-api"])


if __name__ == "__main__":
    unittest.main()
