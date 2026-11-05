"""Elective D: the policy enforcer protects order approval as the page's requirements say.

The tests read application.properties as Quarkus would, and check the one path entry:
POST /orders/{id}/approve needs scope order:approve on resource order, and the CIP takes
the channel claim only from the X-Network-Zone header, which the cluster's gateway sets.
"""

import re
import unittest
from pathlib import Path

PREFIX = "quarkus.keycloak.policy-enforcer."
PROPERTIES = Path(__file__).resolve().parent / "application.properties"
GATEWAY_CLAIM = "{request.header['X-Network-Zone']}"


def read_properties(path):
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"application.properties line {number} has no '=': {line}")
        values[key.strip()] = value.strip()
    return values


def enforcer(values):
    return {key[len(PREFIX):]: value for key, value in values.items() if key.startswith(PREFIX)}


def path_entries(settings):
    entries = {}
    for key, value in settings.items():
        if key.startswith("paths."):
            name, _, rest = key[len("paths."):].partition(".")
            entries.setdefault(name, {})[rest] = value
    return entries


class PolicyEnforcerTest(unittest.TestCase):
    def setUp(self):
        self.settings = enforcer(read_properties(PROPERTIES))
        entries = path_entries(self.settings)
        self.assertEqual(len(entries), 1, f"expected one paths.<name> entry, found {sorted(entries)}")
        ((self.entry_name, self.entry),) = entries.items()

    def methods(self):
        methods = {}
        for key, value in self.entry.items():
            match = re.fullmatch(r"methods\.([^.]+)\.(method|scopes|scopes-enforcement-mode)", key)
            if match:
                methods.setdefault(match.group(1), {})[match.group(2)] = value
            elif key.startswith("methods."):
                self.fail(f"unknown method setting paths.{self.entry_name}.{key}")
        return methods

    def claims(self):
        prefix = "claim-information-point."
        return {key[len(prefix):]: value for key, value in self.entry.items() if key.startswith(prefix)}

    def test_the_enforcer_is_enabled(self):
        self.assertEqual(self.settings.get("enabled"), "true", "set policy-enforcer.enabled=true")

    def test_the_entry_protects_the_approve_path_as_resource_order(self):
        self.assertEqual(self.entry.get("paths"), "/orders/{id}/approve",
                         "the entry's paths must be /orders/{id}/approve")
        self.assertEqual(self.entry.get("name"), "order", "the entry's name must be the resource, order")

    def test_only_post_is_mapped_and_it_needs_order_approve(self):
        methods = self.methods()
        self.assertEqual(len(methods), 1,
                         "map exactly one method; an entry without method= covers every HTTP method")
        ((label, method),) = methods.items()
        self.assertEqual(method.get("method"), "POST",
                         f"set paths.{self.entry_name}.methods.{label}.method=POST")
        scopes = [scope.strip() for scope in method.get("scopes", "").split(",") if scope.strip()]
        self.assertEqual(scopes, ["order:approve"],
                         "approving needs scope order:approve, and only that scope")

    def test_channel_comes_only_from_the_gateway_header(self):
        claims = self.claims()
        self.assertEqual(sorted(claims), ["claims.channel"],
                         "the CIP pushes one claim, channel, and nothing else")
        value = claims["claims.channel"]
        for source in ("request.body", "request.parameter", "request.cookie", "request.uri",
                       "request.relativePath", "request.secure", "request.method"):
            self.assertNotIn(source, value, f"{source} is set by the caller, not by the gateway")
        self.assertEqual(value, GATEWAY_CLAIM,
                         "channel must come only from the header the gateway sets: X-Network-Zone")

    def test_nothing_else_is_configured(self):
        allowed = {"enabled"}
        other = sorted(key for key in self.settings if key not in allowed and not key.startswith("paths."))
        self.assertEqual(other, [], "configure only the enforcer and the approve entry")


if __name__ == "__main__":
    unittest.main()
