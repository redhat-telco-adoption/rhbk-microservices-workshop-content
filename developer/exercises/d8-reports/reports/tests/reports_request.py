"""Module 8's requirements for the `reports` client request, in one place.

The D8 tests and the ops desk both run this module: a request the tests accept is one the desk
accepts. It uses only the standard library, because the ops desk runs it in a stock UBI Python
image with nothing installed.

This file is the canonical source. workshop/agnosticd-role/tools/package_manifests.py freezes a
copy into the ops desk role, and its --check fails when the copy differs.
"""

from __future__ import annotations

import re

CLIENT_ID = "reports"
MAX_BYTES = 16 * 1024
CALLBACK = "/login/oauth2/code/keycloak"

# Each setting the request may hold, and the requirement in the guide it serves.
REQUIREMENT = {
    "clientId": "scope",
    "publicClient": "1",
    "standardFlowEnabled": "1",
    "implicitFlowEnabled": "1",
    "defaultClientScopes": "2",
    "fullScopeAllowed": "3",
    "realmRoleScopeMappings": "3",
    "redirectUris": "4",
    "postLogoutRedirectUris": "4",
    "directAccessGrantsEnabled": "5",
    "serviceAccountsEnabled": "5",
    "pkceCodeChallengeMethod": "6",
}
BOOLEANS = {"publicClient", "standardFlowEnabled", "implicitFlowEnabled", "fullScopeAllowed",
            "directAccessGrantsEnabled", "serviceAccountsEnabled"}
LISTS = {"defaultClientScopes", "realmRoleScopeMappings", "redirectUris", "postLogoutRedirectUris"}
STRINGS = {"clientId", "pkceCodeChallengeMethod"}
API_AUDIENCES = {"orders-api-aud", "inventory-api-aud", "notifications-api-aud"}


class RequestFormatError(ValueError):
    """The request is not in the shape the ops desk reads."""


def expected(reports_url: str) -> dict:
    """The only request that meets the six requirements, for this reports address."""
    return {
        "clientId": CLIENT_ID,
        "publicClient": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [f"{reports_url}{CALLBACK}"],
        "postLogoutRedirectUris": [f"{reports_url}/"],
        "pkceCodeChallengeMethod": "S256",
        "fullScopeAllowed": False,
        "realmRoleScopeMappings": ["user"],
        "defaultClientScopes": ["orders-api-aud"],
    }


# ---- A strict reader for the request's shape ----
#
# The request is flat: `key: value` lines, and `key:` followed by `- item` lines. The reader
# accepts only that, and rejects anything YAML could read differently (flow lists, anchors,
# tags, multi-line values, escapes, YAML 1.1 words such as `yes`). So whatever it accepts,
# yaml.safe_load reads the same way; scripts/tests/test_workshop_ops_desk.py checks this.

_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_BARE = re.compile(r"[A-Za-z][A-Za-z0-9@/_.:*%+=~-]*")
_YAML_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~"}
# Characters YAML reads as line breaks or byte-order marks, besides the C0 controls.
_SPECIAL = {"\x7f", "\x85", "\u2028", "\u2029", "\ufeff"}


def _scalar(raw: str, line: int):
    """One value: true, false, a bare word, or a quoted string without escapes."""
    value = raw.strip()
    if value[:1] in {'"', "'"}:
        quote = value[0]
        end = value.find(quote, 1)
        if end < 0:
            raise RequestFormatError(f"line {line}: the quoted value has no closing {quote}")
        inner, after = value[1:end], value[end + 1:]
        if after.strip() and not (after[0] == " " and after.strip().startswith("#")):
            raise RequestFormatError(f"line {line}: unexpected text after the quoted value")
        if quote == '"' and "\\" in inner:
            raise RequestFormatError(f"line {line}: escape sequences are not supported")
        return inner
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if value in {"true", "false"}:
        return value == "true"
    if value.lower() in _YAML_WORDS:
        raise RequestFormatError(f"line {line}: write {value!r} as true, false, or a quoted string")
    if not _BARE.fullmatch(value) or value.endswith(":"):
        raise RequestFormatError(f"line {line}: put {value!r} in double quotes")
    return value


def parse(text: str) -> dict:
    """Read a request. Raises RequestFormatError, with the line, for anything outside its shape."""
    if not isinstance(text, str):
        raise RequestFormatError("the request is not text")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise RequestFormatError(f"the request is larger than {MAX_BYTES} bytes")
    if "\t" in text:
        raise RequestFormatError("the request contains a tab; indent with spaces")
    request: dict = {}
    current = None  # the list key whose items are being read
    indent = None
    for number, line in enumerate(text.split("\n"), start=1):
        line = line.removesuffix("\r")
        if any(ord(char) < 32 or char in _SPECIAL for char in line):
            raise RequestFormatError(f"line {number}: control characters are not allowed")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.startswith(("---", "...")) or line[0] in "%&*!|>[{":
            raise RequestFormatError(f"line {number}: write one `key: value` or `- item` per line")
        item = re.fullmatch(r"( *)- (.*)", line) or re.fullmatch(r"( *)-", line)
        if item:
            if current is None:
                raise RequestFormatError(f"line {number}: a list item must follow a `key:` line")
            if indent is None:
                indent = len(item.group(1))
            elif len(item.group(1)) != indent:
                raise RequestFormatError(f"line {number}: indent every item of {current} the same")
            raw = item.group(2) if item.lastindex and item.lastindex >= 2 else ""
            if not raw.strip() or raw.strip().startswith("#"):
                raise RequestFormatError(f"line {number}: the list item is empty")
            if raw.lstrip()[:1] in {"-", "[", "{", "&", "*", "!", "|", ">"}:
                raise RequestFormatError(f"line {number}: write one plain value per list item")
            request[current].append(_scalar(raw, number))
            continue
        if line[0] == " ":
            raise RequestFormatError(f"line {number}: only list items may be indented")
        if current is not None and not request[current]:
            raise RequestFormatError(f"line {number}: {current} has no value; write [] for an empty list")
        current, indent = None, None
        key, colon, rest = line.partition(":")
        if not colon or not _KEY.fullmatch(key) or key.lower() in _YAML_WORDS or (rest and rest[0] != " "):
            raise RequestFormatError(f"line {number}: write one `key: value` or `- item` per line")
        if key in request:
            raise RequestFormatError(f"line {number}: {key} appears twice")
        rest = rest.strip()
        if not rest or rest.startswith("#"):
            request[key] = []
            current = key
        elif rest == "[]" or re.fullmatch(r"\[\]\s+#.*", rest):
            request[key] = []
        elif rest[0] in "[{&*!|>@`":
            raise RequestFormatError(f"line {number}: write {key} as a list, one `- item` per line")
        else:
            request[key] = _scalar(rest, number)
    if current is not None and not request[current]:
        raise RequestFormatError(f"{current} has no value; write [] for an empty list")
    return request


# ---- The six requirements ----

def review(request, reports_url: str) -> list[tuple[str, str]]:
    """Every reason the request fails Module 8's requirements, as (requirement, reason) pairs.

    `request` is the request text or an already-read mapping. An empty list means it passes.
    The requirement is "1" to "6" as numbered in the guide, "scope" for what the ops desk never
    creates, or "format" for a request it cannot read.
    """
    if isinstance(request, str):
        try:
            request = parse(request)
        except RequestFormatError as error:
            return [("format", str(error))]
    if not isinstance(request, dict):
        return [("format", "the request must be a list of `key: value` settings")]
    want = expected(reports_url)
    reasons = []

    def fail(key, reason):
        reasons.append((REQUIREMENT.get(key, "scope"), reason))

    for key in sorted(set(request) - set(REQUIREMENT)):
        fail(key, f"{key} is not a setting the ops desk accepts; a request has only "
                  f"{', '.join(sorted(REQUIREMENT))}")
    for key in REQUIREMENT:
        if key not in request:
            fail(key, f"{key} is missing")
            continue
        value = request[key]
        if key in BOOLEANS and not isinstance(value, bool):
            fail(key, f"{key} must be true or false, not {value!r}")
        elif key in LISTS and not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
            fail(key, f"{key} must be a list of text values")
        elif key in STRINGS and not isinstance(value, str):
            fail(key, f"{key} must be text, not {value!r}")
        else:
            reason = _rule(key, value, want)
            if reason:
                fail(key, reason)
    return reasons


def _rule(key, value, want):
    if key == "clientId" and value != CLIENT_ID:
        return f"refused: the ops desk creates only the {CLIENT_ID} client, not {value!r}"
    if key == "publicClient" and value:
        return "publicClient must be false: reports runs on a server and keeps a secret"
    if key == "standardFlowEnabled" and not value:
        return "standardFlowEnabled must be true: users sign in through Keycloak"
    if key == "implicitFlowEnabled" and value:
        return "implicitFlowEnabled must be false: the implicit flow puts tokens in the browser"
    if key == "defaultClientScopes" and value != want[key]:
        others = sorted((set(value) & API_AUDIENCES) - {"orders-api-aud"})
        if others:
            return (f"defaultClientScopes includes {', '.join(others)}: its tokens would be accepted "
                    "by an API reports never calls")
        return 'defaultClientScopes must be exactly ["orders-api-aud"], so its tokens are for Orders only'
    if key == "fullScopeAllowed" and value:
        return "refused: full scope puts every role the user has in the token, manager included"
    if key == "realmRoleScopeMappings" and value != want[key]:
        if "manager" in value:
            return "refused: manager in the scope would let reports create orders"
        return 'realmRoleScopeMappings must be exactly ["user"], the role Orders needs for reads'
    if key in {"redirectUris", "postLogoutRedirectUris"} and value != want[key]:
        if any("*" in uri for uri in value):
            return f"refused: {key} has a wildcard; give the exact address"
        return f"{key} must be exactly {want[key]}"
    if key == "directAccessGrantsEnabled" and value:
        return "directAccessGrantsEnabled must be false: reports must never handle a user's password"
    if key == "serviceAccountsEnabled" and value:
        return "serviceAccountsEnabled must be false: reports must never act on its own behalf"
    if key == "pkceCodeChallengeMethod" and value != "S256":
        return "pkceCodeChallengeMethod must be S256, so an intercepted sign-in code is useless"
    return None
