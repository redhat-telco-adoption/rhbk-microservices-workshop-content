"""Internal inventory reservation API with strict access-token validation."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient
from jwt.exceptions import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from pydantic import BaseModel, Field
from pythonjsonlogger.json import JsonFormatter

ISSUER = os.environ.get("ISSUER", "")
JWKS_URL = f"{ISSUER.rstrip('/')}/protocol/openid-connect/certs"
JWKS = PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=5)

logger = logging.getLogger("inventory_api")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter("%(message)s"))
logger.addHandler(handler)

app = FastAPI(title="inventory-api", docs_url=None, redoc_url=None, openapi_url=None)


class Reservation(BaseModel):
    orderId: str = Field(min_length=1, max_length=80)
    item: str = Field(min_length=1, max_length=120)
    quantity: int = Field(gt=0, le=1000)


class AuthenticationFailure(Exception):
    def __init__(self, reason: str, status_code: int = 401):
        self.reason = reason
        self.status_code = status_code


def verify_token(token: str) -> dict[str, Any]:
    """Verify JWT signature and required issuer/audience/time claims synchronously."""
    try:
        signing_key = JWKS.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience="inventory-api",
            issuer=ISSUER,
            leeway=30,
            options={"require": ["exp", "sub"], "verify_nbf": True},
        )
        if claims.get("typ") != "Bearer":
            raise AuthenticationFailure("invalid_token")
        return claims
    except ExpiredSignatureError as exc:
        raise AuthenticationFailure("expired") from exc
    except InvalidIssuerError as exc:
        raise AuthenticationFailure("bad_issuer") from exc
    except InvalidAudienceError as exc:
        raise AuthenticationFailure("bad_audience") from exc
    except AuthenticationFailure:
        raise
    except Exception as exc:
        # Includes unavailable JWKS, malformed JWT, missing required claims, and bad signatures.
        raise AuthenticationFailure("invalid_token") from exc


def bearer_claims(request: Request) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        request.state.reason = "missing_token"
        raise AuthenticationFailure("missing_token")
    try:
        claims = verify_token(header[7:].strip())
    except AuthenticationFailure as failure:
        request.state.reason = failure.reason
        raise
    realm_access = claims.get("realm_access")
    raw_roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    roles = [role for role in raw_roles if isinstance(role, str)] if isinstance(raw_roles, list) else []
    request.state.identity = {
        "subject": claims.get("sub"),
        "username": claims.get("preferred_username"),
        "client_id": claims.get("azp"),
        "roles": roles,
    }
    return claims


@app.middleware("http")
async def request_completion(request: Request, call_next):
    request.state.identity = {"subject": None, "username": None, "client_id": None, "roles": []}
    request.state.reason = None
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    except AuthenticationFailure as failure:
        status = failure.status_code
        request.state.reason = failure.reason
        challenge = 'Bearer' if status == 401 else 'Bearer error="insufficient_scope"'
        return JSONResponse(
            {"detail": "Unauthorized" if status == 401 else "Forbidden"},
            status_code=status,
            headers={"WWW-Authenticate": challenge},
        )
    finally:
        from opentelemetry import trace

        span_context = trace.get_current_span().get_span_context()
        span_id = format(span_context.span_id, "016x") if span_context.is_valid else None
        trace_id = format(span_context.trace_id, "032x") if span_context.is_valid else None
        identity = request.state.identity
        log_level = logging.WARNING if status >= 400 else logging.INFO
        logger.log(
            log_level,
            "request_complete",
            extra={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "WARN" if status >= 400 else "INFO",
                "service": "inventory-api",
                "event": "request_complete",
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "decision": "deny" if status >= 400 else "allow",
                "subject": identity.get("subject"),
                "username": identity.get("username"),
                "client_id": identity.get("client_id"),
                "roles": identity.get("roles", []),
                "reason": request.state.reason,
                "trace_id": trace_id,
                "span_id": span_id,
            },
        )


@app.exception_handler(AuthenticationFailure)
async def authentication_error(request: Request, exc: AuthenticationFailure):
    # FastAPI dependency exceptions are handled here; middleware owns request completion logging.
    request.state.reason = exc.reason
    challenge = 'Bearer' if exc.status_code == 401 else 'Bearer error="insufficient_scope"'
    return JSONResponse(
        {"detail": "Unauthorized" if exc.status_code == 401 else "Forbidden"},
        status_code=exc.status_code,
        headers={"WWW-Authenticate": challenge},
    )


@app.get("/health/live")
async def liveness():
    return {"status": "UP"}


@app.get("/health/ready")
async def readiness():
    return {"status": "UP"}


@app.post("/inventory/reserve")
async def reserve(request: Request, payload: Reservation, claims: dict[str, Any] = Depends(bearer_claims)):
    realm_access = claims.get("realm_access")
    raw_roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    roles = [role for role in raw_roles if isinstance(role, str)] if isinstance(raw_roles, list) else []
    if "user" not in roles:
        request.state.reason = "missing_role"
        raise AuthenticationFailure("missing_role", 403)
    if claims.get("azp") != "orders-api":
        request.state.reason = "wrong_client"
        raise AuthenticationFailure("wrong_client", 403)
    # The caller has been verified before its identity is used in the response.
    return {"reserved": True, "for": claims.get("preferred_username")}
