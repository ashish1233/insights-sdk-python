"""Identity: who is making this call.

Two kinds of principal, deliberately distinct (ADR-1):

- A **user**, authenticated through corporate SSO. Stubbed here.
- A **service**, used by scheduled jobs. A job has no human behind it, and
  attributing its access to a fake user would corrupt the audit trail that ADR-4
  depends on. Jobs get their own identity kind.

The SDK only *verifies* tokens. Issuing them is the identity provider's job
(`stubs/idp/`), so that a compromised tenant app cannot mint credentials.

Tokens are short-lived by design. ADR-1 chooses a library over a service, which
means there is no central place to revoke a token mid-flight. Short TTLs are the
compensating control: the blast radius of a leaked token is bounded by its
remaining lifetime rather than by our ability to recall it.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum

import jwt

ALGORITHM = "HS256"

USER_TOKEN_TTL_SECONDS = 3600
SERVICE_TOKEN_TTL_SECONDS = 900


def _signing_key() -> str:
    """Shared secret for the stubbed IdP.

    Real deployments replace this with asymmetric verification against the
    corporate IdP's published keys; nothing else in this module changes.
    """
    return os.environ.get(
        "INSIGHTS_TOKEN_SECRET",
        "dev-only-insecure-secret-replaced-by-the-idp-in-any-real-deployment",
    )


class PrincipalKind(str, Enum):
    USER = "user"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    kind: PrincipalKind
    subject: str
    tenant_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_service(self) -> bool:
        return self.kind is PrincipalKind.SERVICE

    def describe(self) -> str:
        """Short form used in telemetry and audit records."""
        return f"{self.kind.value}:{self.subject}"


class AuthError(Exception):
    """Authentication failed.

    Deliberately not an HTTPException. The SDK does not assume it is running
    inside a web framework — `jobs.py` uses this module too — and framework
    coupling here was the cause of a real bug: an HTTPException raised inside
    middleware sits outside Starlette's exception handling and surfaces as a 500
    rather than a 401. Translation to HTTP happens in `middleware.py`, which is
    the only layer that knows about HTTP.
    """


def issue_token(
    *,
    kind: PrincipalKind,
    subject: str,
    tenant_id: str,
    scopes: frozenset[str] | set[str] | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """Mint a token. Used by the stub IdP and by tests — not by tenant apps."""
    if ttl_seconds is None:
        ttl_seconds = (
            SERVICE_TOKEN_TTL_SECONDS
            if kind is PrincipalKind.SERVICE
            else USER_TOKEN_TTL_SECONDS
        )
    now = int(time.time())
    payload = {
        "sub": subject,
        "kind": kind.value,
        "tenant": tenant_id,
        "scopes": sorted(scopes or ()),
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, _signing_key(), algorithm=ALGORITHM)


def verify_token(token: str, *, expected_tenant: str) -> Principal:
    """Verify a token and bind it to the tenant this app serves.

    The `expected_tenant` check is a runtime gate from ADR-3: a valid token
    issued for tenant A must not be accepted by tenant B's app. Without it, a
    leaked token would be usable platform-wide rather than within one tenant.
    """
    try:
        claims = jwt.decode(token, _signing_key(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired.")
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"Token is not valid: {exc}")

    tenant_id = claims.get("tenant")
    subject = claims.get("sub")
    raw_kind = claims.get("kind")

    if not tenant_id or not subject or not raw_kind:
        raise AuthError("Token is missing required claims.")

    if tenant_id != expected_tenant:
        raise AuthError(
            f"Token was issued for tenant {tenant_id!r} but this app serves "
            f"{expected_tenant!r}."
        )

    try:
        kind = PrincipalKind(raw_kind)
    except ValueError:
        raise AuthError(f"Unknown principal kind {raw_kind!r}.")

    return Principal(
        kind=kind,
        subject=subject,
        tenant_id=tenant_id,
        scopes=frozenset(claims.get("scopes") or ()),
    )
