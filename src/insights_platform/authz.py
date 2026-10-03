"""Authorization: what this principal is allowed to do.

Scope checks are advisory in the standard tier and mandatory in the restricted
tier (ADR-2). A standard-tier team can write a route that never calls these
helpers; the warehouse role is their backstop and the audit trail is the
detection. A restricted-tier app cannot: `middleware.py` refuses to serve a
route that declares no scope requirement.
"""

from __future__ import annotations

from .config import TenantConfig
from .identity import Principal

READ_INSIGHTS = "insights:read"
READ_SENSITIVE = "insights:read_sensitive"
RUN_EXPORT = "export:run"


class AuthzError(Exception):
    """The principal is authenticated but not permitted to do this."""


def require_scope(principal: Principal, scope: str) -> None:
    """Raise unless the principal holds `scope`."""
    if scope not in principal.scopes:
        raise AuthzError(
            f"{principal.describe()} lacks required scope {scope!r}."
        )


def require_human(principal: Principal) -> None:
    """Raise if a service identity is used where a human is required.

    Some actions should never be taken by an unattended job — anything whose
    audit record would be meaningless without a person accountable for it.
    """
    if principal.is_service:
        raise AuthzError(
            "This action requires a user; service identities are not accepted."
        )


def assert_route_is_scoped(config: TenantConfig, declared_scope: str | None) -> None:
    """Startup-time check for restricted-tier apps.

    Called by `middleware.py` while registering routes. A restricted-tier app
    with an unscoped route fails to start rather than serving one unguarded
    endpoint — the fail-closed posture from ADR-2 applied at boot instead of at
    request time, where it is cheaper to notice.
    """
    if config.is_restricted and not declared_scope:
        raise RuntimeError(
            "Restricted-tier apps must declare a required scope on every route. "
            "Use @scoped(...) or explicitly mark the route public with "
            "@scoped(PUBLIC). See ADR-2."
        )


PUBLIC = "__public__"
