"""Tests for the guarantees the ADRs make.

Each test names the decision it defends. These exist because an ADR that claims
something the code does not do is worse than no ADR — it is a false statement
about a system someone will rely on.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insights_platform import (
    PUBLIC,
    READ_INSIGHTS,
    READ_SENSITIVE,
    AuditUnavailable,
    AuditWriter,
    AuthError,
    Principal,
    PrincipalKind,
    TenantConfig,
    Tier,
    current_principal,
    install,
    issue_token,
    scoped,
    verify_token,
)
from insights_platform.middleware import Depends
from insights_platform.telemetry import PayloadInTelemetryError, get_logger


def make_config(tier: Tier = Tier.STANDARD, tenant: str = "finance") -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant,
        tier=tier,
        idp_url="http://idp.invalid",
        warehouse_url="http://warehouse.invalid",
        audit_url="http://audit.invalid",
    )


# --- ADR-1: service identity is distinct from user identity -------------------


def test_service_identity_is_not_a_user():
    token = issue_token(
        kind=PrincipalKind.SERVICE, subject="nightly-export", tenant_id="finance"
    )
    principal = verify_token(token, expected_tenant="finance")
    assert principal.is_service
    assert principal.describe() == "service:nightly-export"


def test_service_tokens_are_shorter_lived_than_user_tokens():
    from insights_platform.identity import (
        SERVICE_TOKEN_TTL_SECONDS,
        USER_TOKEN_TTL_SECONDS,
    )

    # ADR-1: no revocation path, so lifetime is the only control.
    assert SERVICE_TOKEN_TTL_SECONDS < USER_TOKEN_TTL_SECONDS


# --- ADR-2 / ADR-3: a token is bound to one tenant ----------------------------


def test_token_from_another_tenant_is_rejected():
    token = issue_token(
        kind=PrincipalKind.USER, subject="alice@corp", tenant_id="people-analytics"
    )
    with pytest.raises(AuthError, match="people-analytics"):
        verify_token(token, expected_tenant="finance")


# --- ADR-3, gate 1: authentication -------------------------------------------


def build_app(tier: Tier = Tier.STANDARD) -> FastAPI:
    app = FastAPI()
    config = make_config(tier)
    install(app, config)

    @app.get("/data")
    @scoped(PUBLIC)
    async def read(principal: Principal = Depends(current_principal)):
        return {"principal": principal.describe()}

    return app


def test_missing_token_is_401():
    with TestClient(build_app()) as client:
        assert client.get("/data").status_code == 401


def test_malformed_token_is_401_not_500():
    """Regression test.

    An HTTPException raised inside Starlette middleware is not converted by the
    exception-handling middleware and surfaces as a 500. The SDK raises plain
    exceptions and translates them in `middleware.install`, so a bad token is a
    401 — which is what ADR-3 claims and what an operator needs to see.
    """
    with TestClient(build_app()) as client:
        response = client.get("/data", headers={"Authorization": "Bearer nonsense"})
        assert response.status_code == 401
        assert "not valid" in response.json()["detail"]


def test_valid_token_reaches_the_route():
    token = issue_token(
        kind=PrincipalKind.USER, subject="alice@corp", tenant_id="finance"
    )
    with TestClient(build_app()) as client:
        response = client.get("/data", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json()["principal"] == "user:alice@corp"


def test_cors_preflight_survives_the_auth_gate():
    """A preflight carries no Authorization header.

    If the auth middleware saw it first, every browser call would fail with a
    401 that looks nothing like the CORS problem it actually is. The CORS
    middleware is installed last so it sits outermost.
    """
    with TestClient(build_app()) as client:
        response = client.options(
            "/data",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        assert response.status_code == 200
        assert (
            response.headers["access-control-allow-origin"]
            == "http://localhost:5173"
        )


def test_health_is_public_and_reports_the_contract():
    """ADR-4's operator view requires all apps to answer the same shape."""
    with TestClient(build_app()) as client:
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["tenant_id"] == "finance"
        assert body["tier"] == "standard"
        assert "sdk_version" in body


# --- ADR-3, gate 2: telemetry carries no payloads -----------------------------


def test_telemetry_refuses_collections():
    log = get_logger("test")
    rows = [{"employee": "alice", "salary": 120_000}]
    with pytest.raises(PayloadInTelemetryError, match="may contain tenant rows"):
        log.info("fetched", rows=rows)


def test_telemetry_refuses_long_strings():
    log = get_logger("test")
    with pytest.raises(PayloadInTelemetryError, match="over the"):
        log.info("dump", blob="x" * 500)


def test_telemetry_accepts_counts():
    log = get_logger("test")
    log.info("fetched", row_count=1, dataset="headcount")  # must not raise


# --- ADR-2: restricted tier is fail-closed on audit ---------------------------


async def test_restricted_tier_refuses_when_audit_is_unreachable():
    writer = AuditWriter(make_config(Tier.RESTRICTED, "people-analytics"))
    principal = Principal(
        kind=PrincipalKind.USER, subject="alice@corp", tenant_id="people-analytics"
    )
    with pytest.raises(AuditUnavailable):
        await writer.record(
            principal=principal, action="warehouse.read", resource="compensation"
        )


async def test_caller_cannot_override_the_tenant_scope():
    """Regression. ADR-2's gate must not be reachable from the call site.

    The query dict used to splat `**params` *after* the injected scope, so
    `fetch(principal, "compensation", tenant_id="finance")` silently replaced
    it. ADR-2's threat model is the careless query; a gate a typo can disable
    is not a gate. Reserved keys are now refused rather than ignored, so the
    mistake is loud.
    """
    from insights_platform.data import DataError, WarehouseClient

    config = make_config(Tier.STANDARD, "finance")
    client = WarehouseClient(config, AuditWriter(config))
    principal = Principal(
        kind=PrincipalKind.USER, subject="bob@corp", tenant_id="finance"
    )

    with pytest.raises(DataError, match="set by the platform"):
        await client.fetch(principal, "spend", tenant_id="people-analytics")

    with pytest.raises(DataError, match="set by the platform"):
        await client.fetch(principal, "spend", dataset="compensation")


async def test_direct_client_call_is_still_tenant_tagged():
    """ADR-4 assumes *every* telemetry record carries a tenant.

    The HTTP middleware and the job harness bind that context, but a client
    called directly — from a notebook, a test, a tenant's own background task —
    would otherwise emit `tenant_id: null`, which is the one record an auditor
    cannot use. The data clients bind it themselves for that reason.
    """
    import json
    import logging

    from insights_platform.data import DataError, WarehouseClient
    from insights_platform.telemetry import _JsonFormatter, configure

    captured: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(self.format(record))

    configure()
    handler = _Capture()
    handler.setFormatter(_JsonFormatter())
    logging.getLogger("insights").addHandler(handler)
    try:
        config = make_config(Tier.STANDARD, "finance")
        client = WarehouseClient(config, AuditWriter(config))
        principal = Principal(
            kind=PrincipalKind.USER, subject="bob@corp", tenant_id="finance"
        )
        with pytest.raises(DataError):
            await client.fetch(principal, "spend")
    finally:
        logging.getLogger("insights").removeHandler(handler)

    emitted = [json.loads(line) for line in captured]
    assert emitted, "expected the client to emit telemetry"
    assert all(record["tenant_id"] == "finance" for record in emitted)
    assert all(record["principal"] == "user:bob@corp" for record in emitted)


async def test_standard_tier_buffers_when_audit_is_unreachable():
    writer = AuditWriter(make_config(Tier.STANDARD, "finance"))
    principal = Principal(
        kind=PrincipalKind.USER, subject="bob@corp", tenant_id="finance"
    )
    await writer.record(principal=principal, action="warehouse.read", resource="spend")
    assert len(writer.buffered) == 1


# --- ADR-2: restricted tier cannot have unscoped routes -----------------------


def test_restricted_app_refuses_to_start_with_an_unscoped_route():
    app = FastAPI()
    install(app, make_config(Tier.RESTRICTED, "people-analytics"))

    @app.get("/leaky")
    async def leaky():
        return {}

    # Assert on the route that is actually at fault. An earlier version of this
    # test passed because FastAPI's own `/docs/oauth2-redirect` was being
    # flagged, which meant it would have passed even with `/leaky` scoped.
    with pytest.raises(RuntimeError, match=r"unscoped routes: /leaky"):
        with TestClient(app):
            pass


def test_restricted_app_starts_with_only_platform_routes():
    """A plain FastAPI app on the restricted tier must boot.

    FastAPI registers `/docs/oauth2-redirect` from its own configuration, and a
    hardcoded exemption list missed it — so the paved road did not work out of
    the box. The exemptions are now read from the app itself.
    """
    app = FastAPI()
    install(app, make_config(Tier.RESTRICTED, "people-analytics"))

    @app.get("/report")
    @scoped(READ_SENSITIVE)
    async def report():
        return {}

    with TestClient(app):
        pass


def test_declared_scope_is_enforced_even_if_the_route_forgets():
    """ADR-2 says restricted-tier scope checks cannot be disabled by the tenant.

    That is only true if the middleware enforces the declared scope itself. A
    route that declares one and then forgets `require_scope` in its body would
    otherwise serve compensation data to any authenticated caller — a silent
    failure, and the exact shape of bug the tier exists to prevent.
    """
    app = FastAPI()
    install(app, make_config(Tier.RESTRICTED, "people-analytics"))

    @app.get("/compensation")
    @scoped(READ_SENSITIVE)
    async def compensation():
        # Deliberately does not call require_scope.
        return {"rows": ["sensitive"]}

    without = issue_token(
        kind=PrincipalKind.USER,
        subject="alice@corp",
        tenant_id="people-analytics",
        scopes={READ_INSIGHTS},
    )
    with_sensitive = issue_token(
        kind=PrincipalKind.USER,
        subject="alice@corp",
        tenant_id="people-analytics",
        scopes={READ_INSIGHTS, READ_SENSITIVE},
    )

    with TestClient(app) as client:
        denied = client.get(
            "/compensation", headers={"Authorization": f"Bearer {without}"}
        )
        assert denied.status_code == 403
        assert READ_SENSITIVE in denied.json()["detail"]

        allowed = client.get(
            "/compensation", headers={"Authorization": f"Bearer {with_sensitive}"}
        )
        assert allowed.status_code == 200


def test_standard_app_starts_with_an_unscoped_route():
    app = FastAPI()
    install(app, make_config(Tier.STANDARD, "finance"))

    @app.get("/relaxed")
    async def relaxed():
        return {}

    with TestClient(app):
        pass  # standard tier tolerates it; the warehouse role is the backstop
