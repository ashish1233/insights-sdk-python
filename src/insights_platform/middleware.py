"""FastAPI wiring — the only module in the SDK that knows about HTTP.

Everything else raises plain exceptions. That separation is deliberate and it
fixes a real class of bug: an `HTTPException` raised inside Starlette middleware
is *outside* the exception-handling middleware that would convert it, so it
surfaces as a 500 instead of the 401 the author intended. Translation happens
here, once, where the framework is actually in scope.

This module installs the three runtime gates ADR-3 commits to, and nothing else:
authentication, tenant-tagged telemetry, and — for restricted-tier apps —
a startup check that no route is unscoped.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.routing import Match

from .audit import AuditUnavailable, AuditWriter
from .authz import PUBLIC, AuthzError
from .config import TenantConfig
from .data import DataError, RestClient, WarehouseClient
from .identity import AuthError, Principal, verify_token
from .telemetry import (
    PayloadInTelemetryError,
    configure,
    get_logger,
    health_payload,
    tenant_context,
)

log = get_logger("http")

SDK_VERSION = "0.1.0"


def _public_paths(app: FastAPI) -> set[str]:
    """Paths exempt from auth and from the scoped-route check.

    Read from the app rather than hardcoded: FastAPI registers its own docs
    routes from these attributes, including `/docs/oauth2-redirect`, which is
    easy to forget. Hardcoding the list meant a plain `FastAPI()` on the
    restricted tier failed to start — the paved road did not work out of the
    box, which is the worst possible defect in a scaffold.
    """
    candidates = {
        "/health",
        app.docs_url,
        app.redoc_url,
        app.openapi_url,
        app.swagger_ui_oauth2_redirect_url,
    }
    return {path for path in candidates if path}


def _declared_scope(app: FastAPI, request: Request) -> str | None:
    """The scope the matched route declares via `@scoped(...)`, if any.

    Starlette only puts the matched route into the request scope once routing
    has happened, which is inside `call_next` — too late for middleware to act
    on. So the match is resolved here using the router's own predicate rather
    than a reimplementation of its matching rules.
    """
    for route in app.routes:
        match, _ = route.matches(request.scope)
        if match is Match.FULL:
            endpoint = getattr(route, "endpoint", None)
            return getattr(endpoint, "__insights_scope__", None)
    return None


@dataclass
class Platform:
    """Handed back to the app so routes can reach platform services."""

    config: TenantConfig
    audit: AuditWriter
    warehouse: WarehouseClient
    rest: RestClient


def scoped(scope: str) -> Callable[[Callable], Callable]:
    """Declare the scope a route requires.

    Restricted-tier apps must decorate every route; use `scoped(PUBLIC)` to mark
    one deliberately open. Standard-tier apps may use it but are not obliged to —
    the tier difference from ADR-2, expressed in the one place a tenant touches.
    """

    def decorate(endpoint: Callable) -> Callable:
        endpoint.__insights_scope__ = scope  # type: ignore[attr-defined]
        return endpoint

    return decorate


def current_principal(request: Request) -> Principal:
    """Route dependency returning the authenticated principal."""
    principal = getattr(request.state, "principal", None)
    if principal is None:
        # Unreachable through the middleware; present so that a route used
        # outside it fails loudly rather than silently returning None.
        raise AuthError("No authenticated principal on this request.")
    return principal


# Local development origins. The shell (:5100) is included because a federated
# standard-tier app is called from the shell's origin, not its own. A restricted
# app is never called from the shell — it is served from a separate origin
# precisely so it cannot be (ADR-2) — so a restricted tenant should narrow this
# to its own origin when calling `install`.
DEFAULT_DEV_ORIGINS = (
    "http://localhost:5100",
    "http://127.0.0.1:5100",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
)


def install(
    app: FastAPI,
    config: TenantConfig,
    *,
    allowed_origins: Sequence[str] = DEFAULT_DEV_ORIGINS,
) -> Platform:
    configure()
    audit = AuditWriter(config)
    platform = Platform(
        config=config,
        audit=audit,
        warehouse=WarehouseClient(config, audit),
        rest=RestClient(config, audit),
    )

    @app.middleware("http")
    async def _authenticate_and_tag(request: Request, call_next):
        if request.url.path in _public_paths(app):
            return await call_next(request)

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing bearer token."},
            )

        try:
            principal = verify_token(
                header[len("Bearer ") :], expected_tenant=config.tenant_id
            )
        except AuthError as exc:
            # Plain exception, explicit response — no 500s here.
            return JSONResponse(status_code=401, content={"detail": str(exc)})

        # Enforce the scope the route declares, rather than trusting the route
        # to check it itself. Declaring `@scoped(READ_SENSITIVE)` and then
        # forgetting `require_scope` in the body would otherwise serve the data
        # to any authenticated caller — a silent failure, and exactly the kind
        # ADR-2 says the restricted tier must not be able to have.
        declared = _declared_scope(app, request)
        if declared and declared != PUBLIC and declared not in principal.scopes:
            with tenant_context(config.tenant_id, principal):
                log.warning("Refused: missing scope.", required_scope=declared)
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"{principal.describe()} lacks required scope "
                    f"{declared!r}."
                },
            )

        request.state.principal = principal
        with tenant_context(config.tenant_id, principal):
            # One record per request, on completion, carrying what an operator
            # actually asks: which route, how long, what happened. ADR-4's
            # default view is built from exactly these fields, and a request
            # log without a duration cannot answer "is it slow", which is the
            # first question of most incidents.
            started = time.monotonic()
            try:
                response = await call_next(request)
            except Exception as exc:
                log.error(
                    "Request failed.",
                    method=request.method,
                    path=request.url.path,
                    duration_ms=round((time.monotonic() - started) * 1000, 1),
                    error_class=type(exc).__name__,
                )
                raise
            log.info(
                "Request completed.",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round((time.monotonic() - started) * 1000, 1),
            )
            return response

    # Added last, so it sits outermost. A CORS preflight is an OPTIONS request
    # with no Authorization header; if the auth middleware saw it first every
    # browser call would fail with a 401 that looks nothing like a CORS problem.
    # This lives in the platform rather than in each app precisely because it is
    # the kind of thing twenty-five teams would each get subtly wrong.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(AuthzError)
    async def _authz(_: Request, exc: AuthzError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuditUnavailable)
    async def _audit_down(_: Request, exc: AuditUnavailable) -> JSONResponse:
        # Restricted tier, fail-closed (ADR-2). 503 rather than 500: this is a
        # deliberate refusal, and the distinction matters to whoever is paged.
        log.error("Refusing request: audit unavailable on restricted tier.")
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(DataError)
    async def _data(_: Request, exc: DataError) -> JSONResponse:
        log.error("Data source failed.", error_class=type(exc).__name__)
        return JSONResponse(status_code=502, content={"detail": "Data source failed."})

    @app.exception_handler(PayloadInTelemetryError)
    async def _payload(_: Request, exc: PayloadInTelemetryError) -> JSONResponse:
        # A tenant bug, surfaced loudly rather than swallowed, so it is fixed
        # before it reaches production.
        log.error("Telemetry rejected a payload.")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.get("/health")
    async def _health() -> dict[str, Any]:
        payload = health_payload(config.tenant_id, config.tier.value, SDK_VERSION)
        payload["audit_buffered"] = len(audit.buffered)
        return payload

    def _verify_routes_are_scoped() -> None:
        if not config.is_restricted:
            return
        public = _public_paths(app)
        unscoped = [
            route.path
            for route in app.routes
            if getattr(route, "endpoint", None) is not None
            and route.path not in public
            and getattr(route.endpoint, "__insights_scope__", None) is None
        ]
        if unscoped:
            raise RuntimeError(
                "Restricted-tier app has unscoped routes: "
                + ", ".join(sorted(unscoped))
                + ". Decorate each with @scoped(...) or @scoped(PUBLIC). See ADR-2."
            )

    # Wrap the app's lifespan so the check runs before it accepts traffic. Routes
    # are registered after install(), so this cannot be a straight call.
    _inner_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(scope_app: FastAPI):
        _verify_routes_are_scoped()
        async with _inner_lifespan(scope_app):
            yield

    app.router.lifespan_context = _lifespan

    log.info(
        "Platform installed.", tenant=config.tenant_id, tier=config.tier.value
    )
    return platform


__all__ = [
    "Platform",
    "install",
    "scoped",
    "current_principal",
    "Depends",
    "PUBLIC",
]
