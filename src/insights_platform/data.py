"""Data access: shared connections, scoped per tenant.

The third runtime gate from ADR-3 lives here. Every query carries the tenant
scope, injected by the client rather than supplied by the caller — a tenant
cannot ask for another tenant's rows because there is no parameter through which
to ask.

The warehouse role the connection uses is the backstop (ADR-2): if this scoping
is ever wrong, the database still refuses. Belt and braces, because the gap
between them is where ADR-5's weakest omission sits — nothing automatically
verifies those grants today.

Audit is recorded **before** the fetch, not after. On the restricted tier a
failed audit write must prevent the disclosure, and an audit written afterwards
cannot do that.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from .audit import AuditWriter
from .config import TenantConfig
from .identity import Principal
from .telemetry import get_logger, tenant_context

log = get_logger("data")

_TIMEOUT_SECONDS = 10.0

# Keys the SDK owns. A caller supplying one is trying — probably by accident —
# to choose their own tenant scope.
_RESERVED_QUERY_KEYS = frozenset({"tenant_id", "dataset"})


def _reject_reserved(params: dict[str, Any]) -> None:
    clash = _RESERVED_QUERY_KEYS & params.keys()
    if clash:
        raise DataError(
            f"{', '.join(sorted(clash))} is set by the platform and cannot be "
            "passed to fetch(). Tenant scope is not a caller parameter (ADR-2)."
        )


class DataError(Exception):
    """A data source failed or refused the request."""


class DataClient(ABC):
    """Base for all data connections.

    Tenants may subclass this to reach a source the platform does not provide.
    Doing so means re-implementing the scope injection and audit calls below, so
    the SDK's own connectors should be preferred wherever they fit.
    """

    def __init__(self, config: TenantConfig, audit: AuditWriter) -> None:
        self._config = config
        self._audit = audit

    def _tagged(self, principal: Principal):
        """Bind tenant context for the duration of a fetch.

        The HTTP middleware and the job harness already bind it, and re-binding
        is harmless. This exists for the third case: code calling a client
        directly — a notebook, a test, a tenant's own background task. ADR-4's
        operator model assumes every telemetry record carries a tenant, and
        without this those calls would emit `tenant_id: null`, which is exactly
        the record an auditor cannot use.
        """
        return tenant_context(self._config.tenant_id, principal)

    @abstractmethod
    async def fetch(self, principal: Principal, resource: str, **params: Any) -> Any:
        ...


class WarehouseClient(DataClient):
    """The shared analytical warehouse.

    Stubbed by `stubs/warehouse/`. The real implementation swaps the transport
    and keeps the scoping and audit behaviour unchanged.
    """

    async def fetch(
        self, principal: Principal, resource: str, **params: Any
    ) -> list[dict[str, Any]]:
        with self._tagged(principal):
            await self._audit.record(
                principal=principal, action="warehouse.read", resource=resource
            )

            # The gate. `tenant_id` is injected and the caller cannot reach it:
            # reserved keys are rejected loudly rather than silently ignored,
            # and the injection happens after the splat so ordering cannot
            # betray us if someone edits this later.
            #
            # An earlier version splatted `**params` last, which meant
            # `fetch(principal, "compensation", tenant_id="finance")` quietly
            # replaced the scope. ADR-2's whole threat model is the careless
            # query; a gate that a typo can disable is not a gate.
            _reject_reserved(params)
            query = {**params, "tenant_id": self._config.tenant_id, "dataset": resource}
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                    response = await client.post(
                        f"{self._config.warehouse_url}/query", json=query
                    )
                    response.raise_for_status()
                    rows = response.json()["rows"]
            except Exception as exc:
                raise DataError(
                    f"Warehouse query failed for {resource!r}: {exc}"
                ) from exc

            # Row count, never rows — telemetry refuses payloads anyway (ADR-4).
            log.info("Warehouse read.", dataset=resource, row_count=len(rows))
            return rows


class RestClient(DataClient):
    """An internal REST API registered as a shared data connection.

    Stubbed by `stubs/warehouse/` under a different path. Tenant scope travels as
    a header because the upstream owns its own filtering; the platform's job is
    to assert who is asking, not to rewrite someone else's API.
    """

    async def fetch(
        self, principal: Principal, resource: str, **params: Any
    ) -> dict[str, Any]:
        with self._tagged(principal):
            await self._audit.record(
                principal=principal, action="rest.read", resource=resource
            )
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                    response = await client.get(
                        f"{self._config.warehouse_url}/rest/{resource}",
                        params=params,
                        headers={"X-Insights-Tenant": self._config.tenant_id},
                    )
                    response.raise_for_status()
                    payload = response.json()
            except Exception as exc:
                raise DataError(f"REST call failed for {resource!r}: {exc}") from exc

            log.info("REST read.", resource=resource)
            return payload
