"""Scheduled job harness — the second paved road.

The brief says teams vary: some ship web apps, others batch jobs. Those differ in
more than packaging. A job has no user behind it, so attributing its work to a
fake user token would quietly corrupt the audit trail ADR-4 depends on — an
auditor reading "alice@ read the compensation dataset at 03:00" would be reading
a lie. Jobs therefore run as a **service principal**, which is a distinct kind of
identity rather than a borrowed one.

Jobs also report different signals. A web app is judged on latency and error
rate; a job is judged on whether it ran at all, how long it took, and whether it
has silently stopped running. `run()` emits those.
"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

import httpx

from .audit import AuditWriter
from .config import TenantConfig
from .data import RestClient, WarehouseClient
from .identity import Principal
from .telemetry import configure, get_logger, tenant_context

log = get_logger("jobs")


class JobContext:
    """What a job body is handed. Mirrors `Platform` for web apps."""

    def __init__(
        self,
        config: TenantConfig,
        principal: Principal,
        audit: AuditWriter,
    ) -> None:
        self.config = config
        self.principal = principal
        self.audit = audit
        self.warehouse = WarehouseClient(config, audit)
        self.rest = RestClient(config, audit)
        self.log = get_logger("job")


async def _fetch_service_token(config: TenantConfig, job_name: str) -> str:
    """Exchange the job's deploy-time credential for a short-lived token.

    Service tokens are shorter-lived than user tokens (15 minutes) because a job
    that runs for longer than that should be re-authenticating rather than
    holding a credential open — ADR-1 has no revocation path, so lifetime is the
    only control.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{config.idp_url}/token/service",
            json={"tenant_id": config.tenant_id, "service": job_name},
        )
        response.raise_for_status()
        return response.json()["token"]


async def run(
    name: str,
    body: Callable[[JobContext], Awaitable[Any]],
    *,
    config: TenantConfig,
) -> Any:
    """Run a job body with platform identity, telemetry, and audit.

    Exceptions are logged with their class and re-raised: the scheduler decides
    what a failure means, not the SDK. Swallowing them here would turn a failed
    export into a successful no-op, which is the worst outcome available.
    """
    configure()
    from .identity import verify_token

    token = await _fetch_service_token(config, name)
    principal = verify_token(token, expected_tenant=config.tenant_id)

    audit = AuditWriter(config)
    context = JobContext(config, principal, audit)

    started = time.monotonic()
    with tenant_context(config.tenant_id, principal):
        log.info("Job started.", job=name)
        try:
            result = await body(context)
        except Exception as exc:
            log.error(
                "Job failed.",
                job=name,
                duration_seconds=round(time.monotonic() - started, 3),
                error_class=type(exc).__name__,
            )
            raise
        log.info(
            "Job completed.",
            job=name,
            duration_seconds=round(time.monotonic() - started, 3),
        )
        return result
