"""Audit: the record of who touched which data.

Separate from telemetry on purpose. Telemetry is operational and may be sampled,
rotated, or dropped under load. Audit is evidence — it is what the compliance
partner reads (ADR-4), so it has different durability requirements and a
different destination.

The tier difference from ADR-2 is implemented here:

- **Restricted tier is fail-closed.** If the access cannot be recorded, the
  access does not happen. An unrecorded read of compensation data is worse than
  an outage, because the outage is visible and bounded and the unrecorded read is
  neither.
- **Standard tier is fail-open.** Events buffer locally and the request proceeds.
  Converting a telemetry outage into a platform-wide outage for ordinary
  reporting data would be a bad trade.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

import httpx

from .config import TenantConfig
from .identity import Principal
from .telemetry import get_logger

log = get_logger("audit")

_SINK_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class AuditEvent:
    tenant_id: str
    principal: str
    action: str
    resource: str
    result: str
    ts: float


class AuditUnavailable(Exception):
    """The audit sink could not be reached and the tier requires it."""


class AuditWriter:
    def __init__(self, config: TenantConfig) -> None:
        self._config = config
        self._buffered: list[AuditEvent] = []

    @property
    def buffered(self) -> list[AuditEvent]:
        """Events that could not be delivered. Exposed for the health endpoint:
        a growing buffer is an operational signal, not a silent condition."""
        return list(self._buffered)

    async def record(
        self,
        *,
        principal: Principal,
        action: str,
        resource: str,
        result: str = "ok",
    ) -> None:
        event = AuditEvent(
            tenant_id=self._config.tenant_id,
            principal=principal.describe(),
            action=action,
            resource=resource,
            result=result,
            ts=time.time(),
        )
        try:
            async with httpx.AsyncClient(timeout=_SINK_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self._config.audit_url}/events", json=asdict(event)
                )
                response.raise_for_status()
        except Exception as exc:
            if self._config.is_restricted:
                # ADR-2: restricted tier is fail-closed.
                raise AuditUnavailable(
                    "Audit sink unavailable; refusing the access because this "
                    "tenant is on the restricted tier."
                ) from exc
            self._buffered.append(event)
            log.warning(
                "Audit sink unavailable; buffering event.",
                action=action,
                buffered_count=len(self._buffered),
            )
