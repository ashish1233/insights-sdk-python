"""Telemetry: structured logs that cannot carry tenant data.

Two runtime gates from ADR-3 live here.

**Every record is tenant-tagged.** ADR-4's operator model is built entirely on
being able to answer "which tenant, which principal" for any line of telemetry.
A record without that is not useful and is not emitted.

**No payloads.** This is the control that matters most in practice. The realistic
way compensation data reaches an operator's screen is not a malicious query — it
is a well-meant `log.info(f"rows: {rows}")` in an exception handler. So the
logging API accepts scalar fields only and refuses collections outright, rather
than trusting every tenant to remember. The refusal names the alternative, because
a gate that blocks without explaining gets routed around.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

from .identity import Principal

_tenant: ContextVar[str | None] = ContextVar("tenant_id", default=None)
_principal: ContextVar[str | None] = ContextVar("principal", default=None)

MAX_FIELD_CHARS = 200


class PayloadInTelemetryError(Exception):
    """Raised when a caller tries to log something that may contain tenant data."""


def _reject_payload(key: str, value: Any) -> Any:
    if isinstance(value, (list, tuple, set, dict)):
        raise PayloadInTelemetryError(
            f"Telemetry field {key!r} is a {type(value).__name__}, which may contain "
            "tenant rows. Log a count or an identifier instead "
            f"(e.g. {key}_count={len(value)}). To share real data with the platform "
            "team, generate a scrubbed sample deliberately — see ADR-4."
        )
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        raise PayloadInTelemetryError(
            f"Telemetry field {key!r} is {len(value)} characters, over the "
            f"{MAX_FIELD_CHARS} limit. Long strings are how serialized records reach "
            "logs. Log an identifier rather than the content."
        )
    if not isinstance(value, (str, int, float, bool, type(None))):
        raise PayloadInTelemetryError(
            f"Telemetry field {key!r} is {type(value).__name__}; only scalars are "
            "accepted."
        )
    return value


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "tenant_id": _tenant.get(),
            "principal": _principal.get(),
        }
        extra = getattr(record, "fields", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["error_class"] = record.exc_info[0].__name__
        return json.dumps(payload)


class TenantLogger:
    """Logger that enforces the no-payload rule on every call."""

    def __init__(self, inner: logging.Logger) -> None:
        self._inner = inner

    def _emit(self, level: int, message: str, fields: dict[str, Any]) -> None:
        checked = {k: _reject_payload(k, v) for k, v in fields.items()}
        self._inner.log(level, message, extra={"fields": checked})

    def debug(self, message: str, **fields: Any) -> None:
        self._emit(logging.DEBUG, message, fields)

    def info(self, message: str, **fields: Any) -> None:
        self._emit(logging.INFO, message, fields)

    def warning(self, message: str, **fields: Any) -> None:
        self._emit(logging.WARNING, message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._emit(logging.ERROR, message, fields)

    def exception(self, message: str, **fields: Any) -> None:
        checked = {k: _reject_payload(k, v) for k, v in fields.items()}
        self._inner.exception(message, extra={"fields": checked})


_configured = False


def configure(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("insights")
    root.setLevel(level)
    root.handlers = [handler]
    root.propagate = False
    _configured = True


def get_logger(name: str) -> TenantLogger:
    configure()
    return TenantLogger(logging.getLogger(f"insights.{name}"))


@contextmanager
def tenant_context(tenant_id: str, principal: Principal | None) -> Iterator[None]:
    """Bind tenant and principal for the duration of a request or job run."""
    t = _tenant.set(tenant_id)
    p = _principal.set(principal.describe() if principal else None)
    try:
        yield
    finally:
        _tenant.reset(t)
        _principal.reset(p)


def current_tenant() -> str | None:
    return _tenant.get()


def health_payload(tenant_id: str, tier: str, version: str) -> dict[str, Any]:
    """The health contract every app must expose.

    ADR-4's operator view works only because all twenty-five apps answer the same
    shape; ADR-3 enforces that in CI rather than hoping for it.
    """
    return {
        "status": "ok",
        "tenant_id": tenant_id,
        "tier": tier,
        "sdk_version": version,
    }
