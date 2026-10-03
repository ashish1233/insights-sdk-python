"""Insights Platform SDK.

The paved road for internal insight apps: identity, authorization, scoped data
access, telemetry, and audit. See `docs/adr/` for why it is a library rather than
a set of services, and `ONBOARDING.md` for how a team starts.
"""

from .audit import AuditUnavailable, AuditWriter
from .authz import (
    PUBLIC,
    READ_INSIGHTS,
    READ_SENSITIVE,
    RUN_EXPORT,
    AuthzError,
    require_human,
    require_scope,
)
from .config import ConfigError, TenantConfig, Tier, load_config
from .data import DataClient, DataError, RestClient, WarehouseClient
from .identity import AuthError, Principal, PrincipalKind, issue_token, verify_token
from .jobs import JobContext
from .jobs import run as run_job
from .middleware import Platform, current_principal, install, scoped
from .telemetry import PayloadInTelemetryError, get_logger, tenant_context

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # configuration
    "TenantConfig",
    "Tier",
    "load_config",
    "ConfigError",
    # identity
    "Principal",
    "PrincipalKind",
    "verify_token",
    "issue_token",
    "AuthError",
    # authorization
    "require_scope",
    "require_human",
    "AuthzError",
    "READ_INSIGHTS",
    "READ_SENSITIVE",
    "RUN_EXPORT",
    "PUBLIC",
    # data
    "DataClient",
    "WarehouseClient",
    "RestClient",
    "DataError",
    # telemetry and audit
    "get_logger",
    "tenant_context",
    "PayloadInTelemetryError",
    "AuditWriter",
    "AuditUnavailable",
    # web apps
    "install",
    "scoped",
    "current_principal",
    "Platform",
    # jobs
    "run_job",
    "JobContext",
]
