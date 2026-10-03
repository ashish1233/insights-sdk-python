"""Tenant configuration.

Tier is a platform-assigned property, not something a tenant asserts about itself
(ADR-2). It is read from the environment the platform controls at deploy time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class Tier(str, Enum):
    STANDARD = "standard"
    RESTRICTED = "restricted"


@dataclass(frozen=True)
class TenantConfig:
    tenant_id: str
    tier: Tier
    idp_url: str
    warehouse_url: str
    audit_url: str

    @property
    def is_restricted(self) -> bool:
        return self.tier is Tier.RESTRICTED


class ConfigError(RuntimeError):
    """Raised at startup when platform configuration is missing or invalid."""


def load_config() -> TenantConfig:
    """Load tenant config from the environment.

    Fails at startup rather than at first request: a misconfigured app should not
    accept traffic at all.
    """
    tenant_id = os.environ.get("INSIGHTS_TENANT_ID", "").strip()
    if not tenant_id:
        raise ConfigError(
            "INSIGHTS_TENANT_ID is not set. The platform sets this at deploy time; "
            "if you are running locally, see ONBOARDING.md."
        )

    raw_tier = os.environ.get("INSIGHTS_TIER", Tier.STANDARD.value).strip()
    try:
        tier = Tier(raw_tier)
    except ValueError:
        raise ConfigError(
            f"INSIGHTS_TIER={raw_tier!r} is not a known tier. "
            f"Valid values: {', '.join(t.value for t in Tier)}. "
            "Tier is assigned by the platform team (ADR-2); it is not self-selected."
        )

    return TenantConfig(
        tenant_id=tenant_id,
        tier=tier,
        idp_url=os.environ.get("INSIGHTS_IDP_URL", "http://localhost:8081"),
        warehouse_url=os.environ.get("INSIGHTS_WAREHOUSE_URL", "http://localhost:8082"),
        audit_url=os.environ.get("INSIGHTS_AUDIT_URL", "http://localhost:8083"),
    )
