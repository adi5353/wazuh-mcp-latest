"""Pydantic v2 response schemas for Wazuh API output validation (Gap 13).

Every response from the Wazuh Manager or Indexer is validated against these
schemas before being forwarded to the LLM. Unknown fields are ignored; missing
optional fields receive safe defaults — preventing LLM hallucinations from
unexpected null values or missing keys in API responses.

Usage in tools::

    from .schemas import parse_alert, parse_agent, parse_vulnerability

    raw = await wz.request("GET", "/agents?agent_ids=001")
    agents = [parse_agent(a) for a in (raw.get("data", {}).get("affected_items") or [])]
"""
from __future__ import annotations

from typing import Any
import logging

log = logging.getLogger(__name__)

# Pydantic v2 is a dependency of the mcp package — always available.
try:
    from pydantic import BaseModel, Field, field_validator
    _PYDANTIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYDANTIC_AVAILABLE = False


# ── Alert schema ──────────────────────────────────────────────────────────────

class RuleInfo(BaseModel):
    model_config = {"extra": "ignore"}

    id: str = Field(default="0")
    description: str = Field(default="")
    level: int = Field(default=0)
    groups: list[str] = Field(default_factory=list)
    mitre: dict[str, Any] = Field(default_factory=dict)

    @field_validator("level", mode="before")
    @classmethod
    def coerce_level(cls, v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0


class AgentInfo(BaseModel):
    model_config = {"extra": "ignore"}

    id: str = Field(default="000")
    name: str = Field(default="unknown")
    ip: str = Field(default="")


class AlertResponse(BaseModel):
    """Single Wazuh alert document from the Indexer."""
    model_config = {"extra": "ignore"}

    id: str = Field(default="", alias="_id")
    timestamp: str = Field(default="", alias="@timestamp")
    rule: RuleInfo = Field(default_factory=RuleInfo)
    agent: AgentInfo = Field(default_factory=AgentInfo)
    full_log: str = Field(default="")
    location: str = Field(default="")

    model_config = {"extra": "ignore", "populate_by_name": True}


# ── Agent schema ──────────────────────────────────────────────────────────────

class AgentResponse(BaseModel):
    """Wazuh Manager agent record."""
    model_config = {"extra": "ignore"}

    id: str = Field(default="000")
    name: str = Field(default="unknown")
    ip: str = Field(default="")
    status: str = Field(default="unknown")
    os_name: str = Field(default="")
    os_version: str = Field(default="")
    version: str = Field(default="")
    last_keep_alive: str = Field(default="")
    group: list[str] = Field(default_factory=list)

    @field_validator("group", mode="before")
    @classmethod
    def coerce_group(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return list(v)


# ── Vulnerability schema ───────────────────────────────────────────────────────

class VulnerabilityResponse(BaseModel):
    """Single vulnerability record from Wazuh states index."""
    model_config = {"extra": "ignore"}

    cve: str = Field(default="")
    name: str = Field(default="")
    version: str = Field(default="")
    severity: str = Field(default="Unknown")
    cvss3_score: float = Field(default=0.0)
    status: str = Field(default="")
    published: str = Field(default="")

    @field_validator("cvss3_score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: Any) -> str:
        if not v:
            return "Unknown"
        return str(v).capitalize()


# ── SCA check schema ──────────────────────────────────────────────────────────

class SCACheckResponse(BaseModel):
    """Single SCA policy check result."""
    model_config = {"extra": "ignore"}

    id: int = Field(default=0)
    title: str = Field(default="")
    description: str = Field(default="")
    result: str = Field(default="")
    remediation: str = Field(default="")
    reason: str = Field(default="")

    @field_validator("id", mode="before")
    @classmethod
    def coerce_id(cls, v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0


# ── Parse helpers ─────────────────────────────────────────────────────────────

def _safe_parse(model_cls, data: dict) -> dict:
    """Validate `data` against `model_cls`. Returns a clean dict.

    On validation error, logs a warning and returns the raw data so the tool
    never crashes — LLM gets something rather than nothing.
    """
    if not _PYDANTIC_AVAILABLE or not isinstance(data, dict):
        return data
    try:
        return model_cls.model_validate(data, strict=False).model_dump(by_alias=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("Schema validation warning for %s: %s", model_cls.__name__, exc)
        return data


def parse_alert(data: dict) -> dict:
    """Validate and normalise a raw Indexer alert document."""
    return _safe_parse(AlertResponse, data)


def parse_agent(data: dict) -> dict:
    """Validate and normalise a raw Manager agent record."""
    return _safe_parse(AgentResponse, data)


def parse_vulnerability(data: dict) -> dict:
    """Validate and normalise a raw vulnerability record."""
    return _safe_parse(VulnerabilityResponse, data)


def parse_sca_check(data: dict) -> dict:
    """Validate and normalise a raw SCA check result."""
    return _safe_parse(SCACheckResponse, data)
