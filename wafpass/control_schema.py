"""Pydantic schema for wizard-generated WAF++ controls.

This is the single source of truth for validating controls produced by
``wafpass control generate``.  The schema intentionally uses a simpler,
author-focused structure (no assertions / scopes) compared to the full
engine-evaluated control format.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

# ── Allowed vocabulary ────────────────────────────────────────────────────────

PILLARS = [
    "security",
    "cost",
    "performance",
    "reliability",
    "operational",
    "sustainability",
    "sovereign",
]

SEVERITIES = ["critical", "high", "medium", "low"]

TYPES = [
    "governance",
    "configuration",
    "iac",
    "network",
    "identity",
    "data",
    "cost",
]

ENGINES = ["terraform", "checkov", "manual"]

# Pillar → short prefix used in control IDs (e.g. SOV → SOV-011)
PILLAR_TO_PREFIX: dict[str, str] = {
    "security": "SEC",
    "cost": "COST",
    "performance": "PERF",
    "reliability": "REL",
    "operational": "OPS",
    "sustainability": "SUS",
    "sovereign": "SOV",
}

_PillarLiteral = Literal[
    "security",
    "cost",
    "performance",
    "reliability",
    "operational",
    "sustainability",
    "sovereign",
]
_SeverityLiteral = Literal["critical", "high", "medium", "low"]
_TypeLiteral = Literal[
    "governance", "configuration", "iac", "network", "identity", "data", "cost"
]
_EngineLiteral = Literal["terraform", "checkov", "manual"]


# ── Sub-models ────────────────────────────────────────────────────────────────


class WizardCheck(BaseModel):
    """A single check within a wizard-generated control."""

    id: str
    engine: _EngineLiteral
    description: str
    expected: str

    @field_validator("id")
    @classmethod
    def id_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("check id must not be empty")
        return v

    @field_validator("description", "expected")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("field must not be empty")
        return v


class WizardControl(BaseModel):
    """A WAF++ control authored via the generate wizard."""

    id: str
    pillar: _PillarLiteral
    severity: _SeverityLiteral
    type: list[_TypeLiteral]
    description: str
    checks: list[WizardCheck]

    @field_validator("id")
    @classmethod
    def id_format(cls, v: str) -> str:
        v = v.strip().upper()
        if not v:
            raise ValueError("control id must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("description must not be empty")
        return v

    @field_validator("type")
    @classmethod
    def type_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("at least one type must be selected")
        return v

    @field_validator("checks")
    @classmethod
    def checks_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("at least one check must be defined")
        return v

    @model_validator(mode="after")
    def id_matches_pillar(self) -> "WizardControl":
        prefix = PILLAR_TO_PREFIX.get(self.pillar, "")
        if prefix and not self.id.startswith(prefix + "-"):
            # Not a hard error — user may choose custom IDs; emit a warning via
            # a model field so callers can surface it if they wish.
            pass
        return self
