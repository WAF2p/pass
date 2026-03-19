"""Data models for WAF++ PASS."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Assertion:
    """A single assertion within a check."""

    attribute: str
    op: str
    # Optional fields depending on operator
    expected: object = None          # normalised: covers 'value' and 'values' from YAML
    key: str | None = None           # for key_exists
    pattern: str | None = None       # for matches / not_matches
    message: str | None = None       # human-readable failure message
    fallback_attribute: str | None = None  # for attribute_exists_or_fallback


@dataclass
class Scope:
    """Scope definition for a check (which Terraform block types to target)."""

    block_type: str  # resource | provider | variable | terraform | module
    resource_types: list[str] = field(default_factory=list)
    provider_name: str | None = None


@dataclass
class Check:
    """A single automated check within a control."""

    id: str
    engine: str
    provider: str
    automated: bool
    severity: str
    title: str
    scope: Scope
    assertions: list[Assertion]
    on_fail: str
    remediation: str


@dataclass
class Control:
    """A WAF++ control loaded from a YAML file."""

    id: str
    title: str
    pillar: str
    severity: str
    category: str
    description: str
    checks: list[Check]
    regulatory_mapping: list[dict] = field(default_factory=list)
    # Each entry: {"framework": str, "controls": list[str]}


@dataclass
class CheckResult:
    """Result of evaluating a single check against a single Terraform block."""

    check_id: str
    check_title: str
    control_id: str
    severity: str
    status: str          # PASS | FAIL | SKIP | ERROR
    resource: str        # e.g. "aws_s3_bucket.example"
    message: str
    remediation: str


@dataclass
class ControlResult:
    """Aggregated result for a full control (all checks, all matched blocks)."""

    control: Control
    results: list[CheckResult] = field(default_factory=list)

    @property
    def status(self) -> str:
        """PASS if all results pass, FAIL if any fail, SKIP otherwise."""
        if not self.results:
            return "SKIP"
        statuses = {r.status for r in self.results}
        if "FAIL" in statuses:
            return "FAIL"
        if "PASS" in statuses:
            return "PASS"
        return "SKIP"


@dataclass
class Report:
    """Top-level report aggregating all control results for one or more Terraform paths."""

    path: str  # Display string; for multi-path scans this is all paths joined with " | "
    controls_loaded: int
    controls_run: int
    results: list[ControlResult] = field(default_factory=list)
    detected_regions: list[tuple[str, str]] = field(default_factory=list)
    # Each entry: (region_name, provider) e.g. ("eu-central-1", "aws")
    source_paths: list[str] = field(default_factory=list)
    # Individual paths scanned (mirrors path when single; populated for multi-path runs)

    @property
    def total_pass(self) -> int:
        return sum(1 for r in self.results if r.status == "PASS")

    @property
    def total_fail(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")

    @property
    def total_skip(self) -> int:
        return sum(1 for r in self.results if r.status == "SKIP")

    @property
    def check_pass(self) -> int:
        return sum(1 for cr in self.results for r in cr.results if r.status == "PASS")

    @property
    def check_fail(self) -> int:
        return sum(1 for cr in self.results for r in cr.results if r.status == "FAIL")

    @property
    def check_skip(self) -> int:
        return sum(1 for cr in self.results for r in cr.results if r.status == "SKIP")
