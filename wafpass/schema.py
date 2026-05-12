"""WAF++ PASS result schema — the serialisation contract.

This module defines the canonical JSON shape of a wafpass-result.json file.
It is the single source of truth used by:

  * ``wafpass check --output json``  (produces the payload)
  * ``wafpass-server POST /runs``     (validates the payload on ingest)
  * Dashboard / CI consumers         (parse the payload)

Consumers should import from here rather than duplicating these types.

Shape
-----
::

    {
      "schema_version": "1.0",
      "project":        "my-infra",
      "branch":         "main",
      "git_sha":        "abc1234",
      "triggered_by":   "github-actions",
      "iac_framework":  "terraform",
      "score":          82,
      "pillar_scores":  {"SEC": 90, "OPS": 75, ...},
      "path":           "infra/",
      "controls_loaded": 70,
      "controls_run":    65,
      "detected_regions": [["eu-central-1", "aws"]],
      "source_paths":   ["infra/"],
      "findings": [
        {
          "check_id":    "WAF-SEC-010-01",
          "check_title": "MFA enabled on root account",
          "control_id":  "WAF-SEC-010",
          "pillar":      "SEC",
          "severity":    "CRITICAL",
          "status":      "FAIL",
          "resource":    "aws_iam_account_password_policy.main",
          "message":     "mfa_delete is false",
          "remediation": "Set mfa_delete = true"
        },
        ...
      ]
    }
"""

from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class SecretFindingSchema(BaseModel):
    """A single hardcoded-secret finding from the WAF++ secret scanner.

    Note: ``raw_value`` is intentionally excluded — only the masked form is
    persisted so the server never stores live credential material.
    """

    file: str           # relative path to the source file
    line_no: int        # 1-based line number
    pattern_name: str   # human-readable label, e.g. "Hardcoded password"
    severity: str       # critical | high
    matched_key: str    # attribute name, e.g. "password" (empty for format patterns)
    masked_value: str   # first 4 chars + *** — never the full value
    suppressed: bool = False


class FindingSchema(BaseModel):
    """A single check result (one check × one resource)."""

    check_id: str
    check_title: str
    control_id: str
    pillar: str = ""
    severity: str
    status: str  # PASS | FAIL | SKIP | ERROR | WAIVED
    resource: str
    message: str
    remediation: str
    example: Optional[dict[str, Any]] = None
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)


class ControlCheckMetaSchema(BaseModel):
    """Lightweight metadata for a single automated check within a control."""

    id: str
    title: str
    severity: str
    remediation: str = ""
    example: Optional[dict[str, Any]] = None  # {"compliant": str, "non_compliant": str}


class ControlMetaSchema(BaseModel):
    """Metadata for a WAF++ control loaded during the scan.

    Carried inside WafpassResultSchema.controls_meta so that consumers
    (dashboard, CI) know exactly which controls were evaluated without
    needing access to the YAML files.
    """

    id: str
    title: str
    pillar: str
    severity: str
    category: str = ""
    description: str = ""
    rationale: str = ""
    threat: list[str] = Field(default_factory=list)
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)
    checks: list[ControlCheckMetaSchema] = Field(default_factory=list)


class WafpassResultSchema(BaseModel):
    """Top-level wafpass-result.json payload.

    Produced by ``wafpass check --output json`` and consumed by
    ``wafpass-server POST /runs``.
    """

    schema_version: str = Field(default="1.0", description="Schema version for forward-compatibility checks.")

    # ── Run metadata ──────────────────────────────────────────────────────────
    project: str = Field(default="", description="Human-readable project / repo name.")
    branch: str = Field(default="", description="VCS branch name, e.g. 'main'.")
    git_sha: str = Field(default="", description="Full or short commit SHA.")
    triggered_by: str = Field(
        default="local",
        description="How this run was triggered: local | github-actions | gitlab-ci | …",
    )
    iac_framework: str = Field(
        default="terraform",
        description="IaC framework scanned: terraform | cdk | bicep | pulumi | …",
    )
    stage: str = Field(
        default="",
        description="Deployment stage this run was executed against, e.g. dev | staging | prod.",
    )

    # ── Aggregate scores ──────────────────────────────────────────────────────
    score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Overall compliance score (0–100).",
    )
    pillar_scores: dict[str, int] = Field(
        default_factory=dict,
        description="Per-pillar scores, e.g. {'SEC': 90, 'OPS': 75}.",
    )

    # ── Scan context ──────────────────────────────────────────────────────────
    path: str = Field(default="", description="Display path(s) scanned.")
    controls_loaded: int = Field(default=0, ge=0)
    controls_run: int = Field(default=0, ge=0)
    detected_regions: list[list[str]] = Field(
        default_factory=list,
        description="Detected cloud regions: [[region, provider], ...].",
    )
    source_paths: list[str] = Field(default_factory=list)

    # ── Controls metadata ─────────────────────────────────────────────────────
    controls_meta: list[ControlMetaSchema] = Field(
        default_factory=list,
        description="Metadata for each control that was loaded during this run.",
    )

    # ── Findings ──────────────────────────────────────────────────────────────
    findings: list[FindingSchema] = Field(default_factory=list)

    # ── Secret scanner findings (optional, populated when --no-secrets is NOT set) ──
    secret_findings: list[SecretFindingSchema] = Field(
        default_factory=list,
        description=(
            "Hardcoded-secret findings from the WAF++ regex secret scanner. "
            "Only masked values are stored — raw credential material is never persisted."
        ),
    )

    # ── Terraform plan changes (optional, populated via --plan-file) ──────────
    plan_changes: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Normalised terraform plan change summary. "
            "Populated when --plan-file is passed to wafpass check. "
            "Shape: {terraform_version, format_version, scanned_at, summary, changes}."
        ),
    )
