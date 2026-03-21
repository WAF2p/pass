"""AWS CDK IaC plugin stub for WAF++ PASS.

AWS CDK support is not yet implemented.

When activated via ``--iac cdk``, this plugin will parse synthesised CDK
output (CloudFormation JSON/YAML templates inside ``cdk.out/``) and map
constructs onto :class:`~wafpass.iac.base.IaCState` so that WAF++ controls
with ``engine: cdk`` can be evaluated.

Planned approach
----------------
1. Detect ``cdk.out/`` directory or individual CloudFormation template files
   (``*.template.json``, ``*.template.yaml``).
2. Parse the CloudFormation ``Resources`` section.  Each entry maps to an
   ``IaCBlock`` with:
     - block_type="resource"
     - type=CloudFormation resource type (e.g. "AWS::S3::Bucket")
     - name=logical ID
     - attributes=``Properties`` dict
3. Parse ``Parameters`` → block_type="variable".
4. Infer region from the CDK context (``cdk.context.json``) or environment
   configuration passed at synth time.

Supported file extensions: ``.template.json``, ``.template.yaml``, ``.json``
(under ``cdk.out/``).
"""

from __future__ import annotations

import logging
from pathlib import Path

from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState  # noqa: F401
from wafpass.iac.registry import registry

logger = logging.getLogger(__name__)


class CdkPlugin:
    """IaC plugin stub for AWS CDK synthesised CloudFormation output."""

    name: str = "cdk"
    file_extensions: list[str] = [".json", ".yaml", ".yml"]

    def can_parse(self, path: Path) -> bool:
        # Heuristic: look for cdk.out directory or *.template.json files
        if path.is_dir():
            return (path / "cdk.out").is_dir() or any(path.rglob("*.template.json"))
        if path.is_file():
            return path.name.endswith(".template.json") or path.name.endswith(".template.yaml")
        return False

    def parse(self, path: Path) -> IaCState:  # type: ignore[empty-body]
        logger.warning(
            "CDK plugin is not yet implemented. "
            "Path '%s' will not be scanned. "
            "Returning empty IaCState.",
            path,
        )
        return IaCState()

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        return []


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(CdkPlugin())
