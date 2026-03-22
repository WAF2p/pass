"""Pulumi IaC plugin stub for WAF++ PASS.

Pulumi support is not yet implemented.

When activated via ``--iac pulumi``, this plugin will parse Pulumi YAML
programs (``Pulumi.yaml``) and map resource declarations onto
:class:`~wafpass.iac.base.IaCState` so that WAF++ controls with
``engine: pulumi`` can be evaluated.

Planned approach
----------------
Pulumi supports multiple language SDKs (Python, TypeScript, Go, C#) in
addition to the declarative YAML format.  The most practical starting point
is the **Pulumi YAML** format, which is a first-class SDK and covers the
same use-cases as HCL:

1. Parse ``Pulumi.yaml`` (and ``Pulumi.<stack>.yaml`` stack overrides).
2. Map the ``resources:`` section to ``IaCBlock`` objects:
     - block_type="resource"
     - type=Pulumi resource type (e.g. "aws:s3/bucket:Bucket")
     - name=logical name
     - attributes=``properties`` dict + ``options`` dict
3. Parse ``config:`` → block_type="variable".
4. Infer region from stack config (``aws:region``, ``azure-native:location``, …).

For Python/TypeScript/Go programs, a best-effort AST analysis could be
added later, or users could export a Pulumi state snapshot (JSON) and parse
that instead.
"""

from __future__ import annotations

import logging
from pathlib import Path

from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState  # noqa: F401
from wafpass.iac.registry import registry

logger = logging.getLogger(__name__)


class PulumiPlugin:
    """IaC plugin stub for Pulumi YAML programs."""

    name: str = "pulumi"
    file_extensions: list[str] = [".yaml", ".yml"]

    def can_parse(self, path: Path) -> bool:
        if path.is_file():
            return path.name in ("Pulumi.yaml", "Pulumi.yml")
        if path.is_dir():
            return (path / "Pulumi.yaml").exists() or (path / "Pulumi.yml").exists()
        return False

    def parse(self, path: Path) -> IaCState:  # type: ignore[empty-body]
        logger.warning(
            "Pulumi plugin is not yet implemented. "
            "Path '%s' will not be scanned. "
            "Returning empty IaCState.",
            path,
        )
        return IaCState()

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        return []


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(PulumiPlugin())
