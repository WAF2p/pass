"""Bicep IaC plugin stub for WAF++ PASS.

Azure Bicep (``*.bicep``) support is not yet implemented.

When activated via ``--iac bicep``, this plugin will parse Bicep files and
map their constructs onto :class:`~wafpass.iac.base.IaCState` so that WAF++
controls with ``engine: bicep`` can be evaluated.

Planned mapping
---------------
Bicep construct          → IaCBlock
======================== ============================================
``resource`` declaration → block_type="resource", type=resource-type
``module`` reference     → block_type="module"
``param`` declaration    → block_type="variable"
``targetScope``          → block_type="config"

Implementation notes
--------------------
- The ``az bicep build`` CLI can compile Bicep to ARM JSON which is easier
  to parse programmatically.
- Alternatively, the ``bicep-runner`` PyPI package provides a Python binding.
- Region/location is typically carried in ``param location string`` and
  propagated to resources as ``location: location``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState  # noqa: F401
from wafpass.iac.registry import registry

logger = logging.getLogger(__name__)


class BicepPlugin:
    """IaC plugin stub for Azure Bicep (``.bicep``) files."""

    name: str = "bicep"
    file_extensions: list[str] = [".bicep"]

    def can_parse(self, path: Path) -> bool:
        if path.is_file():
            return path.suffix == ".bicep"
        if path.is_dir():
            return any(True for _ in path.rglob("*.bicep"))
        return False

    def parse(self, path: Path) -> IaCState:  # type: ignore[empty-body]
        logger.warning(
            "Bicep plugin is not yet implemented. "
            "Path '%s' will not be scanned. "
            "Returning empty IaCState.",
            path,
        )
        return IaCState()

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        return []


# ── Self-register ─────────────────────────────────────────────────────────────
registry.register(BicepPlugin())
