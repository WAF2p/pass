"""Backward-compatibility shim — Terraform parser public API.

Code that previously imported from ``wafpass.parser`` continues to work
unchanged.  New code should import directly from ``wafpass.iac``.

    # old (still works)
    from wafpass.parser import TerraformBlock, TerraformState, parse_terraform

    # new (preferred)
    from wafpass.iac import IaCBlock, IaCState, registry
"""

from __future__ import annotations

from pathlib import Path

# Re-export generic types under the old Terraform-specific names.
from wafpass.iac.base import IaCBlock as TerraformBlock  # noqa: F401
from wafpass.iac.base import IaCState as TerraformState  # noqa: F401

# Ensure the terraform plugin (and all others) are registered.
import wafpass.iac  # noqa: F401


def parse_terraform(path: Path) -> TerraformState:
    """Parse all ``.tf`` files under *path* and return a :class:`TerraformState`.

    This is a convenience wrapper around the Terraform plugin; equivalent to::

        from wafpass.iac import registry
        registry.get("terraform").parse(path)

    Args:
        path: Directory containing ``.tf`` files, or a single ``.tf`` file.

    Returns:
        :class:`TerraformState` (alias for :class:`~wafpass.iac.base.IaCState`)
        with all parsed blocks.
    """
    from wafpass.iac.registry import registry
    plugin = registry.get("terraform")
    if plugin is None:  # should never happen after importing wafpass.iac
        raise RuntimeError("Terraform plugin is not registered.")
    return plugin.parse(path)


__all__ = ["TerraformBlock", "TerraformState", "parse_terraform"]
