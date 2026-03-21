"""Abstract base types for monitoring/observability export plugins in WAF++ PASS.

Export plugins receive the run snapshot produced by ``wafpass.state`` and push
it to an external system (Grafana, Datadog, Splunk, a generic webhook, …).

Implementing a new plugin
-------------------------
1. Create ``wafpass/export/plugins/mytool.py``::

    from wafpass.export.base import ExportPlugin, ExportResult
    from wafpass.export.registry import registry

    class MyToolPlugin:
        name = "mytool"
        description = "Push WAF++ metrics to MyTool."

        def export(self, snapshot: dict, config: dict) -> ExportResult:
            # snapshot: full run snapshot from wafpass.state
            # config:   plugin-specific keys from .wafpass-export.yml
            try:
                # … send data to MyTool …
                return ExportResult(success=True, message="OK", details={})
            except Exception as exc:
                return ExportResult(success=False, message=str(exc), details={})

    registry.register(MyToolPlugin())

2. Add an import to ``wafpass/export/plugins/__init__.py``::

    from wafpass.export.plugins import mytool  # noqa: F401

3. Document the expected config keys in a YAML comment block at the top of
   your plugin file and in the README.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class ExportResult:
    """Outcome of a single plugin export call."""

    success: bool
    message: str
    details: dict = field(default_factory=dict)


@runtime_checkable
class ExportPlugin(Protocol):
    """Protocol that every monitoring export plugin must satisfy.

    Plugins are lightweight singletons that translate a WAF++ run snapshot
    into whatever format the target system expects, then deliver it over the
    network.  They are stateless — all connection parameters come from
    *config*.

    The *snapshot* dict produced by :func:`wafpass.state.build_run_snapshot`
    is the canonical input:

    .. code-block:: python

        {
            "schema_version": 1,
            "run_id": "20260321-152251-a1e136bd",
            "generated_at": "2026-03-21T15:22:51+00:00",
            "tool_version": "0.1.0",
            "iac_plugin": "terraform",
            "source_paths": ["./infra"],
            "score": 45,
            "totals": {"controls_run": 70, "pass": 55, "fail": 10, "skip": 5, "waived": 0},
            "pillar_scores": {"cost": 20, "security": 60, ...},
            "control_statuses": {"WAF-COST-010": "PASS", ...},
            "control_details": {...},
            "diff_from_previous": {...},   # only present when a previous run exists
        }
    """

    #: Short identifier used in ``--export`` CLI flag, e.g. ``"grafana"``.
    name: str

    #: One-line description shown in ``--help`` and error messages.
    description: str

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        """Push *snapshot* to the target monitoring system.

        Args:
            snapshot: Full run snapshot from :func:`wafpass.state.build_run_snapshot`.
            config:   Plugin-specific configuration dict (parsed from
                      ``exports.<name>`` in ``.wafpass-export.yml``).

        Returns:
            :class:`ExportResult` indicating success or failure.
        """
        ...
