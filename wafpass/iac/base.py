"""Abstract base types for IaC plugins in WAF++ PASS."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class IaCBlock:
    """A single parsed IaC block (resource, provider, variable, etc.).

    This is the framework-agnostic representation of any IaC configuration
    block.  Each plugin maps its native constructs (HCL resource blocks,
    Bicep resources, CDK constructs, Pulumi resources, …) onto this model so
    that the assertion engine can evaluate them uniformly.
    """

    block_type: str   # resource | provider | variable | module | config
    type: str         # e.g. "aws_s3_bucket", "aws", "Microsoft.Storage/storageAccounts"
    name: str         # e.g. "example"  (empty for some block types)
    address: str      # e.g. "aws_s3_bucket.example"
    attributes: dict  # key-value attributes extracted from the block
    raw: dict         # original parsed representation (plugin-specific)


@dataclass
class IaCState:
    """Aggregated state produced by parsing one or more IaC source files.

    Every IaC plugin returns an IaCState.  Plugins populate whichever fields
    are meaningful for their format; unused fields stay empty.

    ``config_blocks`` is a catch-all for framework-level configuration that
    has no resource equivalent:
      - Terraform: ``terraform { … }`` blocks
      - CDK: stack-level configuration objects
      - Pulumi: project/stack config
      - Bicep: ``targetScope`` declarations
    """

    resources: list[IaCBlock] = field(default_factory=list)
    providers: list[IaCBlock] = field(default_factory=list)
    variables: list[IaCBlock] = field(default_factory=list)
    modules: list[IaCBlock] = field(default_factory=list)
    config_blocks: list[IaCBlock] = field(default_factory=list)

    # ── Backward-compatibility alias ──────────────────────────────────────────
    # The engine and parser.py shim historically used ``terraform_blocks``.
    # Keeping a property lets old code keep working without touching the engine.
    @property
    def terraform_blocks(self) -> list[IaCBlock]:
        return self.config_blocks

    @terraform_blocks.setter
    def terraform_blocks(self, value: list[IaCBlock]) -> None:
        self.config_blocks = value


@runtime_checkable
class IaCPlugin(Protocol):
    """Protocol that every IaC parser plugin must satisfy.

    Plugins are lightweight objects (usually a module-level singleton) that
    know how to:
      1. Detect whether a path contains files they can parse.
      2. Parse those files into an :class:`IaCState`.
      3. Extract cloud-region information from the parsed state.

    Register a plugin with the global registry::

        from wafpass.iac.registry import registry
        registry.register(MyPlugin())
    """

    #: Short identifier used in ``--iac`` CLI flag and in control YAML
    #: ``engine:`` fields, e.g. ``"terraform"``, ``"bicep"``, ``"cdk"``,
    #: ``"pulumi"``.
    name: str

    #: File extensions this plugin handles, e.g. ``[".tf"]``.
    file_extensions: list[str]

    def can_parse(self, path: Path) -> bool:
        """Return True if *path* contains files this plugin can parse."""
        ...

    def parse(self, path: Path) -> IaCState:
        """Parse all matching files under *path* and return an :class:`IaCState`."""
        ...

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        """Return ``(region_name, provider)`` tuples detected in *state*."""
        ...
