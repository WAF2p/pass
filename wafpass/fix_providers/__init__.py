"""Pluggable auto-fix providers.

A fix provider supplies framework- and cloud-provider-specific defaults so the
auto-fixer can turn failing assertions into concrete patches.  Providers are
loaded automatically when the ``wafpass.fix_providers`` package is imported.

Register a new provider by importing ``fix_provider_registry`` and calling
``register()``::

    from wafpass.fix_providers import FixProvider, fix_provider_registry

    fix_provider_registry.register(FixProvider(
        name="terraform_aws",
        frameworks=["terraform"],
        providers=["aws"],
        block_defaults={...},
        resource_type_prefixes=["aws_"],
    ))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FixProvider:
    """Provider-specific auto-fix metadata.

    Attributes:
        name: Unique provider id, e.g. ``terraform_aws``.
        frameworks: IaC frameworks this provider applies to (e.g. ["terraform"]).
        providers: Cloud provider names from control/provider metadata
            (e.g. ["aws"]). Multiple related provider names can be listed,
            e.g. ["azure", "azurerm", "azapi"].
        block_defaults: Mapping from (resource_type, attribute_path) to a default
            value/template dict.  These make ``attribute_exists`` assertions
            fixable.  Use resource type ``*`` as a wildcard.
        resource_type_prefixes: Optional prefixes used to auto-detect the
            provider from a resource type like ``aws_s3_bucket`` or
            ``azurerm_storage_account``.
    """

    name: str
    frameworks: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    block_defaults: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    resource_type_prefixes: list[str] = field(default_factory=list)
    # Optional rendering mode overrides for specific (resource_type, attribute_path)
    # entries in ``block_defaults``.  Supported values: "block" (default),
    # "jsonencode", "map".
    block_modes: dict[tuple[str, str], str] = field(default_factory=dict)
    # Bare Terraform provider names this provider covers for provider {} blocks,
    # e.g. ["aws"] for provider "aws" {}, ["hcloud"] for provider "hcloud" {}.
    provider_block_types: list[str] = field(default_factory=list)

    def supports_resource(
        self, framework: str, provider_name: str | None, res_type: str
    ) -> bool:
        """Return True if this provider claims the given resource/provider block."""
        if framework and framework.lower() not in [f.lower() for f in self.frameworks]:
            return False
        lower_provider = (provider_name or "").lower()
        if lower_provider in {p.lower() for p in self.providers}:
            return True
        lower_res = res_type.lower()
        for prefix in self.resource_type_prefixes:
            if lower_res.startswith(prefix.lower()):
                return True
        if lower_res in {p.lower() for p in self.provider_block_types}:
            return True
        return False

    def lookup_block_template(
        self, res_type: str, attribute_path: str
    ) -> dict[str, Any] | None:
        """Return default dict for a missing block/attribute, if known."""
        # Exact resource type match wins.
        if (res_type, attribute_path) in self.block_defaults:
            return self.block_defaults[(res_type, attribute_path)]
        # Fallback: match a wildcard resource type '*'.
        if ("*", attribute_path) in self.block_defaults:
            return self.block_defaults[("*", attribute_path)]
        return None

    def lookup_nested_default(self, res_type: str, attribute_path: str) -> Any | None:
        """Return a default value for a dotted attribute path."""
        parts = attribute_path.split(".")
        defaults = self.lookup_block_template(res_type, parts[0])
        if defaults is None:
            return None
        value: Any = defaults
        for part in parts[1:]:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        return value


class FixProviderRegistry:
    """Registry of FixProvider instances."""

    def __init__(self) -> None:
        self._providers: dict[str, FixProvider] = {}

    def register(self, provider: FixProvider) -> None:
        self._providers[provider.name] = provider

    def get(self, name: str) -> FixProvider | None:
        return self._providers.get(name)

    def all(self) -> list[FixProvider]:
        return list(self._providers.values())

    def find_provider(
        self, framework: str, provider_name: str | None, res_type: str
    ) -> FixProvider | None:
        """Find the first registered provider that claims this resource."""
        for provider in self._providers.values():
            if provider.supports_resource(framework, provider_name, res_type):
                return provider
        return None


# Module-level singleton.
fix_provider_registry = FixProviderRegistry()

# Auto-load bundled providers so importing this package populates the registry.
from wafpass.fix_providers import cdk_aws  # noqa: E402,F401
from wafpass.fix_providers import pulumi_aws  # noqa: E402,F401
from wafpass.fix_providers import terraform_alicloud  # noqa: E402,F401
from wafpass.fix_providers import terraform_aws  # noqa: E402,F401
from wafpass.fix_providers import terraform_azure  # noqa: E402,F401
from wafpass.fix_providers import terraform_core  # noqa: E402,F401
from wafpass.fix_providers import terraform_digitalocean  # noqa: E402,F401
from wafpass.fix_providers import terraform_gcp  # noqa: E402,F401
from wafpass.fix_providers import terraform_hcloud  # noqa: E402,F401
from wafpass.fix_providers import terraform_oci  # noqa: E402,F401
from wafpass.fix_providers import terraform_openstack  # noqa: E402,F401
from wafpass.fix_providers import terraform_ovh  # noqa: E402,F401
from wafpass.fix_providers import terraform_scaleway  # noqa: E402,F401
from wafpass.fix_providers import terraform_stackit  # noqa: E402,F401
from wafpass.fix_providers import terraform_yandex  # noqa: E402,F401
