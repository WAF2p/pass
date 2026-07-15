"""Terraform core/framework defaults for the WAF++ auto-fixer.

These defaults apply to the top-level ``terraform { ... }`` configuration block
rather than to a specific cloud provider.
"""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_CORE_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("terraform", "required_version"): ">= 1.6.0, < 2.0.0",
    ("terraform", "required_providers"): {
        "aws": {"source": "hashicorp/aws", "version": "~> 5.0"},
        "azurerm": {"source": "hashicorp/azurerm", "version": "~> 3.100"},
        "google": {"source": "hashicorp/google", "version": "~> 5.0"},
    },
    # Generic tag controls do not apply to terraform blocks, but keep the key
    # for consistency with other providers.
    ("*", "tags"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_core",
        frameworks=["terraform"],
        providers=["terraform"],
        block_defaults=_TERRAFORM_CORE_BLOCK_DEFAULTS,
        resource_type_prefixes=[],
        provider_block_types=["terraform"],
    )
)
