"""Pulumi Python AWS defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry
from wafpass.fix_providers.terraform_aws import _TERRAFORM_AWS_BLOCK_DEFAULTS

fix_provider_registry.register(
    FixProvider(
        name="pulumi_aws",
        frameworks=["pulumi"],
        providers=["aws"],
        block_defaults=_TERRAFORM_AWS_BLOCK_DEFAULTS,
        resource_type_prefixes=["aws_"],
        provider_block_types=["aws"],
        block_modes={("aws_sqs_queue", "redrive_policy"): "jsonencode"},
    )
)
