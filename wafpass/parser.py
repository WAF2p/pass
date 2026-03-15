"""Parse Terraform .tf files into structured TerraformState objects.

python-hcl2 output format (verified against hcl2 >= 4.3):
  - Each top-level block type maps to a list of dicts.
  - resource: [{"aws_s3_bucket": {"my_bucket": {...attrs...}}}, ...]
  - provider: [{"aws": {...attrs...}}, ...]
  - variable: [{"my_var": {...attrs...}}, ...]
  - module:   [{"my_module": {...attrs...}}, ...]
  - terraform: [{...attrs...}]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

logger = logging.getLogger(__name__)


@dataclass
class TerraformBlock:
    """A single parsed Terraform block (resource, provider, variable, etc.)."""

    block_type: str       # resource | provider | variable | terraform | module
    type: str             # e.g. "aws_s3_bucket", "aws", "my_var"
    name: str             # e.g. "example"  (empty for provider/variable/terraform)
    address: str          # e.g. "aws_s3_bucket.example"
    attributes: dict      # key-value attributes from the HCL block
    raw: dict             # original parsed dict


@dataclass
class TerraformState:
    """Aggregated state from all parsed .tf files in a directory."""

    resources: list[TerraformBlock] = field(default_factory=list)
    providers: list[TerraformBlock] = field(default_factory=list)
    variables: list[TerraformBlock] = field(default_factory=list)
    modules: list[TerraformBlock] = field(default_factory=list)
    terraform_blocks: list[TerraformBlock] = field(default_factory=list)


def _parse_resource_blocks(raw_list: list, state: TerraformState) -> None:
    """Parse 'resource' blocks.

    hcl2 format: [{"aws_s3_bucket": {"my_bucket": {...attrs...}}}, ...]
    Each list item maps one resource type to a dict of {name: attrs}.
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for resource_type, names_dict in item.items():
            if not isinstance(names_dict, dict):
                continue
            for resource_name, attrs_raw in names_dict.items():
                attrs = attrs_raw if isinstance(attrs_raw, dict) else {}
                block = TerraformBlock(
                    block_type="resource",
                    type=resource_type,
                    name=resource_name,
                    address=f"{resource_type}.{resource_name}",
                    attributes=attrs,
                    raw={resource_type: {resource_name: attrs_raw}},
                )
                state.resources.append(block)


def _parse_provider_blocks(raw_list: list, state: TerraformState) -> None:
    """Parse 'provider' blocks.

    hcl2 format: [{"aws": {...attrs...}}, {"azurerm": {...attrs...}}]
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for provider_name, attrs_raw in item.items():
            attrs = attrs_raw if isinstance(attrs_raw, dict) else {}
            block = TerraformBlock(
                block_type="provider",
                type=provider_name,
                name="",
                address=f"provider.{provider_name}",
                attributes=attrs,
                raw={provider_name: attrs_raw},
            )
            state.providers.append(block)


def _parse_variable_blocks(raw_list: list, state: TerraformState) -> None:
    """Parse 'variable' blocks.

    hcl2 format: [{"my_var": {...attrs...}}, ...]
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for var_name, attrs_raw in item.items():
            attrs = attrs_raw if isinstance(attrs_raw, dict) else {}
            block = TerraformBlock(
                block_type="variable",
                type=var_name,
                name=var_name,
                address=f"var.{var_name}",
                attributes=attrs,
                raw={var_name: attrs_raw},
            )
            state.variables.append(block)


def _parse_module_blocks(raw_list: list, state: TerraformState) -> None:
    """Parse 'module' blocks.

    hcl2 format: [{"my_module": {...attrs...}}, ...]
    """
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        for mod_name, attrs_raw in item.items():
            attrs = attrs_raw if isinstance(attrs_raw, dict) else {}
            block = TerraformBlock(
                block_type="module",
                type=mod_name,
                name=mod_name,
                address=f"module.{mod_name}",
                attributes=attrs,
                raw={mod_name: attrs_raw},
            )
            state.modules.append(block)


def _parse_terraform_blocks(raw_list: list, state: TerraformState) -> None:
    """Parse 'terraform' configuration blocks.

    hcl2 format: [{...attrs...}]
    """
    for item in raw_list:
        attrs = item if isinstance(item, dict) else {}
        block = TerraformBlock(
            block_type="terraform",
            type="terraform",
            name="",
            address="terraform",
            attributes=attrs,
            raw=item if isinstance(item, dict) else {},
        )
        state.terraform_blocks.append(block)


def _parse_hcl2_file(content: str, state: TerraformState, file_path: Path) -> None:
    """Parse a single .tf file content and add blocks to state."""
    try:
        parsed: dict = hcl2.loads(content)
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", file_path, exc)
        return

    for block_type, block_value in parsed.items():
        if not isinstance(block_value, list):
            continue
        try:
            if block_type == "resource":
                _parse_resource_blocks(block_value, state)
            elif block_type == "provider":
                _parse_provider_blocks(block_value, state)
            elif block_type == "variable":
                _parse_variable_blocks(block_value, state)
            elif block_type == "module":
                _parse_module_blocks(block_value, state)
            elif block_type == "terraform":
                _parse_terraform_blocks(block_value, state)
        except Exception as exc:
            logger.warning("Error processing %s block in %s: %s", block_type, file_path, exc)


def parse_terraform(path: Path) -> TerraformState:
    """Parse all .tf files in the given path (recursively).

    Args:
        path: Path to a directory containing .tf files, or a single .tf file.

    Returns:
        TerraformState with all parsed blocks.
    """
    state = TerraformState()

    if path.is_file():
        tf_files = [path]
    elif path.is_dir():
        tf_files = sorted(path.rglob("*.tf"))
    else:
        logger.error("Path does not exist: %s", path)
        return state

    if not tf_files:
        logger.warning("No .tf files found in: %s", path)
        return state

    for tf_path in tf_files:
        try:
            content = tf_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", tf_path, exc)
            continue

        _parse_hcl2_file(content, state, tf_path)

    logger.debug(
        "Parsed %d resources, %d providers, %d variables, %d modules, %d terraform blocks",
        len(state.resources),
        len(state.providers),
        len(state.variables),
        len(state.modules),
        len(state.terraform_blocks),
    )
    return state
