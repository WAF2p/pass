# WAF++ PASS

**WAF++ PASS** is a CLI tool that checks Terraform (`.tf`) files against the [WAF++ framework](https://waf2p.dev) YAML control definitions and produces a structured compliance report.

## Installation

```bash
# Using pip
pip install -e .

# Using uv (recommended)
uv pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"
uv pip install -e ".[dev]"
```

## Controls directory setup

PASS reads controls from a local `controls/` directory (gitignored by default — controls are synced from the framework repo, not committed here).

Copy controls from the WAF++ framework repository:

```bash
cp /path/to/waf++/framework/modules/controls/controls/*.yml controls/
```

Or use a symlink / sync script appropriate for your workflow.

## Usage

```bash
# Check all controls against a Terraform directory
wafpass check ./infra/

# Filter by pillar
wafpass check ./infra/ --pillar cost

# Run specific controls only
wafpass check ./infra/ --controls WAF-COST-010,WAF-COST-020

# Filter by minimum severity and show all results
wafpass check ./infra/ --severity high --verbose

# Exit non-zero if any check is skipped (strictest mode)
wafpass check ./infra/ --fail-on any

# Use a custom controls directory
wafpass check ./infra/ --controls-dir /path/to/controls

# Show only the summary table
wafpass check ./infra/ --summary

# Print version
wafpass --version
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed |
| `1`  | Failures detected (or skips, depending on `--fail-on`) |
| `2`  | Errors (missing controls dir, unreadable Terraform files, etc.) |

## `--fail-on` modes

| Mode  | Exits non-zero when… |
|-------|----------------------|
| `fail` (default) | Any check status is FAIL |
| `skip` | Any check status is FAIL or SKIP |
| `any`  | Any check status is not PASS |

## Supported pillars

| Pillar | Prefix |
|--------|--------|
| `cost` | `WAF-COST-*` |
| `sovereign` | `WAF-SOV-*` |
| `security` | `WAF-SEC-*` |
| `reliability` | `WAF-REL-*` |
| `operations` | `WAF-OPS-*` |
| `architecture` | `WAF-ARCH-*` |
| `governance` | `WAF-GOV-*` |

## Running tests

```bash
pytest

# With coverage
pytest --cov=wafpass --cov-report=term-missing
```

## Links

- Framework documentation: [waf2p.dev](https://waf2p.dev)
- WAF++ GitHub: [github.com/waf2p](https://github.com/waf2p)
