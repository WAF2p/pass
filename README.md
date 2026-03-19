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

# Multi-cloud: scan multiple folders and merge into a single report
wafpass check ./aws ./azure ./gcp

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

# Generate a PDF report from multiple cloud folders
wafpass check ./aws ./azure --output pdf --pdf-out report.pdf

# Print version
wafpass --version
```

### Multi-cloud / multi-path scanning

Pass multiple paths to `check` to scan Terraform code spread across separate folders (e.g. one per cloud provider) and get a single unified report:

```bash
wafpass check ./infra/aws ./infra/azure ./infra/gcp
```

Each path is parsed independently; resources, providers, and detected regions are merged before controls are evaluated. All other flags (`--pillar`, `--fail-on`, `--output`, etc.) apply to the merged result as usual. When multiple paths are provided, the tool prints a `Scanning: <path>` line for each one so progress is visible in CI logs.

A typical multi-cloud repository layout:

```
infra/
├── aws/
│   ├── main.tf
│   └── variables.tf
├── azure/
│   ├── main.tf
│   └── variables.tf
└── gcp/
    ├── main.tf
    └── variables.tf
```

```bash
wafpass check infra/aws infra/azure infra/gcp --fail-on fail
```

## Intentional waivers (skipping controls on purpose)

Some controls may not apply to your setup, or you may have accepted the risk through an alternative compensating control. PASS lets you explicitly waive controls with a written justification so that:

- The control is shown as **WAIVED** (○) instead of FAIL or SKIP.
- The waiver reason is recorded in both the console output and the PDF report.
- Waived controls **never** cause a non-zero exit code, so CI pipelines are not blocked.
- Expired waivers trigger a warning, prompting the team to revisit the accepted risk.

### Waiver file format

Create a `.wafpass-skip.yml` file (auto-discovered in the current directory, or specify a path with `--skip-file`):

```yaml
# .wafpass-skip.yml
waivers:
  - id: WAF-SEC-020
    reason: "Handled by quarterly external IAM review — tracked in SEC-1234"
    expires: "2026-09-30"   # optional ISO-8601 date; triggers a warning when past

  - id: WAF-COST-010
    reason: "Cost tagging enforced at the Terraform module level, not individual resources"

  - id: WAF-SOV-030
    reason: "Sovereign data residency confirmed via contractual DPA with cloud provider"
    expires: "2027-01-01"
```

Each entry requires:
- `id` — the WAF++ control ID (e.g. `WAF-SEC-020`)
- `reason` — a mandatory plain-text justification

And optionally:
- `expires` — ISO-8601 date (`YYYY-MM-DD`); once past, a warning is printed but the waiver is still applied

### Using waivers

```bash
# Auto-discovery: place .wafpass-skip.yml in the current directory
wafpass check ./infra/

# Explicit path
wafpass check ./infra/ --skip-file ./compliance/accepted-risks.yml

# Works with multi-cloud paths too
wafpass check ./aws ./azure --skip-file ./accepted-risks.yml
```

Console output shows the waiver reason inline:

```
 WAF-SEC-020  Least Privilege & RBAC  [CRITICAL]  ○
  ○ WAIVED  Handled by quarterly external IAM review — tracked in SEC-1234
```

The summary line includes the WAIVED count:

```
  Summary   Controls: 70   ✓ PASS: 5   ✗ FAIL: 2   ─ SKIP: 61   ○ WAIVED: 2
```

The PDF report includes a **Waived Controls** table (purple header) listing every waived control and its recorded justification.

### Waivers and CI/CD

Waivers are safe to use in pipelines. A `WAIVED` control never increments `total_fail` or `total_skip`, so it cannot trigger a non-zero exit code regardless of the `--fail-on` mode. This means you can block a pipeline on real failures while allowing acknowledged exceptions to pass through.

If a waiver has expired, the tool prints a warning to stderr but continues normally — a deliberate choice so pipelines do not break unexpectedly. The intent is to prompt a human review, not an automated failure.

```yaml
# GitHub Actions: block on failures, allow waivers
- name: Run WAF++ PASS
  run: wafpass check ./infra/ --skip-file compliance/accepted-risks.yml --fail-on fail
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

## CI/CD integration

PASS is designed to run unattended in pipelines. The exit code reflects the check outcome; use `--fail-on` to tune the strictness.

**GitHub Actions example (multi-cloud):**

```yaml
- name: Run WAF++ PASS
  run: |
    pip install -e .
    wafpass check infra/aws infra/azure infra/gcp \
      --fail-on fail \
      --output pdf \
      --pdf-out wafpass-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: wafpass-report
    path: wafpass-report.pdf
```

**GitLab CI example:**

```yaml
wafpass:
  script:
    - pip install -e .
    - wafpass check infra/aws infra/azure --fail-on fail --summary
  artifacts:
    paths:
      - wafpass-report.pdf
```

## Running tests

```bash
pytest

# With coverage
pytest --cov=wafpass --cov-report=term-missing
```

## Links

- Framework documentation: [waf2p.dev](https://waf2p.dev)
- WAF++ GitHub: [github.com/waf2p](https://github.com/waf2p)
