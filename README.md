# WAF++ PASS

**WAF++ PASS** is a CLI tool that checks IaC (Infrastructure-as-Code) files against the [WAF++ framework](https://waf2p.dev) YAML control definitions and produces a structured compliance report.

Supported IaC frameworks are loaded as **plugins** — Terraform and AWS CDK are fully implemented; Bicep and Pulumi are available as stubs ready for contribution.

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
# Check all controls against a Terraform directory (default plugin)
wafpass check ./infra/

# Explicitly select the Terraform plugin
wafpass check ./infra/ --iac terraform

# Check a CDK project (reads cdk.out/*.template.json)
wafpass check ./my-cdk-app/ --iac cdk

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

Pass multiple paths to `check` to scan IaC code spread across separate folders (e.g. one per cloud provider) and get a single unified report:

```bash
wafpass check ./infra/aws ./infra/azure ./infra/gcp
```

Each path is parsed independently; resources, providers, and detected regions are merged before controls are evaluated. All other flags (`--pillar`, `--fail-on`, `--output`, etc.) apply to the merged result as usual. When multiple paths are provided, the tool prints a `Scanning [terraform]: <path>` line for each one so progress is visible in CI logs.

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

---

## IaC plugin system

WAF++ PASS uses a plugin architecture so that different IaC frameworks can be supported without changing the core engine or the YAML control definitions.

### Available plugins

| Plugin | `--iac` flag | File type | Status |
|--------|-------------|-----------|--------|
| Terraform | `terraform` (default) | `*.tf` | Fully implemented |
| AWS CDK | `cdk` | `cdk.out/*.template.json` | Fully implemented |
| Bicep | `bicep` | `*.bicep` | Stub – not yet implemented |
| Pulumi | `pulumi` | `Pulumi.yaml` | Stub – not yet implemented |

Stub plugins register themselves in the global registry and log a clear warning when invoked, but return an empty state. They serve as the integration skeleton for contributors.

### Selecting a plugin

```bash
# Default (Terraform)
wafpass check ./infra/

# Explicit plugin selection
wafpass check ./cdk-app/ --iac cdk
wafpass check ./bicep-modules/ --iac bicep
wafpass check ./pulumi-app/ --iac pulumi
```

### How plugins work

Every plugin is a Python class that satisfies the `IaCPlugin` protocol:

```python
class IaCPlugin(Protocol):
    name: str                    # e.g. "terraform"
    file_extensions: list[str]   # e.g. [".tf"]

    def can_parse(self, path: Path) -> bool: ...
    def parse(self, path: Path) -> IaCState: ...
    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]: ...
```

`parse()` returns an `IaCState` — a framework-agnostic bag of `IaCBlock` objects (resources, providers, variables, modules, config blocks). The assertion engine operates exclusively on `IaCState`, so adding a new plugin does not require touching the engine, controls, or reporters.

### Writing a new plugin

1. Create `wafpass/iac/plugins/myframework.py`:

```python
from pathlib import Path
from wafpass.iac.base import IaCBlock, IaCPlugin, IaCState
from wafpass.iac.registry import registry

class MyFrameworkPlugin:
    name = "myframework"
    file_extensions = [".mf"]

    def can_parse(self, path: Path) -> bool:
        return path.is_dir() and any(path.rglob("*.mf"))

    def parse(self, path: Path) -> IaCState:
        state = IaCState()
        # … parse files and append IaCBlock objects to state.resources etc. …
        return state

    def extract_regions(self, state: IaCState) -> list[tuple[str, str]]:
        # … return [(region_name, provider_name), …] …
        return []

registry.register(MyFrameworkPlugin())
```

2. Add an import to `wafpass/iac/plugins/__init__.py`:

```python
from wafpass.iac.plugins import myframework  # noqa: F401
```

3. Write WAF++ controls with `engine: myframework` in the YAML `checks:` section.

### IaCState and IaCBlock

| Field | Description |
|-------|-------------|
| `IaCState.resources` | All resource declarations |
| `IaCState.providers` | Cloud provider configuration blocks |
| `IaCState.variables` | Input variable declarations |
| `IaCState.modules` | Module references |
| `IaCState.config_blocks` | Framework-level config (`terraform {}`, target scope, stack config, …) |

Each `IaCBlock` carries:
- `block_type` — `"resource"`, `"provider"`, `"variable"`, `"module"`, `"config"`, …
- `type` — resource type string (e.g. `"aws_s3_bucket"`, `"AWS::S3::Bucket"`)
- `name` — logical name within the IaC source
- `address` — fully-qualified address (e.g. `"aws_s3_bucket.example"`)
- `attributes` — dict of configuration attributes (what assertions are evaluated against)
- `raw` — original parsed representation (plugin-specific)

### Controls and the `engine` field

Each check in a WAF++ control YAML declares which engine it targets:

```yaml
checks:
  - id: "waf-cost-010.tf.aws.compute-mandatory-tags"
    engine: "terraform"        # ← only evaluated when --iac terraform
    provider: "aws"
    …
```

When you run `wafpass check --iac cdk`, only checks with `engine: cdk` are evaluated; Terraform-specific checks are silently skipped. This lets a single control file hold checks for multiple frameworks side by side.

### CDK plugin

The CDK plugin parses synthesised CloudFormation templates (`cdk.out/*.template.json`) produced by `cdk synth`.  It does not require the CDK CLI at runtime — only the JSON output.

**What is parsed**

| CloudFormation section | Maps to |
|------------------------|---------|
| `Resources` | `IaCBlock(block_type="resource", type="AWS::S3::Bucket", …)` |
| `Parameters` | `IaCBlock(block_type="variable")` |
| `manifest.json` | `IaCBlock(block_type="manifest")` — used for region extraction |

**Attribute normalisation** applied before assertions run:

| Resource type | Normalisation |
|---|---|
| All | Tags array `[{"Key":…,"Value":…}]` → plain dict |
| `AWS::S3::Bucket` | `_EncryptionAlgorithm`, `_EncryptionKeyId`, `_VersioningStatus`, `_HasLifecycleRules` added as top-level attributes |
| `AWS::IAM::Role/Policy` | `_HasWildcardActions`, `_HasWildcardResources` (bool) derived from inline policy statements |
| `AWS::KMS::Key` | `deletion_window_in_days` alias added for `PendingWindowInDays` |
| `AWS::RDS::DBInstance/Cluster` | PascalCase properties kept as-is (`MultiAZ`, `StorageEncrypted`, `BackupRetentionPeriod`) |

**Region detection** reads `aws://ACCOUNT/REGION` environment strings from `cdk.out/manifest.json`.

**CDK checks shipped with WAF++ controls**

| Control | Check | What it verifies |
|---------|-------|-----------------|
| WAF-COST-010 | `waf-cost-010.cdk.aws.resource-mandatory-tags` | All 4 cost tags on S3/RDS/EC2/Lambda/ECS |
| WAF-COST-040 | `waf-cost-040.cdk.aws.s3-lifecycle-rules-defined` | `_HasLifecycleRules = true` |
| WAF-SOV-030 | `waf-sov-030.cdk.aws.s3-versioning-enabled` | `_VersioningStatus = "Enabled"` |
| WAF-SOV-030 | `waf-sov-030.cdk.aws.rds-backup-retention` | `BackupRetentionPeriod >= 7` |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.kms-key-rotation-enabled` | `EnableKeyRotation = true` |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.s3-kms-encryption` | `_EncryptionAlgorithm = "aws:kms"` + CMK set |
| WAF-SOV-050 | `waf-sov-050.cdk.aws.rds-storage-encrypted` | `StorageEncrypted = true` |
| WAF-REL-010 | `waf-rel-010.cdk.aws.rds-multi-az` | `MultiAZ = true` |
| WAF-REL-010 | `waf-rel-010.cdk.aws.rds-automated-backups` | `BackupRetentionPeriod >= 1` |

**CDK dummy project**

A ready-to-use dummy CDK project lives at `../dummy_cdk/` (relative to this repo), mirroring the Terraform demo code in `../dummy_code/`.

```
dummy_cdk/
├── bin/app.ts                              # CDK app entry point (eu-central-1)
├── lib/wafpp-demo-stack.ts                 # TypeScript stack source with PASS/FAIL annotations
├── cdk.out/
│   ├── WafppDemoStack.template.json        # Synthesised CloudFormation — the plugin's parse target
│   └── manifest.json                       # Stack environment (region) metadata
├── cdk.json
└── package.json
```

The template intentionally contains both **compliant** and **non-compliant** resources so every result state (PASS / FAIL / SKIP) is exercised:

| Resource | Controls hit | Expected result |
|----------|-------------|-----------------|
| `DataLakeBucket` | WAF-COST-010, WAF-COST-040, WAF-SOV-030, WAF-SOV-050 | PASS |
| `LogsRawBucket` | WAF-COST-010, WAF-COST-040, WAF-SOV-030, WAF-SOV-050 | FAIL |
| `SovereignCmk` | WAF-SOV-050 | PASS |
| `MainDb` | WAF-COST-010, WAF-SOV-030, WAF-SOV-050, WAF-REL-010 | PASS |
| `SingleAzDb` | WAF-COST-010, WAF-SOV-030, WAF-REL-010 | FAIL |

```bash
# Run the CDK plugin against the demo project
wafpass check ../dummy_cdk --iac cdk --verbose

# Summary only
wafpass check ../dummy_cdk --iac cdk --summary

# Filter to the 5 controls that have CDK checks
wafpass check ../dummy_cdk --iac cdk \
  --controls WAF-COST-010,WAF-COST-040,WAF-SOV-030,WAF-SOV-050,WAF-REL-010 \
  --verbose
```

---

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

---

## Run versioning & change tracking

WAF++ PASS automatically records every run as a versioned JSON snapshot in a local state directory (default: `.wafpass-state/`). On subsequent runs, changes in control status are detected and shown in the console report and the PDF.

### State directory layout

```
.wafpass-state/
  index.json          ← lightweight index of all runs (machine-readable)
  runs/
    run-20260321-152251-a1e136bd.json   ← full snapshot per run
    run-20260321-160000-def67890.json
    …
```

### Snapshot content

Each run file is a self-contained JSON document:

```json
{
  "schema_version": 1,
  "run_id": "20260321-152251-a1e136bd",
  "generated_at": "2026-03-21T15:22:51+00:00",
  "tool_version": "0.1.0",
  "iac_plugin": "terraform",
  "source_paths": ["./infra"],
  "score": 45,
  "totals": { "controls_run": 70, "pass": 55, "fail": 10, "skip": 5, "waived": 0 },
  "pillar_scores": { "cost": 20, "security": 60, "sovereign": 0 },
  "control_statuses": { "WAF-COST-010": "PASS", "WAF-SEC-020": "FAIL" },
  "control_details": { "WAF-COST-010": { "status": "PASS", "severity": "high", … } },
  "diff_from_previous": {
    "previous_run_id": "…",
    "score_delta": 5,
    "regressions": [{ "control_id": "WAF-SEC-020", "from": "PASS", "to": "FAIL", … }],
    "improvements": [],
    "other_changes": []
  }
}
```

### Console output — Changes section

After each run (when a previous run exists), the console shows a **Changes from Previous Run** section:

```
────────────────────────── Changes from Previous Run ───────────────────────────
  Previous run: 2026-03-20 10:00 UTC  (20260320-100000-abc12345)
  Risk score delta: +7 (worse)

  Regressions  (2 control(s) newly FAILED)
    ✗  WAF-COST-010  [HIGH]  PASS → FAIL  Cost Allocation Tagging Enforced
    ✗  WAF-SEC-020   [CRITICAL]  PASS → FAIL  Encryption at Rest

  Improvements  (1 control(s) left FAIL)
    ✓  WAF-COST-030  [MEDIUM]  FAIL → PASS  Budget Alerts Configured
────────────────────────────────────────────────────────────────────────────────
```

The same information appears as a dedicated **Run Change Tracking** page in PDF reports.

### State CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir PATH` | `.wafpass-state` | Directory for versioned state files |
| `--no-state` | off | Disable state saving and change tracking |

```bash
# Use a custom state directory (e.g. shared across teams via a mounted volume)
wafpass check ./infra/ --state-dir /var/wafpass-state

# Disable state tracking (useful for one-off ad-hoc runs)
wafpass check ./infra/ --no-state
```

---

## Monitoring & observability export plugins

WAF++ PASS ships a monitoring export plugin system that pushes run snapshots to external observability platforms after every check. This feeds dashboards, alerts, and time-series trend analysis without requiring a separate CI job.

### Quick start

```bash
# Push to Grafana via Prometheus Pushgateway
wafpass check ./infra/ --export grafana

# Push to multiple targets in one run
wafpass check ./infra/ --export grafana,slack,webhook
```

### Export config file

Create `.wafpass-export.yml` in your working directory (auto-discovered) or pass `--export-config`:

```yaml
# .wafpass-export.yml
exports:

  # ── Grafana via Prometheus Pushgateway (fully implemented) ─────────────────
  grafana:
    pushgateway_url: "http://pushgateway.monitoring.svc:9091"
    job: "wafpass"                    # Pushgateway job label (default: wafpass)
    instance: "my-project"            # Pushgateway instance label (default: run_id)
    # username: "12345"               # optional Basic Auth (Grafana Cloud proxy)
    # password: "${GRAFANA_CLOUD_TOKEN}"

  # ── Prometheus Pushgateway — standalone (stub, delegates to grafana plugin) ──
  prometheus:
    pushgateway_url: "http://pushgateway:9091"
    job: "wafpass"

  # ── Datadog Metrics API v2 (stub) ─────────────────────────────────────────
  datadog:
    api_key: "${DD_API_KEY}"
    site: "datadoghq.eu"              # or datadoghq.com

  # ── Splunk HTTP Event Collector (stub) ────────────────────────────────────
  splunk:
    hec_url: "https://splunk.example.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "main"

  # ── Slack incoming webhook (stub) ─────────────────────────────────────────
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    only_on_regression: true          # only post when new FAILs appear

  # ── Generic HTTP webhook (fully implemented) ──────────────────────────────
  webhook:
    url: "https://my-webhook.example.com/wafpass"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
    include_full_snapshot: true       # false = lightweight summary only
```

Secret values may use `${ENV_VAR}` placeholders — they are expanded from the environment at runtime and never stored in state files.

### Available export plugins

| Plugin | `--export` name | Status | Description |
|--------|----------------|--------|-------------|
| Grafana (Pushgateway) | `grafana` | **Implemented** | Prometheus text format → Pushgateway |
| Prometheus Pushgateway | `prometheus` | Stub (delegates to grafana) | Direct Pushgateway without Grafana branding |
| Datadog | `datadog` | **Stub** | Datadog Metrics API v2 |
| Splunk | `splunk` | **Stub** | Splunk HTTP Event Collector |
| Slack | `slack` | **Stub** | Slack incoming webhook with Block Kit |
| Generic webhook | `webhook` | **Implemented** | POST JSON snapshot to any HTTP endpoint |

### Grafana setup

#### Ready-to-import dashboard

A pre-built Grafana dashboard is included at **`assets/grafana-dashboard.json`**.

Import it via **Dashboards → Import → Upload JSON file** in the Grafana UI. Select your Prometheus datasource when prompted.

The dashboard includes:
- WAF++ logo in the header
- Risk score gauge + PASS/FAIL/SKIP/WAIVED stat panels
- Score delta, regressions, and improvements for the latest run
- Risk score and control status trend lines over time
- Per-pillar risk scores (horizontal bar gauge)
- Score delta and regression/improvement trend lines
- Full per-control status table (filterable, colour-coded by status and severity)
- Check-level pass/fail/skip trends

Dashboard variables: **Data Source**, **IaC Plugin** (multi-select), **Source Path** (multi-select).

#### Self-hosted Grafana + Prometheus + Pushgateway

1. Deploy a [Prometheus Pushgateway](https://github.com/prometheus/pushgateway)
2. Configure Prometheus to scrape it
3. In Grafana, add Prometheus as a data source
4. Import `assets/grafana-dashboard.json` (see above)

**Metrics reference**

| Metric | Type | Description |
|--------|------|-------------|
| `wafpass_score` | gauge | Overall risk score (0 = fully compliant, 100 = all critical controls failing) |
| `wafpass_controls_total{status}` | gauge | Control count by `pass`, `fail`, `skip`, `waived` |
| `wafpass_checks_total{status}` | gauge | Individual check count by status |
| `wafpass_pillar_score{pillar}` | gauge | Risk score per WAF++ pillar |
| `wafpass_control_status{control_id,severity,pillar}` | gauge | Per-control: 0=PASS 1=FAIL 2=SKIP 3=WAIVED |
| `wafpass_score_delta` | gauge | Score change vs previous run (+ve = worse) |
| `wafpass_regressions_total` | gauge | Controls newly entering FAIL this run |
| `wafpass_improvements_total` | gauge | Controls leaving FAIL this run |
| `wafpass_run_timestamp_seconds` | gauge | Unix timestamp of this run |

All metrics carry labels: `iac_plugin`, `run_id`, `tool_version`, `source`.

**Example Grafana alert rule** — fire when any control regresses:
```promql
increase(wafpass_regressions_total[1h]) > 0
```

**Example Grafana alert rule** — fire when risk score exceeds threshold:
```promql
wafpass_score > 50
```

#### Grafana Cloud

Grafana Cloud's Prometheus endpoint requires binary remote_write format. The recommended approach:

1. Deploy **Grafana Alloy** or **Grafana Agent** in your environment
2. Configure it to scrape the Prometheus Pushgateway
3. Set up `remote_write` from the agent to your Grafana Cloud Prometheus endpoint
4. Point the `grafana` plugin at the local Pushgateway URL

### Writing a new export plugin

1. Create `wafpass/export/plugins/mytool.py`:

```python
from wafpass.export.base import ExportPlugin, ExportResult
from wafpass.export.registry import registry

class MyToolPlugin:
    name = "mytool"
    description = "Push WAF++ metrics to MyTool."

    def export(self, snapshot: dict, config: dict) -> ExportResult:
        url = config.get("url") or ""
        if not url:
            return ExportResult(success=False, message="mytool: 'url' is required.")
        try:
            # … send snapshot to MyTool …
            return ExportResult(success=True, message="OK")
        except Exception as exc:
            return ExportResult(success=False, message=str(exc))

registry.register(MyToolPlugin())
```

2. Add an import to `wafpass/export/plugins/__init__.py`:

```python
from wafpass.export.plugins import mytool  # noqa: F401
```

3. Add a config block to `.wafpass-export.yml`:

```yaml
exports:
  mytool:
    url: "https://mytool.example.com/ingest"
```

4. Run:

```bash
wafpass check ./infra/ --export mytool
```

The `snapshot` dict passed to `export()` is the complete run snapshot from `wafpass.state.build_run_snapshot()` — see the schema in the **Run versioning** section above.

### CI/CD with export

```yaml
# GitHub Actions: push metrics to Grafana on every PR and main branch run
- name: Run WAF++ PASS + push to Grafana
  env:
    GRAFANA_CLOUD_TOKEN: ${{ secrets.GRAFANA_CLOUD_TOKEN }}
  run: |
    pip install -e .
    wafpass check ./infra/ \
      --fail-on fail \
      --export grafana \
      --export-config .wafpass-export.yml \
      --output pdf \
      --pdf-out wafpass-report.pdf
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed |
| `1`  | Failures detected (or skips, depending on `--fail-on`) |
| `2`  | Errors (missing controls dir, unreadable IaC files, unknown plugin, etc.) |

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

Run state is saved to `.wafpass-state/` by default. Persist this directory between pipeline runs (via cache or an artifact) to get cross-run change tracking. Without persistence, each run starts fresh with no previous state to compare against.

**GitHub Actions — Terraform (multi-cloud) with state persistence:**

```yaml
- name: Restore WAF++ state cache
  uses: actions/cache@v4
  with:
    path: .wafpass-state
    key: wafpass-state-${{ github.ref }}
    restore-keys: wafpass-state-

- name: Run WAF++ PASS
  run: |
    pip install -e .
    wafpass check infra/aws infra/azure infra/gcp \
      --iac terraform \
      --fail-on fail \
      --output pdf \
      --pdf-out wafpass-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: wafpass-report
    path: wafpass-report.pdf
```

**GitHub Actions — AWS CDK:**

```yaml
- name: Synthesise CDK app
  run: npx cdk synth          # produces cdk.out/

- name: Run WAF++ PASS
  run: |
    pip install -e .
    wafpass check . --iac cdk --fail-on fail --output pdf --pdf-out wafpass-report.pdf

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: wafpass-report
    path: wafpass-report.pdf
```

**GitHub Actions — with Grafana export:**

```yaml
- name: Run WAF++ PASS + push metrics to Grafana
  env:
    GRAFANA_CLOUD_TOKEN: ${{ secrets.GRAFANA_CLOUD_TOKEN }}
  run: |
    pip install -e .
    wafpass check ./infra/ \
      --fail-on fail \
      --export grafana \
      --output pdf \
      --pdf-out wafpass-report.pdf
```

**GitLab CI — Terraform with state persistence:**

```yaml
wafpass:
  cache:
    key: wafpass-state-$CI_COMMIT_REF_SLUG
    paths:
      - .wafpass-state/
  script:
    - pip install -e .
    - wafpass check infra/aws infra/azure --fail-on fail --summary
  artifacts:
    paths:
      - wafpass-report.pdf
```

**GitLab CI — CDK:**

```yaml
wafpass-cdk:
  script:
    - npx cdk synth
    - pip install -e .
    - wafpass check . --iac cdk --fail-on fail --summary
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
