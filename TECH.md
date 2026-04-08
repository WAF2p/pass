# wafpass-core — Technical Reference

This document covers internal architecture, design decisions, technical debt, and contribution guidance for `wafpass-core` (`pass/`). For user-facing documentation see `README.md`.

---

## Directory structure

```
pass/
├── wafpass/
│   ├── __init__.py          # Public API surface
│   ├── engine.py            # run_controls() — assertion evaluation loop
│   ├── models.py            # Core dataclasses (Control, Check, CheckResult, …)
│   ├── schema.py            # Pydantic models for wafpass-result.json contract
│   ├── loader.py            # load_controls() — YAML → Control objects
│   ├── control_schema.py    # Pydantic validation models for control authoring
│   ├── cli.py               # Typer CLI entry point
│   ├── reporter.py          # Rich terminal output
│   ├── pdf_reporter.py      # ReportLab PDF generation
│   ├── baseline.py          # Baseline comparison (change tracking)
│   ├── blast_radius.py      # Impact graph computation
│   ├── blast_renderer.py    # Impact graph rendering helpers
│   ├── carbon.py            # Carbon footprint estimation
│   ├── fixer.py             # Auto-remediation suggestions
│   ├── secret_scanner.py    # Hardcoded credential detection
│   ├── plan_parser.py       # Terraform plan JSON parsing
│   ├── state.py             # Terraform state file handling
│   ├── waivers.py           # Waiver file load and apply
│   ├── wizard.py            # Interactive control authoring CLI
│   ├── parser.py            # Legacy shim (backwards compat)
│   ├── iac/
│   │   ├── base.py          # Protocol: IaCBlock, IaCState, IaCPlugin
│   │   ├── registry.py      # PluginRegistry singleton
│   │   └── plugins/
│   │       ├── terraform.py # Terraform HCL parser (python-hcl2)
│   │       ├── cdk.py       # AWS CDK parser
│   │       ├── bicep.py     # Bicep/ARM parser
│   │       └── pulumi.py    # Pulumi YAML/JSON parser
│   └── export/              # Export formatters (JSON, CSV, …)
├── controls/                # 73 WAF++ control YAML files (WAF-*.yml)
├── tests/
└── pyproject.toml
```

---

## Architecture

### Data flow

```
CLI / library call
       │
       ▼
load_controls(controls_dir)          ← YAML → list[Control]
       │
       ▼
plugin.parse(path)                   ← HCL/CDK/Bicep → IaCState
       │
       ▼
run_controls(controls, state)        ← evaluate assertions
       │
       ▼
list[ControlResult]
       │
       ▼
WafpassResultSchema.model_dump_json() ← serialize to wafpass-result.json
```

### IaC plugin system

Plugins are registered as a module-level singleton (`registry` in `iac/registry.py`). Each plugin is a class implementing the `IaCPlugin` protocol:

```python
class IaCPlugin(Protocol):
    name: str                       # "terraform"
    file_extensions: list[str]      # [".tf"]
    def can_parse(path: Path) -> bool: ...
    def parse(path: Path) -> IaCState: ...
    def extract_regions(state: IaCState) -> list[tuple[str, str]]: ...
```

Plugins auto-register on import of `wafpass/__init__.py`. The registry is keyed by name, so `registry.get("terraform")` always returns the Terraform plugin.

**Adding a new plugin:** Create a class in `iac/plugins/`, implement the protocol, and call `registry.register(MyPlugin())` at module level. No changes needed elsewhere.

### Assertion evaluation (`engine.py`)

`run_controls()` performs a triple-nested loop:

```
for control in controls:
    for check in control.checks (automated only):
        find matching IaCBlocks by scope (block_type + resource_types)
        if no matching blocks → CheckResult(status=SKIP)
        for block in matching_blocks:
            evaluate all assertions against block.attributes
            if any assertion fails → FAIL, else PASS
```

Assertions support 22+ operators. The `op` field maps to a handler function in `engine.py`. Unknown operators yield `SKIP` rather than errors, which is intentional — it allows controls that use cross-resource operators (e.g. `has_associated_resource`) to degrade gracefully when the operator is not yet implemented.

**Attribute resolution** uses dot-path notation (`tags.cost-center`). The resolver walks nested dicts, with special handling for lists (any-match semantics for `in` operators).

### Result schema contract (`schema.py`)

`WafpassResultSchema` is the stable JSON contract between `wafpass-core`, `wafpass-server`, and any downstream tooling. The server's `RunCreate` schema mirrors it. The schema is versioned (`schema_version = "1.0"`).

**Design rule:** Never add required fields to `WafpassResultSchema` without a default — doing so is a breaking change for clients that POST stored results.

### Control YAML format

Each YAML file defines one control. The engine ignores any check where `automated: false`. The full format is documented in `README.md` under _Controls directory setup_.

Key YAML fields that affect engine behaviour:

| Field | Effect |
|-------|--------|
| `checks[].automated` | `false` → check is never run, only stored as metadata |
| `checks[].engine` | Used to filter checks when `engine_name` is passed to `run_controls()` |
| `checks[].scope.block_type` | Determines which `IaCState` attribute to search (`resources`, `providers`, etc.) |
| `checks[].scope.resource_types` | Filters blocks by `IaCBlock.type` |
| `assertions[].op` | Operator; unknown ops yield SKIP |
| `assertions[].fallback_attribute` | Used only with `attribute_exists_or_fallback` |

---

## Key design decisions

### Dataclasses over Pydantic for internal models

`Control`, `Check`, `CheckResult`, and `ControlResult` in `models.py` are plain Python `@dataclass` objects. This keeps the engine fast and dependency-light. Pydantic is used only at the boundary (`schema.py`) where JSON serialization is needed.

### Waivers applied after evaluation

`apply_waivers()` is called after `run_controls()` returns, not during evaluation. This is intentional: it means the raw check results (PASS/FAIL) are always present and can be audited. The waiver only changes the `ControlResult.waived_reason` field and the computed `status` property.

### SKIP semantics

A control emits `SKIP` if no matching IaC blocks are found (e.g. no `aws_s3_bucket` resources in the scanned code). This is distinct from `PASS` — it means "not applicable" rather than "compliant". The score denominator excludes `SKIP` controls.

### Scoring formula

```python
score = round(100 * check_pass / (check_pass + check_fail)) if (check_pass + check_fail) > 0 else 100
```

SKIP and WAIVED checks are excluded from both numerator and denominator. Pillar scores use the same formula applied per-pillar.

---

## Unsupported assertion operators (known technical debt)

Nine assertion operators are declared in control YAMLs but not implemented in `engine.py`. They silently return `SKIP`:

| Operator | Reason not implemented |
|----------|----------------------|
| `has_associated_metric_filter` | Requires cross-resource graph lookup |
| `references_cloudtrail_bucket` | Requires resource reference resolution |
| `region_in_arn_matches` | Requires ARN parsing + provider config |
| `in_variable` | Requires variable value resolution |
| `not_equals_with_sibling` | Requires sibling block lookup |
| `not_all_true_with` | Requires aggregation across block instances |
| `attribute_exists_on_all_providers` | Requires provider-level aggregation |
| `attribute_exists_if` | Conditional evaluation not yet wired |
| `json_not_contains_pattern` | Requires embedded JSON parsing |

**Impact:** Controls using these operators always show as SKIP rather than FAIL. For most controls this affects only some checks, so the control still evaluates correctly on other checks.

**Fix path:** Implement each operator in `engine.py` by adding a handler function to the `_OPERATORS` dict. Most need `IaCState` to be passed into the assertion context (currently only the current block's attributes are available).

---

## IaC plugin completeness

| Plugin | Status | Notes |
|--------|--------|-------|
| Terraform | Production | python-hcl2 parser, all scope types supported |
| CDK | Beta | JSON/TypeScript constructs, may miss complex patterns |
| Bicep | Stub | ARM template parsing, limited assertion coverage |
| Pulumi | Stub | YAML/JSON config, limited assertion coverage |

CDK, Bicep, and Pulumi plugins are functional but have significantly less assertion operator coverage than the Terraform plugin, because the 73 controls were primarily written and tested against Terraform.

---

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest -k "test_engine"          # filter by test name
pytest --tb=short                # shorter tracebacks
```

Tests live in `tests/`. Key test areas:
- `test_engine.py` — assertion operator coverage
- `test_loader.py` — YAML parsing edge cases
- `test_schema.py` — serialization roundtrip

**Known gap:** Integration tests that parse real Terraform against real controls are sparse. Most engine tests use synthetic `IaCState` objects constructed in-test.

---

## Adding a new control

1. Create `controls/WAF-XXX-NNN.yml` following the schema in `README.md`
2. Set `automated: true` on any checks the engine can evaluate
3. Run `wafpass check tests/fixtures/` to validate parsing
4. Validate schema: `python -c "from wafpass.loader import load_controls; from pathlib import Path; cs = load_controls(Path('controls')); print(len(cs), 'controls loaded')`

Controls with no `automated: true` checks are still returned by `load_controls()` and stored in `controls_meta` by the server, but they never generate findings.

---

## Release process

1. Bump `VERSION` file and `pyproject.toml` `version` field
2. Update `CHANGELOG.md`
3. `python -m build` → produces `dist/wafpass_core-X.Y.Z-py3-none-any.whl`
4. Upload to PyPI: `twine upload dist/*`
5. Tag the release in git

---

## Dependencies rationale

| Dependency | Why |
|------------|-----|
| `python-hcl2` | Only production-quality Python HCL parser |
| `pydantic>=2` | Fast schema validation + JSON serialization for the result contract |
| `pyyaml` | YAML control definitions |
| `typer` + `rich` | CLI framework + terminal formatting; typer wraps Click with type annotations |
| `reportlab` (optional) | PDF generation — optional so the core package stays lightweight |
| `fastapi` (optional) | Only needed for `wafpass ui` — pulls in uvicorn; optional extra `[web]` |
