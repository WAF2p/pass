"""Secret detection scanner for WAF++ PASS.

Scans IaC source files for hardcoded credentials — passwords, API keys, tokens,
and private key material that should be managed via a dedicated secrets solution
(AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, SSM Parameter Store, …)
instead of being committed to source code.

Design principles
-----------------
- **Low false-positive first**: every pattern must match a *named sensitive key*
  (e.g. ``password``, ``api_key``) to avoid flagging arbitrary strings.  The
  only exception is well-known credential *formats* such as AWS AKIA access-key
  IDs and PEM private-key headers, which are flagged regardless of context.
- **Reference-aware**: values that are clearly IaC references (``var.*``,
  ``${...}``, ``data.*``, ``module.*``, Secrets Manager / Key Vault paths) are
  silently skipped.
- **Opt-out per line**: add ``# wafpass:ignore-secret`` (or the equivalent
  comment for JSON/YAML) to suppress a finding on that specific line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ── File types to scan ────────────────────────────────────────────────────────

_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".tf", ".tf.json",
    ".bicep",
    ".json",
    ".yaml", ".yml",
    ".py", ".ts", ".go", ".cs",
})

# ── Suppression marker ────────────────────────────────────────────────────────

_SUPPRESS_MARKER = "wafpass:ignore-secret"

# ── Safe-value patterns (skip if the value matches any of these) ──────────────

_SAFE_VALUE_RE: list[re.Pattern] = [
    re.compile(r"^\$\{"),                     # ${var.x}  or  ${data.x}
    re.compile(r"^var\."),                    # var.my_password
    re.compile(r"^local\."),                  # local.secret
    re.compile(r"^data\."),                   # data.aws_secretsmanager…
    re.compile(r"^module\."),                 # module.secrets.password
    re.compile(r"^aws_secretsmanager"),       # direct SM resource ref
    re.compile(r"(?i)secretsmanager"),        # contains "secretsmanager"
    re.compile(r"(?i)keyvault"),              # Azure Key Vault
    re.compile(r"(?i)vault"),                 # HashiCorp Vault
    re.compile(r"(?i)ssm[:/]"),              # SSM path notation
    re.compile(r"^\*+$"),                     # ****** (masked placeholder)
    re.compile(r"^<[^>]+>$"),                 # <REPLACE_ME>
    re.compile(r"^$"),                        # empty string
    # Common placeholder / test values (case-insensitive)
    re.compile(r"(?i)^(replace|your_|placeholder|changeme|todo|dummy|fake|mock|sample|n/?a|not.?set|none|null|undefined|example|test|demo)"),
]

# ── Secret patterns ───────────────────────────────────────────────────────────
# Each entry: (label, severity, regex)
# Regex must capture (key, value) — key is the attribute name, value is the
# literal string. For format-based patterns (no key) use a single capture group.

_NAMED_KEY_FIELDS = (
    r"password|passwd|pwd|db_pass(?:word)?|admin_pass(?:word)?|"
    r"root_pass(?:word)?|master_pass(?:word)?|user_pass(?:word)?"
)
_NAMED_SECRET_FIELDS = (
    r"secret|client_secret|app_secret|master_secret|"
    r"consumer_secret|shared_secret"
)
_NAMED_API_FIELDS = (
    r"api_key|apikey|api_secret|app_key|application_key|"
    r"subscription_key|service_key"
)
_NAMED_TOKEN_FIELDS = (
    r"token|auth_token|access_token|bearer_token|oauth_token|"
    r"refresh_token|id_token|jwt_token"
)
_NAMED_ACCESS_FIELDS = (
    r"access_key|access_key_id|aws_access_key_id"
)
_NAMED_SECRET_KEY_FIELDS = (
    r"secret_key|secret_access_key|aws_secret_access_key|"
    r"storage_access_key|account_key|storage_key"
)
_NAMED_PRIVATE_KEY_FIELDS = (
    r"private_key|rsa_private_key|ssh_private_key|ssl_key|"
    r"tls_private_key|signing_key"
)
_NAMED_CONN_FIELDS = (
    r"connection_string|conn_str|database_url|db_url|"
    r"connection_uri|jdbc_url|redis_url|mongo_url|postgres_url"
)


def _hcl(keys: str) -> re.Pattern:
    """HCL: ``key = "value"``  (Terraform / Bicep-like).

    Matches bare keywords (``password``) and compound underscore-delimited
    names that *end* in the keyword (``db_password``, ``SLACK_BOT_TOKEN``).
    ``(?<![a-zA-Z0-9])`` is used instead of ``\\b`` so that ``_TOKEN`` is
    treated as a word boundary (``_`` is ``\\w`` so ``\\b`` won't fire there).
    """
    return re.compile(
        rf'(?i)(?<![a-zA-Z0-9])(\w*(?:{keys}))\s*=\s*"([^"{{}}]{{4,}})"',
        re.MULTILINE,
    )


def _json_kv(keys: str) -> re.Pattern:
    """JSON: ``"key": "value"`` — also matches compound keys like ``SLACK_BOT_TOKEN``."""
    return re.compile(
        rf'(?i)"(\w*(?:{keys}))"\s*:\s*"([^"{{}}]{{4,}})"',
        re.MULTILINE,
    )


def _yaml_kv(keys: str) -> re.Pattern:
    """YAML: ``key: value`` (unquoted or quoted) — also matches compound keys."""
    return re.compile(
        rf'(?i)^[ \t]*(\w*(?:{keys}))\s*:\s*["\']?([^\'"#\n]{{4,}})["\']?',
        re.MULTILINE,
    )


_PATTERNS: list[tuple[str, str, list[re.Pattern]]] = [
    # label, severity, [patterns...]
    (
        "Hardcoded password",
        "critical",
        [_hcl(_NAMED_KEY_FIELDS), _json_kv(_NAMED_KEY_FIELDS), _yaml_kv(_NAMED_KEY_FIELDS)],
    ),
    (
        "Hardcoded secret",
        "high",
        [_hcl(_NAMED_SECRET_FIELDS), _json_kv(_NAMED_SECRET_FIELDS), _yaml_kv(_NAMED_SECRET_FIELDS)],
    ),
    (
        "Hardcoded API key",
        "high",
        [_hcl(_NAMED_API_FIELDS), _json_kv(_NAMED_API_FIELDS), _yaml_kv(_NAMED_API_FIELDS)],
    ),
    (
        "Hardcoded token",
        "high",
        [_hcl(_NAMED_TOKEN_FIELDS), _json_kv(_NAMED_TOKEN_FIELDS), _yaml_kv(_NAMED_TOKEN_FIELDS)],
    ),
    (
        "Hardcoded access key",
        "critical",
        [_hcl(_NAMED_ACCESS_FIELDS), _json_kv(_NAMED_ACCESS_FIELDS), _yaml_kv(_NAMED_ACCESS_FIELDS)],
    ),
    (
        "Hardcoded secret key",
        "critical",
        [_hcl(_NAMED_SECRET_KEY_FIELDS), _json_kv(_NAMED_SECRET_KEY_FIELDS), _yaml_kv(_NAMED_SECRET_KEY_FIELDS)],
    ),
    (
        "Hardcoded private key",
        "critical",
        [_hcl(_NAMED_PRIVATE_KEY_FIELDS), _json_kv(_NAMED_PRIVATE_KEY_FIELDS), _yaml_kv(_NAMED_PRIVATE_KEY_FIELDS)],
    ),
    (
        "Hardcoded connection string",
        "high",
        [_hcl(_NAMED_CONN_FIELDS), _json_kv(_NAMED_CONN_FIELDS), _yaml_kv(_NAMED_CONN_FIELDS)],
    ),
]

# Format-based patterns — matched on the full line, single capture group (value)
_FORMAT_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "AWS access key ID",
        "critical",
        re.compile(r"\b(AKIA[A-Z0-9]{16})\b"),
    ),
    (
        "AWS secret access key (candidate)",
        "critical",
        # 40-char base64-like string after aws_secret_access_key keyword
        re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})["\']?'),
    ),
    (
        "PEM private key",
        "critical",
        re.compile(r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)"),
    ),
    (
        "Generic high-entropy bearer token",
        "high",
        re.compile(r'(?i)\bAuthorization\s*[=:]\s*["\']?Bearer\s+([A-Za-z0-9._\-]{20,})["\']?'),
    ),
]

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    """A single hardcoded-secret finding."""

    file: Path
    line_no: int                # 1-based
    pattern_name: str           # human-readable label
    severity: str               # critical | high | medium
    matched_key: str            # the attribute/variable name (empty for format patterns)
    raw_value: str              # the literal value that was matched
    suppressed: bool = False    # True if line has the ignore marker

    @property
    def masked_value(self) -> str:
        """Return a masked version of the value (first 4 chars + ***)."""
        v = self.raw_value.strip()
        if len(v) <= 4:
            return "****"
        return v[:4] + "*" * min(len(v) - 4, 8)

    @property
    def file_line(self) -> str:
        return f"{self.file}:{self.line_no}"


# ── Scanner ───────────────────────────────────────────────────────────────────

def _is_safe_value(value: str) -> bool:
    v = value.strip()
    for pat in _SAFE_VALUE_RE:
        if pat.search(v):
            return True
    return False


def _collect_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            if p.suffix in _SCAN_EXTENSIONS or "".join(p.suffixes) in _SCAN_EXTENSIONS:
                files.append(p)
        elif p.is_dir():
            for ext in _SCAN_EXTENSIONS:
                files.extend(p.rglob(f"*{ext}"))
    # Deduplicate
    seen: set[Path] = set()
    unique: list[Path] = []
    for f in files:
        r = f.resolve()
        if r not in seen:
            seen.add(r)
            unique.append(f)
    return sorted(unique)


def scan_secrets(paths: list[Path]) -> list[SecretFinding]:
    """Scan *paths* for hardcoded secrets and return all findings.

    Args:
        paths: List of files or directories to scan.

    Returns:
        List of :class:`SecretFinding` objects, sorted by file + line number.
        Suppressed findings are included (``finding.suppressed == True``) so
        callers can report suppression counts if desired.
    """
    findings: list[SecretFinding] = []
    files = _collect_files(paths)

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()

        # ── Named-key patterns (operate on full content for multiline, then resolve line) ─
        for label, severity, patterns in _PATTERNS:
            for pat in patterns:
                for m in pat.finditer(content):
                    key = m.group(1)
                    value = m.group(2).strip()
                    if _is_safe_value(value):
                        continue
                    # Find line number from match start
                    line_no = content.count("\n", 0, m.start()) + 1
                    raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
                    suppressed = _SUPPRESS_MARKER in raw_line
                    findings.append(SecretFinding(
                        file=fpath,
                        line_no=line_no,
                        pattern_name=label,
                        severity=severity,
                        matched_key=key,
                        raw_value=value,
                        suppressed=suppressed,
                    ))

        # ── Format-based patterns ─────────────────────────────────────────────
        for label, severity, pat in _FORMAT_PATTERNS:
            for m in pat.finditer(content):
                value = m.group(1).strip()
                if _is_safe_value(value):
                    continue
                line_no = content.count("\n", 0, m.start()) + 1
                raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
                suppressed = _SUPPRESS_MARKER in raw_line
                findings.append(SecretFinding(
                    file=fpath,
                    line_no=line_no,
                    pattern_name=label,
                    severity=severity,
                    matched_key="",
                    raw_value=value,
                    suppressed=suppressed,
                ))

    # Deduplicate (same file+line+pattern may be matched by multiple sub-patterns)
    seen_keys: set[tuple[str, int, str]] = set()
    unique: list[SecretFinding] = []
    for f in findings:
        k = (str(f.file), f.line_no, f.pattern_name)
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(f)

    unique.sort(key=lambda f: (str(f.file), f.line_no))
    return unique


# ── Remediation guidance ──────────────────────────────────────────────────────

REMEDIATION_GUIDANCE = """
Hardcoded secrets in IaC code are a critical security risk:
  • They are committed to version control and visible in git history forever.
  • They are often replicated across environments without rotation.
  • A single repository exposure leaks credentials to all systems.

Recommended remediation by cloud provider
──────────────────────────────────────────
  AWS      → data.aws_secretsmanager_secret_version.<name>.secret_string
             data.aws_ssm_parameter.<name>.value  (SSM Parameter Store)
  Azure    → azurerm_key_vault_secret / @Microsoft.KeyVault(...)
  GCP      → data.google_secret_manager_secret_version.<name>.secret_data
  Vault    → data.vault_generic_secret.<path>.data["<key>"]

Terraform best practice
────────────────────────
  1. Declare a variable (no default!):   variable "db_password" {}
  2. Pass it at runtime:                 TF_VAR_db_password=<value>  or  -var-file
  3. Or reference a managed secret:      password = data.aws_secretsmanager_secret_version.db.secret_string

Suppress a specific finding (use sparingly, add justification):
  resource "..." "..." {
    password = "..." # wafpass:ignore-secret  reason: value is non-sensitive placeholder
  }
""".strip()
