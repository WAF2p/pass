"""Rich-based console reporter for WAF++ PASS."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from wafpass import __version__
from wafpass.models import CheckResult, ControlResult, Report

console = Console()

SEVERITY_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

STATUS_ICONS = {
    "PASS":   ("✓", "green"),
    "FAIL":   ("✗", "red"),
    "SKIP":   ("─", "yellow"),
    "WAIVED": ("○", "blue"),
    "ERROR":  ("!", "bold red"),
}


def _severity_badge(severity: str) -> Text:
    color = SEVERITY_COLORS.get(severity.lower(), "white")
    return Text(f"[{severity.upper()}]", style=color)


def _status_text(status: str) -> Text:
    icon, color = STATUS_ICONS.get(status, ("?", "white"))
    return Text(f"{icon} {status}", style=color)


def _format_result_line(result: CheckResult, verbose: bool) -> list[tuple[Text, str, str]] | None:
    """Return a formatted row for a check result, or None if it should be hidden."""
    if not verbose and result.status == "PASS":
        return None

    icon, color = STATUS_ICONS.get(result.status, ("?", "white"))
    status_t = Text(f"{icon} {result.status}", style=color)
    resource_t = Text(result.resource, style="bold white")
    message_t = Text(result.message, style="dim")

    return status_t, resource_t, message_t


def print_report(report: Report, verbose: bool = False, diff: dict | None = None) -> None:
    """Print the full WAF++ PASS report to the console."""
    # Header panel
    header_lines = [
        f"[bold cyan]WAF++ PASS[/bold cyan]  [dim]v{__version__}[/dim]",
        f"[dim]Checking:[/dim] [white]{report.path}[/white]   "
        f"[dim]Controls loaded:[/dim] [white]{report.controls_loaded}[/white]",
    ]
    console.print(Panel("\n".join(header_lines), border_style="cyan", padding=(0, 2)))
    console.print()

    # Per-control sections
    for cr in report.results:
        _print_control_section(cr, verbose)

    # Summary
    _print_summary(report)

    # Change tracking (shown after summary when a previous run exists)
    if diff is not None:
        _print_diff(diff)


def _print_control_section(cr: ControlResult, verbose: bool) -> None:
    """Print a single control section."""
    control = cr.control
    severity_badge = _severity_badge(control.severity)

    # Control header rule
    title_text = Text()
    title_text.append(f" {control.id}", style="bold white")
    title_text.append(f"  {control.title}", style="white")
    title_text.append("  ")
    title_text.append_text(severity_badge)

    status_icon, status_color = STATUS_ICONS.get(cr.status, ("?", "white"))
    title_text.append(f"  {status_icon}", style=status_color)

    console.print(Rule(title_text, style="dim"))

    if cr.waived_reason is not None:
        console.print(
            f"  [blue]○ WAIVED[/blue]  [dim]{cr.waived_reason}[/dim]\n"
        )
        return

    if not cr.results:
        console.print("  [yellow]─ SKIP[/yellow]  No matching resources found.\n")
        return

    has_visible = False
    for result in cr.results:
        icon, color = STATUS_ICONS.get(result.status, ("?", "white"))

        if not verbose and result.status == "PASS":
            continue

        has_visible = True
        status_t = Text(f"  {icon} {result.status}", style=color)
        resource_t = Text(f"  {result.resource:<38}", style="bold white")
        message_t = Text(result.message, style="dim")

        line = Text()
        line.append_text(status_t)
        line.append("  ")
        line.append(f"{result.resource:<38}", style="bold white")
        line.append("  ")
        line.append_text(message_t)
        console.print(line)

        if result.status == "FAIL" and result.remediation:
            rem = result.remediation.strip().replace("\n", " ")
            # Truncate long remediations for readability
            if len(rem) > 120:
                rem = rem[:117] + "..."
            console.print(f"           [dim]→ {rem}[/dim]")

    # Count skipped non-automated (those that would have been in original YAML but not loaded)
    skip_count = sum(1 for r in cr.results if r.status == "SKIP")
    if skip_count > 0 and not verbose:
        console.print(
            f"  [yellow]─ SKIP[/yellow]  [dim]({skip_count} check(s) skipped)[/dim]"
        )
        has_visible = True

    if not has_visible and verbose is False:
        # All passed, show a brief summary
        pass_count = sum(1 for r in cr.results if r.status == "PASS")
        console.print(
            f"  [green]✓ PASS[/green]  [dim]All {pass_count} check(s) passed.[/dim]"
        )

    console.print()


def _print_summary(report: Report) -> None:
    """Print the summary section."""
    console.print(Rule(style="dim"))

    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold white", no_wrap=True)
    table.add_column(style="white", no_wrap=True)

    waived_part = f"   [blue]○ WAIVED: {report.total_waived}[/blue]" if report.total_waived else ""
    controls_summary = (
        f"Controls: {report.controls_run}   "
        f"[green]✓ PASS: {report.total_pass}[/green]   "
        f"[red]✗ FAIL: {report.total_fail}[/red]   "
        f"[yellow]─ SKIP: {report.total_skip}[/yellow]"
        f"{waived_part}"
    )
    checks_summary = (
        f"Checks:   {report.check_pass + report.check_fail + report.check_skip}   "
        f"[green]✓ PASS: {report.check_pass}[/green]   "
        f"[red]✗ FAIL: {report.check_fail}[/red]   "
        f"[yellow]─ SKIP: {report.check_skip}[/yellow]"
    )

    console.print(f"  [bold]Summary[/bold]   {controls_summary}")
    console.print(f"           {checks_summary}")
    console.print(Rule(style="dim"))

    if report.total_fail > 0:
        console.print("  [bold red]EXIT CODE: 1[/bold red]  [dim](failures detected)[/dim]")
    elif report.total_waived > 0:
        console.print(
            "  [bold green]EXIT CODE: 0[/bold green]  "
            f"[dim](all checks passed or waived — {report.total_waived} waived)[/dim]"
        )
    else:
        console.print("  [bold green]EXIT CODE: 0[/bold green]  [dim](all checks passed)[/dim]")

    console.print()


def _print_diff(diff: dict) -> None:
    """Print the 'Changes from Previous Run' section."""
    regressions = diff.get("regressions", [])
    improvements = diff.get("improvements", [])
    other_changes = diff.get("other_changes", [])
    score_delta = diff.get("score_delta", 0)
    prev_ts = diff.get("previous_generated_at", "")
    prev_id = diff.get("previous_run_id", "")

    total_changes = len(regressions) + len(improvements) + len(other_changes)

    # Section header
    console.print()
    console.print(Rule("[bold]Changes from Previous Run[/bold]", style="dim"))

    # Previous run metadata
    if prev_ts:
        # Format ISO timestamp for readability
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
            ts_display = dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            ts_display = prev_ts
        console.print(
            f"  [dim]Previous run:[/dim] [white]{ts_display}[/white]"
            + (f"  [dim]({prev_id})[/dim]" if prev_id else "")
        )

    # Score delta
    if score_delta > 0:
        delta_str = f"  [dim]Risk score delta:[/dim] [red]+{score_delta} (worse)[/red]"
    elif score_delta < 0:
        delta_str = f"  [dim]Risk score delta:[/dim] [green]{score_delta} (improved)[/green]"
    else:
        delta_str = f"  [dim]Risk score delta:[/dim] [dim]0 (no change)[/dim]"
    console.print(delta_str)

    if total_changes == 0:
        console.print("  [dim]No control status changes detected.[/dim]")
        console.print(Rule(style="dim"))
        return

    # Regressions
    if regressions:
        console.print()
        console.print(
            f"  [bold red]Regressions[/bold red]  [dim]({len(regressions)} control(s) newly FAILED)[/dim]"
        )
        for entry in regressions:
            sev = entry.get("severity", "")
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}.get(
                sev.lower(), "white"
            )
            from_s = entry.get("from", "?")
            cid = entry["control_id"]
            title = entry.get("title", "")
            console.print(
                f"    [red]✗[/red]  [bold white]{cid}[/bold white]"
                f"  [{sev_color}][{sev.upper()}][/{sev_color}]"
                f"  [dim]{from_s} →[/dim] [red]FAIL[/red]"
                f"  [dim]{title}[/dim]"
            )

    # Improvements
    if improvements:
        console.print()
        console.print(
            f"  [bold green]Improvements[/bold green]  [dim]({len(improvements)} control(s) left FAIL)[/dim]"
        )
        for entry in improvements:
            sev = entry.get("severity", "")
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}.get(
                sev.lower(), "white"
            )
            to_s = entry.get("to", "?")
            to_color = {"PASS": "green", "WAIVED": "blue", "SKIP": "yellow"}.get(to_s, "white")
            cid = entry["control_id"]
            title = entry.get("title", "")
            console.print(
                f"    [green]✓[/green]  [bold white]{cid}[/bold white]"
                f"  [{sev_color}][{sev.upper()}][/{sev_color}]"
                f"  [dim]FAIL →[/dim] [{to_color}]{to_s}[/{to_color}]"
                f"  [dim]{title}[/dim]"
            )

    # Other changes
    if other_changes:
        console.print()
        console.print(
            f"  [bold yellow]Other changes[/bold yellow]  [dim]({len(other_changes)} control(s))[/dim]"
        )
        for entry in other_changes:
            from_s = entry.get("from", "?")
            to_s = entry.get("to", "?")
            cid = entry["control_id"]
            title = entry.get("title", "")
            console.print(
                f"    [yellow]─[/yellow]  [bold white]{cid}[/bold white]"
                f"  [dim]{from_s} → {to_s}[/dim]"
                f"  [dim]{title}[/dim]"
            )

    console.print()
    console.print(Rule(style="dim"))


def print_summary_only(report: Report) -> None:
    """Print only the summary table (no per-control details)."""
    _print_summary(report)
