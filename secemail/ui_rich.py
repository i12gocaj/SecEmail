"""Visual renderer using `rich`: panels, tables, clear hierarchy.

Replaces the plain-text renderer in `ui.py` when running on a TTY and the
user did not pass `--json`. The plain renderer is kept as a fallback to
ensure compatibility when rich is not available (should not happen — it is
a hard dependency).
"""

from __future__ import annotations

import sys
from typing import List

try:
    from rich.box import ROUNDED, SIMPLE
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

from .explain import explain_check, explain_spoof_outcome, explain_summary
from .models import AuditReport, CheckResult


_STATUS_STYLE = {
    "PASS": ("✓", "bold green"),
    "WARN": ("!", "bold yellow"),
    "FAIL": ("✗", "bold red"),
    "INFO": ("i", "bold cyan"),
}


def render_report_rich(report: AuditReport, console: "Console | None" = None) -> None:
    """Render an AuditReport with rich. Prints directly to stdout."""
    if not _RICH_AVAILABLE:
        raise RuntimeError("rich is not installed — use plain render_text instead.")
    if console is None:
        console = Console(highlight=False)

    # ─── Header ─────────────────────────────────────────────────────────
    title = Text()
    title.append("Sec", style="bold magenta")
    title.append("Email", style="bold cyan")
    title.append("  ·  ", style="dim")
    title.append("SPF / DKIM / DMARC / ARC Audit", style="dim white")
    console.print()
    console.print(title)
    console.print()

    # ─── Información general ────────────────────────────────────────────
    info = Table.grid(padding=(0, 2))
    info.add_column(justify="right", style="dim")
    info.add_column()
    info.add_row("Mode", f"[bold]{report.input_mode.upper()}[/bold]")
    if report.target:
        info.add_row("Target", f"[bold cyan]{report.target}[/bold cyan]")
    info.add_row("From domain", report.from_domain or "[dim]N/A[/dim]")
    info.add_row("Envelope-From", report.envelope_from_domain or "[dim]N/A[/dim]")
    if report.dns_backend:
        info.add_row("DNS backend", f"[dim]{report.dns_backend}[/dim]")
    console.print(Panel(info, title="[bold]Information[/bold]", border_style="cyan", box=ROUNDED, padding=(0, 1)))

    # ─── Resumen ejecutivo ──────────────────────────────────────────────
    summary = report.summary
    counts = Table.grid(padding=(0, 3))
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_row(
        f"[bold green]{summary.get('PASS', 0)}[/bold green]\n[dim]PASS[/dim]",
        f"[bold yellow]{summary.get('WARN', 0)}[/bold yellow]\n[dim]WARN[/dim]",
        f"[bold red]{summary.get('FAIL', 0)}[/bold red]\n[dim]FAIL[/dim]",
        f"[bold cyan]{summary.get('INFO', 0)}[/bold cyan]\n[dim]INFO[/dim]",
    )
    verdict = _verdict_text_for(report)
    console.print(Panel(
        Group(counts, Text(""), verdict),
        title="[bold]Summary[/bold]",
        border_style=_verdict_color(summary),
        box=ROUNDED,
        padding=(1, 2),
    ))

    # ─── Priority actions ───────────────────────────────────────────────
    actions = _collect_actions(report)
    if actions:
        t = Text()
        for i, a in enumerate(actions[:8], 1):
            t.append(f"  {i}. ", style="bold cyan")
            t.append(a)
            t.append("\n")
        console.print(Panel(t, title="[bold]Priority actions[/bold]", border_style="yellow", box=ROUNDED, padding=(0, 1)))

    # ─── Per-protocol results ───────────────────────────────────────────
    console.print()
    console.print("[bold]Detailed results[/bold]")
    console.print()
    for check in report.checks:
        console.print(_check_panel(check))
        console.print()

    # ─── Spoof test (si aplica) ─────────────────────────────────────────
    if report.spoof_test is not None:
        console.print(_spoof_panel(report.spoof_test))
        console.print()

    # ─── Resumen FINAL al pie (para no tener que volver arriba) ─────────
    _print_final_summary(console, report)


def _print_final_summary(console: "Console", report: AuditReport) -> None:
    """Summary panel at the end of the report, with large counts and a verdict."""
    summary = report.summary
    total = sum(summary.values())

    # Tabla compacta horizontal con counts por estado.
    counts = Table.grid(padding=(0, 2))
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_column(justify="center")
    counts.add_row(
        f"[bold green]{summary.get('PASS', 0)}[/bold green]\n[dim]PASS ✓[/dim]",
        f"[bold yellow]{summary.get('WARN', 0)}[/bold yellow]\n[dim]WARN !  [/dim]",
        f"[bold red]{summary.get('FAIL', 0)}[/bold red]\n[dim]FAIL ✗[/dim]",
        f"[bold cyan]{summary.get('INFO', 0)}[/bold cyan]\n[dim]INFO i[/dim]",
        f"[bold]{total}[/bold]\n[dim]TOTAL[/dim]",
    )

    # Lista de cada check con su veredicto, fácil de escanear.
    detail = Table.grid(padding=(0, 2))
    detail.add_column(justify="right")
    detail.add_column()
    for check in report.checks:
        icon, style = _STATUS_STYLE.get(check.status, ("?", "white"))
        detail.add_row(
            f"[{style}]{icon}[/{style}]",
            f"[bold]{check.protocol}[/bold]  [{style}]{check.status}[/{style}]",
        )

    verdict = _verdict_text_for(report)

    console.print(Panel(
        Group(counts, Text(""), detail, Text(""), verdict),
        title="[bold]📊 Final summary[/bold]",
        border_style=_verdict_color(summary),
        box=ROUNDED,
        padding=(1, 2),
    ))


def _verdict_text_for(report: AuditReport) -> Text:
    """Build a human verdict with a short, clear explanation."""
    summary = report.summary
    fail = summary.get("FAIL", 0)
    warn = summary.get("WARN", 0)

    if fail > 0:
        prefix = ("● FAIL ", "bold red")
    elif warn > 0:
        prefix = ("● WARN ", "bold yellow")
    else:
        prefix = ("● PASS ", "bold green")

    human = explain_summary(report)
    return Text.assemble(prefix, (human, "white"))


def _verdict_color(summary: dict) -> str:
    if summary.get("FAIL", 0) > 0:
        return "red"
    if summary.get("WARN", 0) > 0:
        return "yellow"
    return "green"


def _check_panel(check: CheckResult) -> Panel:
    icon, style = _STATUS_STYLE.get(check.status, ("?", "white"))
    title = Text.assemble(
        (f"  {icon}  ", style),
        (f"{check.protocol}", "bold"),
        ("    "),
        (check.status, style),
        (f"   evidence:{check.evidence}", "dim"),
    )

    body = Text()
    for d in check.details[:6]:  # cap to avoid flooding
        body.append("  • ", style="dim cyan")
        body.append(d)
        body.append("\n")

    if check.missing:
        body.append("\n  Missing:\n", style="bold yellow")
        for m in check.missing[:5]:
            body.append(f"    – {m}\n", style="yellow")

    if check.exact_fixes:
        body.append("\n  Technical fix (DNS/config):\n", style="bold green")
        for f in check.exact_fixes[:3]:
            body.append(f"    » {f}\n", style="green")

    if check.implications:
        body.append("\n  Risk:\n", style="bold red")
        for i in check.implications[:2]:
            body.append(f"    ⚠ {i}\n", style="red")

    if check.verified_domains:
        body.append("\n  Verified domains (DKIM): ", style="dim")
        body.append(", ".join(check.verified_domains), style="bold cyan")

    # ─── Human explanation ────────────────────────────────────────────
    human = explain_check(check)
    if human:
        body.append("\n\n  ", style="dim")
        body.append("💡 ", style="bold")
        body.append(human, style="italic")

    border = {"PASS": "green", "WARN": "yellow", "FAIL": "red", "INFO": "cyan"}.get(check.status, "white")
    return Panel(body, title=title, border_style=border, box=SIMPLE, padding=(0, 1))


def _spoof_panel(spoof) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="dim")
    grid.add_column()
    grid.add_row("Mode", spoof.mode)
    grid.add_row("Status", spoof.status)
    grid.add_row("Envelope-From", spoof.envelope_from)
    grid.add_row("Header-From", spoof.header_from)
    grid.add_row("Target", spoof.target_email)
    if getattr(spoof, "session_id", None):
        grid.add_row("Session-Id", f"[dim]{spoof.session_id}[/dim]")
    if spoof.mx_hosts:
        grid.add_row("MX", ", ".join(spoof.mx_hosts))

    from .explain import explain_smtp_attempt

    attempts_table = None
    if spoof.attempts:
        attempts_table = Table(title="SMTP attempts", title_style="bold", box=SIMPLE)
        attempts_table.add_column("MX")
        attempts_table.add_column("Pri")
        attempts_table.add_column("Status")
        attempts_table.add_column("Code")
        attempts_table.add_column("Detail")
        for a in spoof.attempts:
            status = "[green]accepted[/green]" if a.accepted else "[red]rejected[/red]"
            attempts_table.add_row(
                a.mx_host, str(a.preference), status,
                str(a.smtp_code or "—"), (a.message or "")[:80]
            )

    reasons = None
    if spoof.reasons:
        reasons = Text()
        for r in spoof.reasons:
            reasons.append("  • ", style="dim yellow")
            reasons.append(r)
            reasons.append("\n")

    parts: List = [grid]
    if reasons:
        parts.append(Text(""))
        parts.append(reasons)
    if attempts_table:
        parts.append(Text(""))
        parts.append(attempts_table)

    # ─── Human explanation of the outcome ────────────────────────────
    human = explain_spoof_outcome(spoof)
    if human:
        parts.append(Text(""))
        explain_text = Text()
        explain_text.append("💡 ", style="bold")
        explain_text.append(human, style="italic")
        parts.append(explain_text)

    border = "green" if any(a.accepted for a in spoof.attempts) else ("yellow" if spoof.mode == "dry-run" else "red")
    title = "[bold]🎭 SMTP Send[/bold]"
    return Panel(Group(*parts), title=title, border_style=border, box=ROUNDED, padding=(0, 1))


def _collect_actions(report: AuditReport) -> List[str]:
    """Priority actions derived from the checks (same criteria as ui.py)."""
    out: List[str] = []
    for check in report.checks:
        if check.status in {"WARN", "FAIL"}:
            for item in check.exact_fixes:
                line = f"{check.protocol}: {item}"
                if line not in out:
                    out.append(line)
    return out
