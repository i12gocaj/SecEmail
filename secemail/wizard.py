"""Interactive wizard: SecEmail main menu.

Runs automatically when launching `secemail` with no args on a TTY. Also
reachable explicitly with `secemail wizard`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text
    _RICH = True
except ImportError:
    _RICH = False


def run_wizard() -> int:
    """Launch the wizard. Returns the exit code of the executed command.

    Any Ctrl+C at any prompt cancels cleanly without a traceback.
    """
    if not _RICH:
        print(
            "The wizard requires 'rich'. Install with: pip install rich",
            file=sys.stderr,
        )
        return 2

    console = Console()

    try:
        _print_intro(console)

        choice = Prompt.ask(
            "[bold]What do you want to do?[/bold]",
            choices=["1", "2", "3", "4", "5", "q"],
            default="1",
            show_choices=False,
        )

        if choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            return 0
        if choice == "1":
            return _flow_audit(console)
        if choice == "2":
            return _flow_spoof(console)
        if choice == "3":
            return _flow_campaign(console)
        if choice == "4":
            return _flow_capture(console)
        if choice == "5":
            return _flow_dashboard(console)
        return 0
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled by user.[/dim]")
        return 130


# ---------------------------------------------------------------------------
# Intro
# ---------------------------------------------------------------------------


def _print_intro(console: "Console") -> None:
    title = Text()
    title.append("Sec", style="bold magenta")
    title.append("Email", style="bold cyan")

    options = Table.grid(padding=(0, 3))
    options.add_column(justify="right", style="bold cyan", width=3)
    options.add_column(style="bold")
    options.add_column(style="dim")
    options.add_row("1", "Audit", "Analyze authentication of a domain or .eml")
    options.add_row("2", "Spoofing (1 target)", "Send one mail spoofing an authorized domain")
    options.add_row("3", "Campaign (CSV)", "Bulk send to a list of targets from a CSV file")
    options.add_row("4", "Capture", "Start the capture server for a campaign")
    options.add_row("5", "Dashboard", "Aggregate report of opens, clicks and submits")
    options.add_row("q", "Quit", "")

    console.print()
    console.print(Panel(
        options,
        title=title,
        subtitle="[dim]Email Authentication Auditor & Spoofing Toolkit[/dim]",
        border_style="cyan",
        padding=(1, 2),
    ))


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------


def _flow_audit(console: "Console") -> int:
    """Domain or .eml audit — autodetect."""
    target = Prompt.ask(
        "[bold]Domain or path to .eml[/bold] (e.g. company.com or ./mail.eml)"
    )
    full = Confirm.ask(
        "[dim]Full audit? (+ MTA-STS, TLS-RPT, DANE, BIMI; +2-3s)[/dim]",
        default=True,
    )

    argv: List[str] = []
    is_file = target.endswith(".eml") or Path(target).is_file()
    if is_file:
        argv.extend(["--file", target])
    else:
        argv.extend(["--email", target])
    if full:
        argv.append("--check-modern")

    _show_command(console, argv)
    return _execute(argv)


def _flow_spoof(console: "Console") -> int:
    """Single-target real spoofing send (assuming operator authorization)."""
    console.print()
    console.print(Panel(
        Text.assemble(
            ("This flow SENDS real mail to the recipient. ", "bold yellow"),
            ("Forensic log written to ~/.secemail/audit.jsonl. "
             "Contractual authorization is your responsibility.",
             ""),
        ),
        border_style="yellow",
        padding=(1, 2),
    ))

    target = Prompt.ask("[bold]Target email[/bold] (simulation victim)")
    spoof_from = Prompt.ask(
        "[bold]From to spoof[/bold] (e.g. ceo@client.com)"
    )

    # Campaign name suggestion (readable, not UUID).
    import time
    domain_hint = target.rsplit("@", 1)[-1] if "@" in target else "send"
    suggested_name = f"{domain_hint}-{time.strftime('%Y%m%d-%H%M', time.gmtime())}"
    campaign_name = Prompt.ask(
        "[bold]Campaign name[/bold] [dim](groups sends in the dashboard)[/dim]",
        default=suggested_name,
    )

    name = Prompt.ask("[dim]Display name (optional)[/dim]", default="")
    subject = Prompt.ask("[bold]Subject[/bold]", default="Action required")
    html = Prompt.ask(
        "[dim]HTML template (optional; e.g. phishing_templates/mfa_authenticator_approval.html)[/dim]",
        default="",
    )

    track = Confirm.ask(
        "[dim]Enable tracking (pixel/click/submit with capture server)?[/dim]",
        default=False,
    )
    capture_url = ""
    if track:
        capture_url = Prompt.ask(
            "[bold]Public URL of the capture server[/bold] (https://...)"
        )

    # Optional allowlist (defensive, non-blocking). Offered but not required.
    use_allowlist = Confirm.ask(
        "[dim]Validate defensive domain allowlist? (recommended to catch typos)[/dim]",
        default=True,
    )
    domains: List[str] = []
    if use_allowlist:
        domains_str = Prompt.ask(
            "[bold]Domains (comma-separated; e.g. client.com,hotmail.com)[/bold]"
        )
        domains = [x.strip() for x in domains_str.split(",") if x.strip()]

    argv: List[str] = [
        "--spoof-test", target,
        "--spoof-from", spoof_from,
        "--spoof-subject", subject,
        "--campaign-name", campaign_name,
    ]
    if name:
        argv.extend(["--spoof-name", name])
    if html and Path(html).is_file():
        argv.extend(["--html", html])
    for d in domains:
        argv.extend(["--authorize-domain", d])
    if track and capture_url:
        argv.extend(["--track", "--capture-url", capture_url])

    _show_command(console, argv)
    if not Confirm.ask("[bold yellow]Launch NOW?[/bold yellow]", default=False):
        console.print("[dim]Cancelled. The command is shown above.[/dim]")
        return 0
    return _execute(argv)


def _flow_campaign(console: "Console") -> int:
    """Multi-target campaign from a CSV file."""
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Multi-target campaign mode. ", "bold"),
            ("All sends share the same campaign name and appear grouped "
             "in the dashboard. Forensic log per send.",
             ""),
        ),
        border_style="cyan",
        padding=(1, 2),
    ))

    csv_path = Prompt.ask(
        "[bold]CSV file with targets[/bold] [dim](column 'email' required)[/dim]"
    )
    if not Path(csv_path).is_file():
        console.print(f"[red]Error:[/red] file not found: {csv_path}")
        return 2

    spoof_from = Prompt.ask("[bold]From to spoof[/bold] (e.g. ceo@client.com)")

    import time
    from_domain = spoof_from.rsplit("@", 1)[-1] if "@" in spoof_from else "campaign"
    suggested_name = f"{from_domain}-{time.strftime('%Y%m%d-%H%M', time.gmtime())}"
    campaign_name = Prompt.ask(
        "[bold]Campaign name[/bold]",
        default=suggested_name,
    )

    name = Prompt.ask("[dim]Display name (optional)[/dim]", default="")
    subject = Prompt.ask("[bold]Subject[/bold]", default="Action required")
    html = Prompt.ask(
        "[dim]HTML template (optional)[/dim]",
        default="",
    )

    track = Confirm.ask(
        "[dim]Enable tracking (pixel/click/submit)?[/dim]",
        default=True,
    )
    capture_url = ""
    if track:
        capture_url = Prompt.ask("[bold]Capture server URL[/bold] (https://...)")

    max_rec = Prompt.ask("[dim]Max recipients[/dim]", default="50")
    rate = Prompt.ask("[dim]Rate per minute[/dim]", default="30")

    domains_str = Prompt.ask(
        "[bold]Authorized domains (comma-separated; recommended)[/bold]",
        default="",
    )
    domains = [x.strip() for x in domains_str.split(",") if x.strip()]

    argv: List[str] = [
        "--targets-file", csv_path,
        "--spoof-from", spoof_from,
        "--spoof-subject", subject,
        "--campaign-name", campaign_name,
        "--max-recipients", max_rec,
        "--rate-per-minute", rate,
    ]
    if name:
        argv.extend(["--spoof-name", name])
    if html and Path(html).is_file():
        argv.extend(["--html", html])
    for d in domains:
        argv.extend(["--authorize-domain", d])
    if track and capture_url:
        argv.extend(["--track", "--capture-url", capture_url])

    _show_command(console, argv)
    if not Confirm.ask("[bold yellow]Launch the campaign NOW?[/bold yellow]", default=False):
        console.print("[dim]Cancelled. The command is shown above.[/dim]")
        return 0
    return _execute(argv)


def _flow_capture(console: "Console") -> int:
    """Start the local capture server."""
    port_str = Prompt.ask("[bold]Port[/bold]", default="8443")
    bind = Prompt.ask(
        "[dim]Interface (127.0.0.1=local only; 0.0.0.0=exposed)[/dim]",
        default="127.0.0.1",
    )
    templates_dir = Prompt.ask(
        "[dim]Templates directory[/dim]",
        default="phishing_templates",
    )
    default_template = Prompt.ask(
        "[dim]Default landing[/dim]",
        default="landing_portal_corporativo.html",
    )

    argv = [
        "capture",
        "--bind", bind,
        "--port", port_str,
        "--templates-dir", templates_dir,
        "--default-template", default_template,
    ]
    _show_command(console, argv)
    console.print("[dim]Server stays in the foreground; Ctrl+C to stop.[/dim]")
    return _execute(argv)


def _flow_dashboard(console: "Console") -> int:
    """Campaign dashboard — list available campaigns and pick one."""
    from .tracking import list_sessions, render_sessions_list

    try:
        rows = list_sessions()
    except Exception:
        rows = []

    session_id = ""
    if rows:
        console.print()
        console.print(render_sessions_list(rows))
        console.print()
        choice = Prompt.ask(
            "[bold]Select campaign by number (or Enter for all)[/bold]",
            default="",
        )
        if choice.strip().isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(rows):
                session_id = str(rows[idx]["session_id"])
                if session_id == "(no-session)":
                    session_id = ""  # no filter
    else:
        console.print(
            "[dim]No campaigns found in ~/.secemail/. "
            "The dashboard will render the empty state.[/dim]"
        )

    as_json = Confirm.ask("[dim]JSON output?[/dim]", default=False)

    argv = ["report"]
    if session_id:
        argv.extend(["--session-id", session_id])
    if as_json:
        argv.append("--json")

    _show_command(console, argv)
    return _execute(argv)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _show_command(console: "Console", argv: List[str]) -> None:
    cmd = "secemail " + " ".join(_quote(a) for a in argv)
    console.print()
    console.print(Panel(
        f"[bold green]$[/bold green] {cmd}",
        title="[bold]Equivalent command[/bold]",
        border_style="green",
        padding=(0, 2),
    ))
    console.print()


def _quote(s: str) -> str:
    if any(c in s for c in " \"'\\$"):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _execute(argv: List[str]) -> int:
    from .cli import main as classic_main
    return classic_main(argv)
