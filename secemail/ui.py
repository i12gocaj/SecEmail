"""Console styling, spinner, and plain-text report rendering."""

from __future__ import annotations

import sys
import threading
import time
from typing import List, Optional

from .models import AuditReport
from .parsing import unique_preserve_order


class UIStyle:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.colors = {
            "reset": "\033[0m",
            "bold": "\033[1m",
            "dim": "\033[2m",
            "green": "\033[32m",
            "yellow": "\033[33m",
            "red": "\033[31m",
            "cyan": "\033[36m",
            "magenta": "\033[35m",
            "bg_dark": "\033[40m",
        }

    def color(self, text: str, name: str) -> str:
        if not self.enabled:
            return text
        return f"{self.colors.get(name, '')}{text}{self.colors['reset']}"

    def status(self, status: str) -> str:
        if status == "INFO":
            return self.color(" [ i INFO ] ", "cyan")
        if status == "PASS":
            return self.color(" [ ✓ PASS ] ", "green")
        if status == "WARN":
            return self.color(" [ ⚠ WARN ] ", "yellow")
        return self.color(" [ ✗ FAIL ] ", "red")

    def heading(self, text: str) -> str:
        return self.color(text, "bold")

    def title(self, text: str) -> str:
        return self.color(f"\n{text}\n{'=' * len(text)}\n", "cyan")


class Spinner:
    FRAMES = "|/-\\"

    def __init__(self, message: str, enabled: bool):
        self.message = message
        self.enabled = enabled
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_width = 0

    def __enter__(self) -> "Spinner":
        if not self.enabled:
            return self
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.enabled:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.3)
        clear = " " * max(self._last_width, len(self.message) + 6)
        sys.stderr.write(f"\r{clear}\r")
        sys.stderr.flush()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            text = f"{self.message} {frame}"
            self._last_width = max(self._last_width, len(text))
            sys.stderr.write(f"\r{text}")
            sys.stderr.flush()
            i += 1
            time.sleep(0.09)


def collect_action_items(report: AuditReport) -> List[str]:
    actions: List[str] = []
    for check in report.checks:
        if check.status in {"PASS", "INFO"}:
            continue
        source = check.exact_fixes or check.recommendations
        for item in source:
            actions.append(f"{check.protocol}: {item}")
    return unique_preserve_order(actions)


def render_text(report: AuditReport, style: UIStyle) -> str:
    import shutil

    lines: List[str] = []

    # Banner responsive: suprimimos el ASCII art grande si el terminal es estrecho
    # o si stdout no es TTY (pipe a archivo, CI). Mantenemos el título compacto.
    cols = shutil.get_terminal_size((80, 24)).columns
    is_tty = sys.stdout.isatty()
    if cols >= 64 and is_tty:
        banner = f"""{style.color('''
    ███████╗███████╗ ██████╗███████╗███╗   ███╗ █████╗ ██╗██╗
    ██╔════╝██╔════╝██╔════╝██╔════╝████╗ ████║██╔══██╗██║██║
    ███████╗█████╗  ██║     █████╗  ██╔████╔██║███████║██║██║
    ╚════██║██╔══╝  ██║     ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║
    ███████║███████╗╚██████╗███████╗██║ ╚═╝ ██║██║  ██║██║███████╗
    ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝''', 'magenta')}
                 {style.color('Email Authentication Auditor & Spoofing Toolkit', 'dim')}
    """
        lines.append(banner)
    else:
        # Banner compacto para terminales estrechos / no-TTY / pipes.
        lines.append(
            style.color("SecEmail", "magenta")
            + " — "
            + style.color("Email Authentication Auditor & Spoofing Toolkit", "dim")
        )
        lines.append("")

    lines.append(style.title("⚙️  GENERAL INFORMATION"))
    lines.append(f"  🔹 {style.color('Analysis mode', 'dim')}    : {report.input_mode.upper()}")
    if report.target:
        lines.append(f"  🔹 {style.color('Target', 'dim')}           : {style.color(report.target, 'bold')}")
    lines.append(f"  🔹 {style.color('FROM domain', 'dim')}      : {report.from_domain or 'N/A'}")
    lines.append(f"  🔹 {style.color('Envelope-From domain', 'dim')} : {report.envelope_from_domain or 'N/A'}")

    if report.dns_errors:
        lines.append(style.color("\n  ⚠️  DNS warnings:", "yellow"))
        for err in report.dns_errors:
            lines.append(f"    - {err}")
    lines.append("")

    action_items = collect_action_items(report)
    if action_items:
        import textwrap
        lines.append(style.title("🚀 PRIORITY REMEDIATION ACTIONS"))
        for idx, action in enumerate(action_items[:10], start=1):
            # Wrap to fit in 80 cols. The indent uses 5 chars ("  N. ") so we
            # have 75 useful chars; continuation lines align to that column.
            wrapped = textwrap.fill(action, width=75)
            first_line, *rest = wrapped.split("\n")
            lines.append(f"  {style.color(str(idx)+'.', 'cyan')} {first_line}")
            for cont in rest:
                lines.append(f"     {cont}")
        lines.append("")

    lines.append(style.title("🛡️  AUDIT RESULTS (SPF/DKIM/DMARC/ARC)"))
    import textwrap as _tw
    def _wrap_item(text: str, lead_indent: int, cont_indent: int) -> str:
        # Wrap long item text into 78-col-friendly continuations.
        return _tw.fill(
            text,
            width=78,
            initial_indent=" " * lead_indent,
            subsequent_indent=" " * cont_indent,
        )

    for check in report.checks:
        lines.append(f"{style.status(check.status)} {style.color(check.protocol, 'bold')}")
        if check.evidence:
            lines.append(f"      Evidence: {check.evidence}")
        for d in check.details:
            lines.append(_wrap_item(f"• {d}", lead_indent=6, cont_indent=8))

        if check.missing or check.recommendations or check.exact_fixes or check.implications:
            lines.append("")
        if check.missing:
            lines.append(f"      {style.color('➤ Missing:', 'red')}")
            for item in check.missing:
                lines.append(_wrap_item(f"- {item}", lead_indent=8, cont_indent=10))
        if check.recommendations:
            lines.append(f"      {style.color('➤ Recommendation:', 'cyan')}")
            for rec in unique_preserve_order(check.recommendations):
                lines.append(_wrap_item(f"- {rec}", lead_indent=8, cont_indent=10))
        if check.exact_fixes:
            lines.append(f"      {style.color('➤ Technical fix (DNS):', 'green')}")
            for fix in unique_preserve_order(check.exact_fixes):
                lines.append(_wrap_item(f"- {fix}", lead_indent=8, cont_indent=10))
        if check.implications:
            lines.append(f"      {style.color('➤ Security risk:', 'magenta')}")
            for impact in unique_preserve_order(check.implications):
                lines.append(_wrap_item(f"- {impact}", lead_indent=8, cont_indent=10))

        # Human explanation, wrapped to fit within an 80-col terminal.
        # The icon "💡 In plain terms: " takes ~20 visible cols, so we wrap the
        # text body to width=60 and prepend the icon to the first line.
        from .explain import explain_check
        human = explain_check(check)
        if human:
            import textwrap
            body_lines = textwrap.wrap(human, width=54)
            if body_lines:
                lines.append(
                    f"      {style.color('💡 In plain terms:', 'bold')} {body_lines[0]}"
                )
                for cont in body_lines[1:]:
                    lines.append(f"         {cont}")

        lines.append("")

    summary = report.summary
    total = sum(summary.values())

    lines.append(style.title("📊 FINAL SUMMARY"))

    # Conteos por estado
    res = (
        f"  {style.color('✓ PASS', 'green')}: {summary.get('PASS', 0)}   "
        f"{style.color('! WARN', 'yellow')}: {summary.get('WARN', 0)}   "
        f"{style.color('✗ FAIL', 'red')}: {summary.get('FAIL', 0)}   "
        f"{style.color('i INFO', 'cyan')}: {summary.get('INFO', 0)}   "
        f"{style.color('TOTAL', 'bold')}: {total}"
    )
    lines.append(res)
    lines.append("")

    # Compact table of each check with its status
    lines.append(f"  {style.color('Detail by protocol:', 'dim')}")
    for check in report.checks:
        icon_color = {
            "PASS": ("✓", "green"),
            "WARN": ("!", "yellow"),
            "FAIL": ("✗", "red"),
            "INFO": ("i", "cyan"),
        }.get(check.status, ("?", "white"))
        icon, color = icon_color
        lines.append(
            f"    {style.color(icon, color)} "
            f"{check.protocol:<12} {style.color(check.status, color)}"
        )

    # Final human verdict
    from .explain import explain_summary
    lines.append("")
    import textwrap as _tw_v
    verdict = explain_summary(report)
    # Wrap to fit in 80-col terminals. Icon prefix `💡 Verdict: ` is ~12 chars
    # so the body wraps at width=64 and continuation lines align to the icon.
    body = _tw_v.wrap(verdict, width=64)
    if body:
        lines.append(f"  {style.color('💡 Verdict:', 'bold')} {body[0]}")
        for cont in body[1:]:
            lines.append(f"              {cont}")

    return "\n".join(lines)
