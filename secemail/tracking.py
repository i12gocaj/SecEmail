"""URL and template tokenization for campaign tracking.

This layer does NOT run a server; it only generates stable tokens (uuid4) per
target and rewrites placeholders (``{{LURE_URL}}``, ``{{PIXEL_URL}}``,
``{{CLICK_URL}}``, ``{{TARGET_EMAIL}}``, ``{{TOKEN}}``) toward an external
capture server.

The ``token -> target`` mapping is persisted to JSONL (append-only) for
later auditing and report consolidation.

Typical usage:

    tracker = Tracker(storage_path=Path("~/.secemail/tracking.jsonl").expanduser())
    token = tracker.tokenize_for("victim@example.com", capture_base="https://lure.example")
    personalized_html = tracker.tokenize_html(
        html_template,
        target_email="victim@example.com",
        capture_base_url="https://lure.example",
    )

``capture_base_url`` is expected to be the public host (Cloudflare Tunnel,
nginx, etc.) that points to the ``secemail.capture`` server or equivalent.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, urlencode, urlparse


DEFAULT_TRACKING_PATH = Path.home() / ".secemail" / "tracking.jsonl"


def _now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class TrackerEntry:
    token: str
    target_email: str
    created_utc: str
    capture_base_url: Optional[str] = None
    lure_url: Optional[str] = None
    notes: Dict[str, str] = field(default_factory=dict)


class Tracker:
    """Thread-safe tokenizer backed by an append-only JSONL file.

    In-memory state (mapping token -> entry) is rebuilt from the JSONL on
    demand when requested.
    """

    _LURE_RE = re.compile(r"\{\{\s*LURE_URL\s*\}\}")
    _PIXEL_RE = re.compile(r"\{\{\s*PIXEL_URL\s*\}\}")
    _CLICK_RE = re.compile(r"\{\{\s*CLICK_URL\s*\}\}")
    _TARGET_RE = re.compile(r"\{\{\s*TARGET_EMAIL\s*\}\}")
    _TOKEN_RE = re.compile(r"\{\{\s*TOKEN\s*\}\}")

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = Path(storage_path) if storage_path else DEFAULT_TRACKING_PATH
        self._lock = threading.Lock()
        _ensure_parent(self.storage_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def tokenize_for(
        self,
        target_email: str,
        capture_base_url: Optional[str] = None,
        lure_url: Optional[str] = None,
        notes: Optional[Dict[str, str]] = None,
    ) -> str:
        """Generate a new token for ``target_email`` and persist the mapping."""

        token = uuid.uuid4().hex
        entry = TrackerEntry(
            token=token,
            target_email=target_email,
            created_utc=_now_utc_iso(),
            capture_base_url=capture_base_url,
            lure_url=lure_url,
            notes=notes or {},
        )
        self._append_entry(entry)
        return token

    def tokenize_url(
        self,
        base_url: str,
        target_email: str,
        param_name: str = "t",
    ) -> str:
        """Return ``base_url?<param_name>=<token>`` and persist the mapping."""

        token = self.tokenize_for(target_email, lure_url=base_url)
        sep = "&" if urlparse(base_url).query else "?"
        return f"{base_url}{sep}{param_name}={quote(token)}"

    def tokenize_html(
        self,
        html: str,
        target_email: str,
        capture_base_url: str,
        lure_url: Optional[str] = None,
        token: Optional[str] = None,
    ) -> str:
        """Replace placeholders in ``html`` with tokenized URLs.

        If ``token`` is None, a new one is generated. If one is provided
        (for example, reusing the envelope's token), that one is used and
        NO new entry is recorded — the caller is assumed to have persisted it.
        """

        if token is None:
            token = self.tokenize_for(
                target_email,
                capture_base_url=capture_base_url,
                lure_url=lure_url,
            )

        base = capture_base_url.rstrip("/")
        pixel = f"{base}/pixel/{token}.png"

        if lure_url:
            click = f"{base}/click/{token}?{urlencode({'url': lure_url})}"
        else:
            click = f"{base}/lure/{token}"

        out = html
        out = self._LURE_RE.sub(click, out)
        out = self._CLICK_RE.sub(click, out)
        out = self._PIXEL_RE.sub(pixel, out)
        out = self._TARGET_RE.sub(target_email, out)
        out = self._TOKEN_RE.sub(token, out)
        return out

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def load_mapping(self) -> Dict[str, TrackerEntry]:
        """Rebuild the full mapping from the JSONL file."""

        out: Dict[str, TrackerEntry] = {}
        if not self.storage_path.exists():
            return out
        with self._lock, self.storage_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token = data.get("token")
                if not token:
                    continue
                out[token] = TrackerEntry(
                    token=token,
                    target_email=data.get("target_email", ""),
                    created_utc=data.get("created_utc", ""),
                    capture_base_url=data.get("capture_base_url"),
                    lure_url=data.get("lure_url"),
                    notes=data.get("notes") or {},
                )
        return out

    def lookup(self, token: str) -> Optional[TrackerEntry]:
        return self.load_mapping().get(token)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _append_entry(self, entry: TrackerEntry) -> None:
        payload = {
            "token": entry.token,
            "target_email": entry.target_email,
            "created_utc": entry.created_utc,
            "capture_base_url": entry.capture_base_url,
            "lure_url": entry.lure_url,
            "notes": entry.notes,
        }
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock, self.storage_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Reporting helpers (consume capture and tracking JSONL files)
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def list_sessions(
    tracking_path: Optional[Path] = None,
    captures_path: Optional[Path] = None,
) -> List[Dict[str, object]]:
    """List campaigns/sessions found in ``tracking.jsonl``.

    Returns one entry per ``session_id`` with recipient count, first/last
    event timestamps (from ``captures.jsonl``), and a label combining the
    session id with the dates so the user can pick one easily.
    """
    tracking_path = tracking_path or DEFAULT_TRACKING_PATH
    from .capture import DEFAULT_CAPTURE_PATH
    captures_path = captures_path or DEFAULT_CAPTURE_PATH

    tracker = Tracker(tracking_path)
    mapping = tracker.load_mapping()

    # Group by session_id (with "(no session)" bucket for legacy entries)
    sessions: Dict[str, Dict[str, object]] = {}
    for entry in mapping.values():
        sid = str(entry.notes.get("session_id") or "(no-session)")
        if sid not in sessions:
            sessions[sid] = {
                "session_id": sid,
                "recipients": 0,
                "tokens": set(),
                "first_token_created_utc": entry.created_utc,
                "last_token_created_utc": entry.created_utc,
                "first_event_utc": None,
                "last_event_utc": None,
                "events_total": 0,
            }
        sessions[sid]["recipients"] = int(sessions[sid]["recipients"]) + 1  # type: ignore[operator]
        sessions[sid]["tokens"].add(entry.token)  # type: ignore[union-attr]
        if entry.created_utc < str(sessions[sid]["first_token_created_utc"]):
            sessions[sid]["first_token_created_utc"] = entry.created_utc
        if entry.created_utc > str(sessions[sid]["last_token_created_utc"]):
            sessions[sid]["last_token_created_utc"] = entry.created_utc

    # Annotate with first/last event ts from captures.jsonl
    for event in _read_jsonl(captures_path):
        token = event.get("token")
        ts = event.get("ts_utc")
        if not token or not ts:
            continue
        for s in sessions.values():
            if token in s["tokens"]:  # type: ignore[operator]
                s["events_total"] = int(s["events_total"]) + 1  # type: ignore[operator]
                if s["first_event_utc"] is None or ts < str(s["first_event_utc"]):
                    s["first_event_utc"] = ts
                if s["last_event_utc"] is None or ts > str(s["last_event_utc"]):
                    s["last_event_utc"] = ts
                break

    # Drop tokens set from the output (not JSON-serialisable, internal use)
    rows: List[Dict[str, object]] = []
    for s in sessions.values():
        s.pop("tokens", None)
        rows.append(s)
    # Order by last_token_created_utc descending (most recent first)
    rows.sort(key=lambda r: str(r["last_token_created_utc"]), reverse=True)
    return rows


def render_sessions_list(rows: List[Dict[str, object]]) -> str:
    """Plain-text rendering of `list_sessions` output."""
    if not rows:
        return (
            "No campaigns found yet.\n"
            "Launch one with: secemail spoof victim@client.com --from ceo@client.com "
            "--track --capture-url https://lure.your-operator.tld"
        )
    lines = ["Available campaigns:", ""]
    lines.append(f"  {'#':>2}  {'Session ID':<34} {'Recipients':>10}  {'Last activity (UTC)':<22}")
    lines.append("  " + "-" * 75)
    for idx, r in enumerate(rows, 1):
        sid = str(r["session_id"])[:32]
        last = r["last_event_utc"] or r["last_token_created_utc"] or "—"
        lines.append(
            f"  {idx:>2}  {sid:<34} {int(r['recipients']):>10}  {str(last):<22}"  # type: ignore[arg-type]
        )
    lines.append("")
    lines.append("Filter a single campaign with:  secemail dash --session-id <ID>")
    return "\n".join(lines)


def build_campaign_report(
    tracking_path: Optional[Path] = None,
    captures_path: Optional[Path] = None,
    session_id: Optional[str] = None,
) -> Dict[str, object]:
    """Aggregate open/click/submit metrics by session_id.

    Report structure:

        {
          "session_id": "...",
          "totals": {
              "recipients": N,
              "opens": N,
              "clicks": N,
              "submits": N,
              "open_rate": "x.xx%",
              "click_rate": "x.xx%",
              "submit_rate": "x.xx%",
          },
          "per_target": [ {"email": "...", "opened": bool, "clicked": bool, "submitted": bool}, ... ],
        }
    """

    tracking_path = tracking_path or DEFAULT_TRACKING_PATH
    from .capture import DEFAULT_CAPTURE_PATH  # late import to avoid cycles

    captures_path = captures_path or DEFAULT_CAPTURE_PATH

    tracker = Tracker(tracking_path)
    mapping = tracker.load_mapping()

    # Optional filter by session_id (stored inside notes).
    if session_id:
        mapping = {
            t: e for t, e in mapping.items() if e.notes.get("session_id") == session_id
        }

    targets = {entry.token: entry.target_email for entry in mapping.values()}

    opens: Dict[str, bool] = {tok: False for tok in targets}
    clicks: Dict[str, bool] = {tok: False for tok in targets}
    submits: Dict[str, bool] = {tok: False for tok in targets}
    # Per-target timestamps (first open, first click, first submit)
    first_open: Dict[str, str] = {}
    first_click: Dict[str, str] = {}
    first_submit: Dict[str, str] = {}
    # Captured credentials (count of submits with password-like fields)
    submits_with_password: int = 0
    # Global campaign time window
    first_event_ts: Optional[str] = None
    last_event_ts: Optional[str] = None

    for event in _read_jsonl(captures_path):
        token = event.get("token")
        if token not in targets:
            continue
        op = event.get("event")
        ts = event.get("ts_utc")
        if ts:
            if first_event_ts is None or ts < first_event_ts:
                first_event_ts = ts
            if last_event_ts is None or ts > last_event_ts:
                last_event_ts = ts
        if op == "open":
            opens[token] = True
            if token not in first_open and ts:
                first_open[token] = ts
        elif op == "click":
            clicks[token] = True
            if token not in first_click and ts:
                first_click[token] = ts
        elif op == "submit":
            submits[token] = True
            if token not in first_submit and ts:
                first_submit[token] = ts
            # Detect credentials in the body (heuristic: common field names)
            body = event.get("body") or {}
            if isinstance(body, dict):
                keys = {k.lower() for k in body.keys()}
                if keys & {"password", "passwd", "pwd", "pass", "secret", "otp", "code", "token"}:
                    submits_with_password += 1

    total = len(targets)
    n_open = sum(1 for v in opens.values() if v)
    n_click = sum(1 for v in clicks.values() if v)
    n_submit = sum(1 for v in submits.values() if v)

    def pct(n: int) -> str:
        if total == 0:
            return "0.00%"
        return f"{(n / total) * 100:.2f}%"

    per_target = [
        {
            "token": tok,
            "email": email,
            "opened": opens[tok],
            "clicked": clicks[tok],
            "submitted": submits[tok],
            "first_open": first_open.get(tok),
            "first_click": first_click.get(tok),
            "first_submit": first_submit.get(tok),
        }
        for tok, email in sorted(targets.items(), key=lambda kv: kv[1])
    ]

    return {
        "session_id": session_id,
        "totals": {
            "recipients": total,
            "opens": n_open,
            "clicks": n_click,
            "submits": n_submit,
            "submits_with_credentials": submits_with_password,
            "open_rate": pct(n_open),
            "click_rate": pct(n_click),
            "submit_rate": pct(n_submit),
        },
        "timeline": {
            "first_event_utc": first_event_ts,
            "last_event_utc": last_event_ts,
        },
        "per_target": per_target,
    }


def render_campaign_report(report: Dict[str, object]) -> str:
    """Plain-text rendering of the campaign dashboard.

    For visual output via rich (panels, colors), use `render_campaign_report_rich`.
    """

    totals = report["totals"]  # type: ignore[index]
    per_target = report["per_target"]  # type: ignore[index]
    timeline = report.get("timeline") or {}
    session_id = report.get("session_id") or "(all)"
    creds = totals.get("submits_with_credentials", 0)  # type: ignore[union-attr]

    lines = []
    lines.append(f"📊 CAMPAIGN DASHBOARD  ·  session: {session_id}")
    lines.append("=" * 64)

    if totals["recipients"] == 0:  # type: ignore[index]
        lines.append("")
        lines.append("  (no data)")
        lines.append("")
        lines.append("  No recipients yet. Launch a campaign with:")
        lines.append("    secemail spoof victim@client.com --from ceo@client.com \\")
        lines.append("      --track --capture-url https://lure.your-operator.tld")
        lines.append("")
        return "\n".join(lines)

    # ── Metrics ──
    lines.append(f"  Recipients        : {totals['recipients']}")  # type: ignore[index]
    lines.append(f"  Opens             : {totals['opens']:3d} ({totals['open_rate']})")  # type: ignore[index]
    lines.append(f"  Clicks            : {totals['clicks']:3d} ({totals['click_rate']})")  # type: ignore[index]
    lines.append(f"  Submits           : {totals['submits']:3d} ({totals['submit_rate']})")  # type: ignore[index]
    if creds > 0:
        lines.append(f"  ⚠ With credentials: {creds}  (review captures.jsonl)")

    if timeline.get("first_event_utc"):
        lines.append("")
        lines.append(f"  First event       : {timeline['first_event_utc']} UTC")
        lines.append(f"  Last event        : {timeline['last_event_utc']} UTC")

    lines.append("")
    lines.append(f"  {'Recipient':<40s}  {'Open':<6s} {'Click':<6s} {'Submit':<7s}")
    lines.append("  " + "-" * 62)
    for row in per_target:  # type: ignore[union-attr]
        email = row["email"][:40]  # type: ignore[index]
        o = "  ✓  " if row["opened"] else "  ·  "  # type: ignore[index]
        c = "  ✓  " if row["clicked"] else "  ·  "  # type: ignore[index]
        s = "  ✓   " if row["submitted"] else "  ·   "  # type: ignore[index]
        lines.append(f"  {email:<40s}  {o} {c} {s}")

    # ── Human verdict ──
    from .explain import explain_campaign
    notes = explain_campaign(report)
    if notes:
        lines.append("")
        lines.append("  💡 Insights:")
        for note in notes:
            lines.append(f"     · {note}")

    return "\n".join(lines)


def render_campaign_report_rich(report: Dict[str, object]) -> None:
    """Visual rendering with rich. Prints directly to stdout."""
    try:
        from rich.box import ROUNDED, SIMPLE
        from rich.console import Console, Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        print(render_campaign_report(report))
        return

    from .explain import explain_campaign

    console = Console(highlight=False)
    totals = report["totals"]  # type: ignore[index]
    per_target = report["per_target"]  # type: ignore[index]
    timeline = report.get("timeline") or {}
    session_id = report.get("session_id") or "(all)"
    creds = totals.get("submits_with_credentials", 0)  # type: ignore[union-attr]
    recipients = totals.get("recipients", 0)  # type: ignore[union-attr]

    # Header
    title = Text()
    title.append("📊 ", style="bold")
    title.append("Campaign dashboard", style="bold cyan")
    title.append(f"  ·  session: {session_id}", style="dim")
    console.print()
    console.print(title)
    console.print()

    # ── "No data" case ───────────────────────────────────────────────────
    if recipients == 0:
        empty = Text()
        empty.append("No data yet.\n\n", style="bold yellow")
        empty.append("Launch a campaign to begin:\n", style="dim")
        empty.append(
            "  secemail spoof victim@client.com --from ceo@client.com \\\n"
            "    --track --capture-url https://lure.your-operator.tld\n",
            style="cyan",
        )
        console.print(Panel(empty, border_style="yellow", box=ROUNDED, padding=(1, 2)))
        return

    # ── Large counts ─────────────────────────────────────────────────────
    counts = Table.grid(padding=(0, 3))
    for _ in range(5):
        counts.add_column(justify="center")
    counts.add_row(
        f"[bold]{recipients}[/bold]\n[dim]RECIPIENTS[/dim]",
        f"[bold cyan]{totals['opens']}[/bold cyan]\n[dim]OPENED ({totals['open_rate']})[/dim]",  # type: ignore[index]
        f"[bold yellow]{totals['clicks']}[/bold yellow]\n[dim]CLICKS ({totals['click_rate']})[/dim]",  # type: ignore[index]
        f"[bold red]{totals['submits']}[/bold red]\n[dim]SUBMITS ({totals['submit_rate']})[/dim]",  # type: ignore[index]
        f"[bold magenta]{creds}[/bold magenta]\n[dim]CREDENTIALS[/dim]",
    )

    # Timeline if present (use Text.from_markup so dim style is applied)
    if timeline.get("first_event_utc"):
        timeline_widget = Text.from_markup(
            f"\n[dim]First event:[/dim] {timeline['first_event_utc']}    "
            f"[dim]Last:[/dim] {timeline['last_event_utc']}"
        )
    else:
        timeline_widget = Text("")

    border = "red" if totals["submits"] > 0 else ("yellow" if totals["clicks"] > 0 else "cyan")  # type: ignore[index]
    console.print(Panel(
        Group(counts, timeline_widget),
        title="[bold]Metrics[/bold]",
        border_style=border,
        box=ROUNDED,
        padding=(1, 2),
    ))

    # ── Per-target detail table ──────────────────────────────────────────
    table = Table(title="[bold]Per target detail[/bold]", title_style="bold", box=SIMPLE)
    table.add_column("Email", style="white")
    table.add_column("Open", justify="center")
    table.add_column("Click", justify="center")
    table.add_column("Submit", justify="center")
    table.add_column("First event (UTC)", style="dim")

    for row in per_target:  # type: ignore[union-attr]
        email = row["email"][:50]
        o = "[green]✓[/green]" if row["opened"] else "[dim]·[/dim]"
        c = "[yellow]✓[/yellow]" if row["clicked"] else "[dim]·[/dim]"
        s = "[red]✓[/red]" if row["submitted"] else "[dim]·[/dim]"
        first = row.get("first_open") or row.get("first_click") or row.get("first_submit") or "—"
        table.add_row(email, o, c, s, first)
    console.print(table)
    console.print()

    # ── Human insights panel ─────────────────────────────────────────────
    notes = explain_campaign(report)
    if notes:
        body = Text()
        for note in notes:
            body.append("• ", style="bold cyan")
            body.append(note)
            body.append("\n")
        console.print(Panel(
            body,
            title="[bold]💡 Insights[/bold]",
            border_style="cyan",
            box=ROUNDED,
            padding=(0, 1),
        ))


__all__ = [
    "Tracker",
    "TrackerEntry",
    "DEFAULT_TRACKING_PATH",
    "build_campaign_report",
    "render_campaign_report",
    "render_campaign_report_rich",
    "list_sessions",
    "render_sessions_list",
]
