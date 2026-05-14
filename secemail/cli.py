"""CLI entry point: argument parsing, input loading, and orchestration.

Commands:
- (default) SPF/DKIM/DMARC/ARC audit + single-target SMTP simulation.
- ``capture`` starts the HTTP capture server.
- ``report`` builds the campaign dashboard from the persisted JSONL files.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .checks import audit_domain, audit_email
from .dns import DnsResolver, DnsResolverError
from .models import SCHEMA_VERSION
from .parsing import get_email_address
from .spoof import (
    DEFAULT_MAX_RECIPIENTS,
    DEFAULT_RATE_PER_MINUTE,
    render_spoof_result,
    run_spoof_campaign,
    run_spoof_test,
)
from .tracking import (
    DEFAULT_TRACKING_PATH,
    Tracker,
    build_campaign_report,
    render_campaign_report,
)
from .ui import Spinner, UIStyle, render_text


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


_EPILOG = """\
═══════════════════════════════════════════════════════════════════════
 SIMPLIFIED SYNTAX (recommended)
═══════════════════════════════════════════════════════════════════════

  secemail wizard                         # Step-by-step interactive mode

  secemail audit company.com              # Quick domain audit
  secemail audit company.com --full       # + MTA-STS/TLS-RPT/DANE/BIMI
  secemail audit ./mail.eml               # .eml audit (autodetect)
  secemail audit company.com --json       # JSON output for CI/SIEM

  secemail spoof employee@client.com --from ceo@client.com
                                          # Sends a real SMTP message
  secemail spoof employee@client.com --from ceo@client.com --auth client.com
                                          # Adds a defensive allowlist (warns
                                          # if target/from fall outside)
  secemail spoof employee@client.com --from ceo@client.com --auth client.com \\
       --campaign --capture-url https://lure.your-operator.tld
                                          # Campaign preset: track + forensic headers

  secemail serve --port 8443              # Capture server (alias of capture)
  secemail dash                           # Aggregate dashboard (alias of report)

═══════════════════════════════════════════════════════════════════════
 CLASSIC SYNTAX (compatible, still supported)
═══════════════════════════════════════════════════════════════════════

  secemail --email company.com [--check-modern] [--json]
  secemail --file mail.eml [--trusted-authserv-id mx.company.com]
  secemail --spoof-test ... --spoof-from ... --authorize-domain ...
  secemail capture --templates-dir phishing_templates/ --port 8443
  secemail report [--json] [--session-id <id>]

License and authorization: see /LICENSE in this repository.
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secemail",
        description="SecEmail - SPF/DKIM/DMARC/ARC auditor + authorized SMTP simulation",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument("--version", action="version", version=f"secemail {__version__}")

    sub = p.add_subparsers(dest="command", required=False)

    # ----- subcommand: capture ------------------------------------------
    cap = sub.add_parser(
        "capture",
        help="Start an HTTP capture server for Red Team campaigns.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    cap.add_argument("--bind", default="127.0.0.1", help="Listen interface (default 127.0.0.1).")
    cap.add_argument("--port", type=int, default=8443, help="Port (default 8443).")
    cap.add_argument(
        "--templates-dir",
        default="phishing_templates",
        help="Directory with HTML templates for /lure/.",
    )
    cap.add_argument(
        "--default-template",
        default="index.html",
        help="Default template name when no specific <token>.html exists.",
    )
    cap.add_argument(
        "--storage-path",
        default=None,
        help="Path of the captures JSONL (overrides ~/.secemail/captures.jsonl).",
    )

    # ----- subcommand: report -------------------------------------------
    rep = sub.add_parser(
        "report",
        help="Aggregate report of captures/tracking for a session_id.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    rep.add_argument("--session-id", default=None, help="Session-id to filter (default: all).")
    rep.add_argument(
        "--tracking-path",
        default=str(DEFAULT_TRACKING_PATH),
        help="Path of the tracking JSONL.",
    )
    rep.add_argument(
        "--captures-path",
        default=None,
        help="Path of the captures JSONL (default: ~/.secemail/captures.jsonl).",
    )
    rep.add_argument("--json", action="store_true", help="JSON output.")
    rep.add_argument("--no-color", action="store_true", help="Disable colors (plain output).")
    rep.add_argument(
        "--list",
        action="store_true",
        help="List available campaigns (sessions) and exit, without rendering the dashboard.",
    )

    # ----- default mode (no explicit subcommand) -------------------------
    group = p.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="Path to the .eml file with raw mail headers.")
    group.add_argument("-e", "--email", help="Domain or email address to audit at the DNS level.")

    p.add_argument("--dkim-selector", action="append", default=[], help="Specific DKIM selector to validate (e.g. 'default', 'google').")
    p.add_argument("--trusted-authserv-id", action="append", default=[], help="Trusted Authserv-ID for Authentication-Results (repeatable).")
    p.add_argument("--trust-auth-results", action="store_true", help="Trust every Authentication-Results header.")
    p.add_argument("--source-ip", help="Observed source IP to evaluate SPF locally.")
    p.add_argument("--mail-from", help="Observed MAIL FROM for local SPF.")
    p.add_argument("--helo", help="Observed HELO/EHLO for local SPF.")
    p.add_argument("--expect-arc", action="store_true", help="Treat the absence of ARC as WARN in forwarding flows.")
    p.add_argument("--enumerate-dkim", action="store_true", help="Enumerate common DKIM selectors (noisy, ~30 lookups). Result in metadata.dkim_selectors_found.")
    p.add_argument("--check-modern", action="store_true", help="Enable modern checks: MTA-STS, TLS-RPT, DANE, BIMI.")

    # Spoofing module
    spoof_group = p.add_argument_group("Spoofing module (Pentesting)")
    spoof_group.add_argument(
        "-c", "--campaign-name",
        metavar="NAME",
        help=(
            "Human-readable campaign name (used as session_id). "
            "All sends sharing this name appear grouped in the dashboard. "
            "If omitted, a readable default is generated."
        ),
    )
    spoof_group.add_argument("--spoof-test", metavar="TARGET_EMAIL", help="Run a Spoofing test against the given email.")
    spoof_group.add_argument("--spoof-from", metavar="SPOOFED_SENDER", help="Email to forge in the visible 'From'.")
    spoof_group.add_argument("--spoof-name", metavar="SPOOFED_NAME", help="Display name to forge in the visible 'From'.")
    spoof_group.add_argument("--spoof-to", metavar="SPOOFED_RECIPIENT", help="Email to forge in the visible 'To'.")
    spoof_group.add_argument("--html", metavar="HTML_FILE", help="Path to a .html file to use as the body.")
    spoof_group.add_argument("--attach", metavar="FILE_PATH", help="Path to a file to attach (e.g. payload.pdf).")
    spoof_group.add_argument("--spoof-subject", default="Authorized test message", help="Subject of the simulation.")

    # Authorization: new shortcut + 3 legacy flags (deprecated, kept for compat).
    spoof_group.add_argument(
        "--authorize-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help=(
            "(Recommended shortcut) Authorize real sending for DOMAIN. "
            "Implies --send-spoof + --i-have-authorization + --authorized-domain. "
            "Repeatable. Registrable domains only (rejects TLDs and public suffixes)."
        ),
    )
    spoof_group.add_argument("--send-spoof", action="store_true", help="(Deprecated in v1.0) Actually send via SMTP. Prefer --authorize-domain.")
    spoof_group.add_argument("--i-have-authorization", action="store_true", help="(Deprecated in v1.0) Explicit authorization confirmation.")
    spoof_group.add_argument("--authorized-domain", action="append", default=[], help="(Deprecated in v1.0) Authorized domain (repeatable).")
    spoof_group.add_argument("--smtp-timeout", type=float, default=10.0, help="SMTP timeout (default=10s).")
    spoof_group.add_argument("--max-attachment-bytes", type=int, default=10 * 1024 * 1024, help="Maximum attachment size.")

    # New OPSEC flags
    spoof_group.add_argument(
        "--add-forensic-headers",
        action="store_true",
        help=(
            "Add X-SecEmail-Test/Session-Id/Operator headers to the message (default OFF). "
            "Useful for post-engagement verification; OFF by default so a SOC cannot whitelist the header "
            "and contaminate the measurement of real defenses."
        ),
    )
    spoof_group.add_argument(
        "--no-interactive",
        action="store_true",
        help=(
            "Skip the TTY 'SI ENVIAR' confirmation. Required when stdin is not a TTY (CI). "
            "Use with care: removes the last manual guardrail."
        ),
    )

    # Authenticated relay
    spoof_group.add_argument(
        "--relay-host",
        metavar="HOST",
        help=(
            "Authenticated SMTP relay host (instead of direct send to MX). "
            "E.g. smtp.mailgun.org, email-smtp.us-east-1.amazonaws.com, smtp.postmarkapp.com, smtp.sendgrid.net, "
            "sandbox.smtp.mailtrap.io. STARTTLS required."
        ),
    )
    spoof_group.add_argument("--relay-port", type=int, default=587, help="Relay port (default 587).")
    spoof_group.add_argument("--relay-user", help="Relay user.")
    spoof_group.add_argument(
        "--relay-pass",
        help="(NOT recommended for OPSEC) Relay password on argv. Prefer --relay-pass-env.",
    )
    spoof_group.add_argument(
        "--relay-pass-env",
        metavar="VAR",
        help="Name of the environment variable holding the relay password.",
    )

    # Tracking
    spoof_group.add_argument("--track", action="store_true", help="Enable URL and pixel tokenization for tracking.")
    spoof_group.add_argument(
        "--capture-url",
        metavar="URL",
        help="Public base URL of the capture server (e.g. https://lure.example). Required when --track is set.",
    )

    # Bulk campaign
    spoof_group.add_argument(
        "--targets-file",
        metavar="CSV",
        help="CSV with recipients ('email' column required; 'name','extra' optional).",
    )
    spoof_group.add_argument(
        "--max-recipients",
        type=int,
        default=DEFAULT_MAX_RECIPIENTS,
        help=f"Cap of recipients per run (default {DEFAULT_MAX_RECIPIENTS}).",
    )
    spoof_group.add_argument(
        "--rate-per-minute",
        type=int,
        default=DEFAULT_RATE_PER_MINUTE,
        help=f"Delay between sends to avoid looking like a mailbomb (default {DEFAULT_RATE_PER_MINUTE}/min).",
    )

    # Console / UI options
    ui_group = p.add_argument_group("Console options")
    ui_group.add_argument("--json", action="store_true", help="Print output strictly as JSON.")
    ui_group.add_argument("--no-color", action="store_true", help="Disable ANSI color codes.")
    ui_group.add_argument("--no-animate", action="store_true", help="Disable spinners.")
    ui_group.add_argument("--dns-timeout", type=float, default=4.0, help="DNS resolution timeout (default=4.0s).")
    return p


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return _build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def load_input(path: Optional[str]) -> bytes:
    # Explicit stdin: `--file -` (the only supported way to pipe a message).
    # Must come BEFORE the `if path:` branch — otherwise we try to open
    # the literal filename "-".
    if path == "-":
        if sys.stdin.isatty():
            raise ValueError("--file - requires stdin to be a pipe, not a TTY.")
        data = sys.stdin.buffer.read()
        if not data:
            raise ValueError("--file - read 0 bytes from stdin.")
        return data

    # Empty-string path (`--file ""`) is a user mistake, not a stdin request.
    if path is not None and not path.strip():
        raise ValueError(
            "--file cannot be empty. Pass a real path or `--file -` to read from stdin."
        )

    if path:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError as exc:
            raise ValueError(f"File does not exist: {path}") from exc
        except PermissionError as exc:
            raise ValueError(f"No permission to read: {path}") from exc
        except IsADirectoryError as exc:
            raise ValueError(f"Path is a directory, not a file: {path}") from exc
        except OSError as exc:
            raise ValueError(f"Could not read file {path}: {exc}") from exc

        if not data.strip():
            raise ValueError(f"File is empty: {path}")
        return data

    if sys.stdin.isatty():
        raise ValueError(
            "No input received. Use --file PATH, --email DOMAIN, or pipe via `--file -`.\n"
            "Example: cat mail.eml | secemail --file -"
        )

    data = sys.stdin.buffer.read()
    if not data:
        raise ValueError("No input received on stdin.")
    return data


def _load_targets_csv(path: str) -> List[str]:
    targets: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            header_consumed = False
            email_idx: Optional[int] = None
            for row in reader:
                if not row:
                    continue
                if not header_consumed:
                    header_consumed = True
                    lower = [c.strip().lower() for c in row]
                    if "email" in lower:
                        email_idx = lower.index("email")
                        continue
                    if "@" in row[0]:
                        targets.append(row[0].strip())
                        email_idx = 0
                        continue
                idx = email_idx if email_idx is not None else 0
                if idx >= len(row):
                    continue
                email = row[idx].strip()
                if email and "@" in email:
                    targets.append(email)
    except OSError as exc:
        raise ValueError(f"Could not read --targets-file {path}: {exc}") from exc
    if not targets:
        raise ValueError(f"--targets-file {path} contained no valid addresses.")
    return targets


def _resolve_campaign_name(args: argparse.Namespace) -> str:
    """Return the campaign name (used as session_id).

    If the operator didn't pass --campaign-name, generate a readable default
    based on the target domain + UTC timestamp, e.g. "client.com-20260513-1842".
    This keeps the dashboard human-friendly even when not explicitly named.
    """
    explicit = getattr(args, "campaign_name", None)
    if explicit and explicit.strip():
        return explicit.strip()

    import time
    stamp = time.strftime("%Y%m%d-%H%M", time.gmtime())

    # Try to derive a domain hint from common args.
    domain_hint = "send"
    target = getattr(args, "spoof_test", None) or ""
    spoof_from = getattr(args, "spoof_from", None) or ""
    targets_file = getattr(args, "targets_file", None) or ""
    if "@" in target:
        domain_hint = target.rsplit("@", 1)[1]
    elif "@" in spoof_from:
        domain_hint = spoof_from.rsplit("@", 1)[1]
    elif targets_file:
        domain_hint = "campaign-csv"
    return f"{domain_hint}-{stamp}"


def _resolve_authorization(args: argparse.Namespace) -> Tuple[bool, bool, List[str]]:
    """Authorization is assumed at the CLI level: when --spoof-test is set, send.

    The operator is responsible for holding contractual authorization. The
    --authorize-domain / --send-spoof / --i-have-authorization flags are kept
    for backward compatibility and still feed the defensive allowlist, but
    are not required for sending.

    Returns (send_spoof, i_have_authorization, authorized_domains).
    """

    domains = list(args.authorize_domain) + [
        d for d in (args.authorized_domain or []) if d not in args.authorize_domain
    ]
    # Send always True; allowlist is defensive, not blocking.
    send = True
    auth = True

    return send, auth, domains


def _resolve_relay_pass(args: argparse.Namespace) -> Optional[str]:
    if args.relay_pass_env:
        val = os.environ.get(args.relay_pass_env)
        if val is None:
            raise ValueError(
                f"--relay-pass-env points to {args.relay_pass_env} but it is not defined."
            )
        return val
    return args.relay_pass


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def _emit_error(
    args: argparse.Namespace,
    message: str,
    code: str = "input_error",
    exit_code: int = 2,
) -> int:
    """Emit an error consistently.

    - In --json mode: a single ``{schema_version, error: {code, message}}``
      object to stdout, parseable by jq/SIEM. Nothing on stderr to keep
      combined-stream consumers clean.
    - In text mode: a single readable line on stderr.
    """
    if getattr(args, "json", False):
        payload = {
            "schema_version": SCHEMA_VERSION,
            "error": {"code": code, "message": message},
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Error: {message}", file=sys.stderr)
    return exit_code


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _run_capture(args: argparse.Namespace) -> int:
    from . import capture as cap_mod

    # Validate port before touching the socket (avoids raw traceback).
    if not (1 <= args.port <= 65535):
        return _emit_error(
            args,
            f"--port must be between 1 and 65535. Received: {args.port}.",
            code="invalid_port",
        )
    if args.templates_dir:
        td = Path(args.templates_dir)
        if not td.exists() or not td.is_dir():
            return _emit_error(
                args,
                f"--templates-dir does not exist or is not a directory: {args.templates_dir}",
                code="templates_dir_missing",
            )
    try:
        cap_mod.serve_forever(
            bind=args.bind,
            port=args.port,
            templates_dir=args.templates_dir,
            storage_path=args.storage_path,
            default_template=args.default_template,
        )
    except KeyboardInterrupt:
        print("\nCapture server stopped by user.", file=sys.stderr)
        return 130
    except OSError as exc:
        return _emit_error(args, f"capture server: {exc}", code="capture_socket_error")
    return 0


def _run_report(args: argparse.Namespace) -> int:
    captures = Path(args.captures_path) if args.captures_path else None
    tracking = Path(args.tracking_path) if args.tracking_path else None

    # `--list`: list available campaigns and exit.
    if getattr(args, "list", False):
        try:
            from .tracking import list_sessions, render_sessions_list
            rows = list_sessions(tracking_path=tracking, captures_path=captures)
        except (OSError, ValueError) as exc:
            return _emit_error(args, f"report --list: {exc}", code="report_error")
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(render_sessions_list(rows))
        return 0

    # If --session-id is not provided AND there are multiple distinct sessions,
    # show the list instead of mixing them all together with no context.
    if not args.session_id:
        try:
            from .tracking import list_sessions, render_sessions_list
            rows = list_sessions(tracking_path=tracking, captures_path=captures)
        except (OSError, ValueError):
            rows = []
        if len(rows) > 1 and not args.json:
            print(
                "Multiple campaigns are stored. "
                "Pass --session-id <ID> to filter, "
                "or --list to view them:\n",
                file=sys.stderr,
            )
            print(render_sessions_list(rows), file=sys.stderr)
            print(
                "\n(Continuing with all campaigns aggregated...)\n",
                file=sys.stderr,
            )

    try:
        report = build_campaign_report(
            tracking_path=tracking,
            captures_path=captures,
            session_id=args.session_id,
        )
    except (OSError, ValueError) as exc:
        return _emit_error(args, f"report: {exc}", code="report_error")
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        # Rich renderer on TTY; fallback to plain on pipes / --no-color.
        use_rich = (
            sys.stdout.isatty()
            and not getattr(args, "no_color", False)
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("SECEMAIL_PLAIN") is None
        )
        rendered = False
        if use_rich:
            try:
                from .tracking import render_campaign_report_rich
                render_campaign_report_rich(report)
                rendered = True
            except Exception:
                if os.environ.get("SECEMAIL_DEBUG"):
                    raise
                rendered = False
        if not rendered:
            print(render_campaign_report(report))
        # Discoverability: when the user explicitly filtered a session and
        # got nothing, hint where we looked. We skip this for the default
        # empty state because the rich panel already shows a "no data" panel
        # with the example command to launch a campaign.
        totals = report.get("totals") or {}
        if not totals.get("recipients") and args.session_id:
            tp = tracking or DEFAULT_TRACKING_PATH
            cp = captures or Path.home() / ".secemail" / "captures.jsonl"
            print(f"\n(Looking in: {tp} and {cp})", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Main flow (auditoría + spoof single-target + campaña)
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry-point with a top-level Ctrl+C handler for clean exit."""
    try:
        return _main_impl(argv)
    except KeyboardInterrupt:
        # Any Ctrl+C that escapes inner handlers ends here.
        # No traceback, brief message, exit code 130 (SIGINT standard).
        print("\n  Cancelled by user.", file=sys.stderr)
        return 130


def _main_impl(argv: Optional[Sequence[str]] = None) -> int:
    # ─── Default to wizard when no args and stdin is TTY ──────────────
    # If the user just types `secemail` in their terminal, launch the
    # interactive menu instead of the help. For CI/pipes (no-tty), keep
    # the classic behavior of showing help/reading stdin.
    effective_argv = argv if argv is not None else sys.argv[1:]
    if not effective_argv and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            from .wizard import run_wizard
            return run_wizard()
        except ImportError:
            # rich not installed → graceful fallback to classic help.
            print(
                "Notice: the 'rich' dependency is not installed; "
                "for the interactive menu run: pip install rich\n"
                "Showing classic help:\n",
                file=sys.stderr,
            )
            argv = ["--help"]

    # ─── Simplified subcommand layer ──────────────────────────────────
    # If the user invokes `secemail audit X`, `secemail spoof T --from F`,
    # `secemail wizard`, etc., the wrapper rewrites argv to the classic
    # format before parsing.
    from .cli_simple import maybe_rewrite_argv

    rewritten = maybe_rewrite_argv(argv)
    if rewritten is not None:
        # Sentinel for interactive wizard.
        if rewritten == ["__wizard__"]:
            from .wizard import run_wizard
            return run_wizard()
        argv = rewritten

    # ─── No subcommand + non-TTY stdin guard ──────────────────────────
    # Prevent `echo foo | secemail` from silently auditing stdin as a .eml.
    # The user must opt-in explicitly with `--file -` or `--file /dev/stdin`
    # if they want to pipe a message.
    if not effective_argv and not sys.stdin.isatty():
        print(
            "Error: no subcommand and no input. Use one of:\n"
            "  secemail audit company.com\n"
            "  secemail audit ./mail.eml\n"
            "  cat mail.eml | secemail --file -\n"
            "  secemail wizard",
            file=sys.stderr,
        )
        return 2

    args = parse_args(argv)

    if args.command == "capture":
        return _run_capture(args)
    if args.command == "report":
        return _run_report(args)

    color_enabled = (
        not args.json
        and not args.no_color
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )
    style = UIStyle(enabled=color_enabled)
    animate_enabled = (
        not args.json
        and not args.no_animate
        and sys.stderr.isatty()
    )

    send_spoof, i_have_auth, authorized_domains = _resolve_authorization(args)

    # Note: real sending is no longer opt-in via extra flags. Passing
    # --spoof-test or --targets-file == sending (assuming operator
    # authorization). The operational guardrails are TTY confirmation
    # and the forensic log, not declarative flags.

    # UX-3: --source-ip/--mail-from/--helo combos only apply with --file.
    # If set in --email mode, warn (they are silently ignored).
    spf_local_flags = [bool(args.source_ip), bool(args.mail_from), bool(args.helo)]
    if any(spf_local_flags) and args.email:
        print(
            "Notice: --source-ip/--mail-from/--helo only apply with --file; "
            "ignored when auditing a domain.",
            file=sys.stderr,
        )
    if any(spf_local_flags) and not all(spf_local_flags) and args.file:
        return _emit_error(
            args,
            "--source-ip, --mail-from and --helo are interdependent: pass all three or none.",
            code="incomplete_spf_local",
        )

    try:
        relay_pass = _resolve_relay_pass(args)
    except ValueError as exc:
        return _emit_error(args, str(exc), code="relay_pass_error")

    tracker = None
    if args.track:
        if not args.capture_url:
            return _emit_error(args, "--track requires --capture-url URL.", code="track_without_capture_url")
        tracker = Tracker()

    # -----------------------------------------------------------------
    # CAMPAIGN MODE (bulk send from CSV)
    # -----------------------------------------------------------------
    if args.targets_file:
        if not args.spoof_from:
            return _emit_error(
                args,
                "--targets-file requires --spoof-from to define the campaign From.",
                code="campaign_no_from",
            )
        try:
            targets = _load_targets_csv(args.targets_file)
        except ValueError as exc:
            return _emit_error(args, str(exc), code="targets_csv_invalid")

        spoof_domain = args.spoof_from.split("@")[-1].strip()
        if not spoof_domain:
            return _emit_error(
                args,
                "could not derive spoof domain; pass --spoof-from with a full email address.",
                code="campaign_invalid_spoof_from",
            )

        resolver = DnsResolver(timeout=args.dns_timeout)
        campaign_name = _resolve_campaign_name(args)
        try:
            campaign = run_spoof_campaign(
                targets,
                spoof_domain=spoof_domain,
                resolver=resolver,
                style=style,
                spoof_from=args.spoof_from,
                spoof_name=args.spoof_name,
                spoof_to=args.spoof_to,
                attach_path=args.attach,
                html_path=args.html,
                send_spoof=send_spoof,
                i_have_authorization=i_have_auth,
                authorized_domains=authorized_domains,
                spoof_subject=args.spoof_subject,
                smtp_timeout=args.smtp_timeout,
                max_attachment_bytes=args.max_attachment_bytes,
                quiet=True,
                add_forensic_headers=args.add_forensic_headers,
                no_interactive=args.no_interactive,
                relay_host=args.relay_host,
                relay_port=args.relay_port,
                relay_user=args.relay_user,
                relay_pass=relay_pass,
                track_capture_url=args.capture_url if args.track else None,
                tracker=tracker,
                max_recipients=args.max_recipients,
                rate_per_minute=args.rate_per_minute,
                session_id=campaign_name,
            )
        except ValueError as exc:
            return _emit_error(args, str(exc), code="campaign_failed")

        # Persistir reporte de campaña en disco.
        out_path = None
        try:
            out_dir = Path.home() / ".secemail"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"campaign_{campaign.session_id}.json"
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump(asdict(campaign), fh, indent=2, ensure_ascii=False)
        except OSError:
            out_path = None

        accepted = sum(
            1 for r in campaign.results if any(a.accepted for a in r.attempts)
        )
        if args.json:
            print(json.dumps(asdict(campaign), indent=2, ensure_ascii=False))
        else:
            print(style.title("📡 RED TEAM CAMPAIGN"))
            print(f"  session_id      : {campaign.session_id}")
            print(f"  targets         : {campaign.targets_total}")
            print(f"  processed       : {campaign.targets_processed}")
            print(f"  rate (msg/min)  : {campaign.rate_per_minute}")
            if campaign.aborted_reason:
                print(f"  ABORTED         : {campaign.aborted_reason}")
            else:
                print(f"  accepted (MX)   : {accepted}")
            if out_path:
                print(f"  report          : {out_path}")

        # P1-3: exit code reflects real outcome, not just aborted_reason.
        # - aborted (invalid allowlist, etc.) → 2 (input error)
        # - send=True and NO MX accepted → 1 (run failed)
        # - send=False (dry-run) or ≥1 accepted → 0
        if campaign.aborted_reason:
            return 2
        if send_spoof and campaign.targets_processed > 0 and accepted == 0:
            return 1
        return 0

    # -----------------------------------------------------------------
    # SMTP TEST MODE WITHOUT PRIOR AUDIT
    # -----------------------------------------------------------------
    if args.spoof_test and not args.email and not args.file:
        resolver = DnsResolver(timeout=args.dns_timeout)
        raw_spoof_from = getattr(args, "spoof_from", None)
        assumed_addr = get_email_address(raw_spoof_from) if raw_spoof_from else None
        assumed_spoof_domain = (assumed_addr or args.spoof_test).split("@")[-1].strip()
        try:
            spoof_result = run_spoof_test(
                target_email=args.spoof_test,
                spoof_domain=assumed_spoof_domain,
                resolver=resolver,
                style=style,
                spoof_from=raw_spoof_from,
                spoof_name=getattr(args, "spoof_name", None),
                spoof_to=getattr(args, "spoof_to", None),
                attach_path=getattr(args, "attach", None),
                html_path=getattr(args, "html", None),
                send_spoof=send_spoof,
                i_have_authorization=i_have_auth,
                authorized_domains=authorized_domains,
                spoof_subject=args.spoof_subject,
                smtp_timeout=args.smtp_timeout,
                max_attachment_bytes=args.max_attachment_bytes,
                quiet=args.json,
                add_forensic_headers=args.add_forensic_headers,
                no_interactive=args.no_interactive,
                relay_host=args.relay_host,
                relay_port=args.relay_port,
                relay_user=args.relay_user,
                relay_pass=relay_pass,
                track_capture_url=args.capture_url if args.track else None,
                tracker=tracker,
                session_id=_resolve_campaign_name(args),
            )
        except ValueError as exc:
            return _emit_error(args, str(exc), code="spoof_failed")
        if args.json:
            print(
                json.dumps(
                    {"schema_version": SCHEMA_VERSION, "spoof_test": asdict(spoof_result)},
                    indent=2,
                    ensure_ascii=False,
                )
            )
        spoof_failed = (
            spoof_result.mode == "send"
            and not any(a.accepted for a in spoof_result.attempts)
        )
        return 1 if spoof_failed else 0

    # -----------------------------------------------------------------
    # AUDIT MODE
    # -----------------------------------------------------------------
    # Reject obviously-empty --email up front, before the load_input fallback
    # turns it into a misleading "No input received on stdin" message.
    if args.email is not None and not args.email.strip():
        return _emit_error(
            args,
            "--email cannot be empty. Pass a domain (e.g. company.com) or an address "
            "(e.g. user@company.com).",
            code="empty_target",
        )
    try:
        with Spinner("Analyzing SPF/DKIM/DMARC/ARC configuration...", enabled=animate_enabled):
            domain_to_audit = args.email
            if domain_to_audit:
                report = audit_domain(
                    email_or_domain=domain_to_audit,
                    dkim_selectors=args.dkim_selector,
                    dns_timeout=args.dns_timeout,
                    check_modern=getattr(args, "check_modern", False),
                    enumerate_dkim=getattr(args, "enumerate_dkim", False),
                )
            else:
                raw = load_input(args.file)
                report = audit_email(
                    raw_email=raw,
                    dns_timeout=args.dns_timeout,
                    trusted_authserv_ids=args.trusted_authserv_id,
                    trust_all_auth_results=args.trust_auth_results,
                    source_ip=args.source_ip,
                    mail_from=args.mail_from,
                    helo=args.helo,
                    expect_arc=args.expect_arc,
                    check_modern=getattr(args, "check_modern", False),
                    enumerate_dkim=getattr(args, "enumerate_dkim", False),
                )
    except KeyboardInterrupt:
        print("Cancelled by user.", file=sys.stderr)
        return 130
    except (ValueError, DnsResolverError) as exc:
        return _emit_error(args, str(exc), code="audit_failed")
    except RuntimeError as exc:
        # publicsuffix2 missing and similar.
        return _emit_error(args, str(exc), code="dependency_missing")
    except Exception as exc:
        return _emit_error(args, f"Unexpected error: {exc}", code="unexpected", exit_code=2)

    spoof_domain_missing = False
    if args.spoof_test:
        spoof_domain = report.from_domain or report.envelope_from_domain or report.target
        if spoof_domain:
            spoof_resolver = DnsResolver(timeout=args.dns_timeout)
            try:
                report.spoof_test = run_spoof_test(
                    target_email=args.spoof_test,
                    spoof_domain=spoof_domain,
                    resolver=spoof_resolver,
                    style=style,
                    spoof_from=getattr(args, "spoof_from", None),
                    spoof_name=getattr(args, "spoof_name", None),
                    spoof_to=getattr(args, "spoof_to", None),
                    attach_path=getattr(args, "attach", None),
                    html_path=getattr(args, "html", None),
                    send_spoof=send_spoof,
                    i_have_authorization=i_have_auth,
                    authorized_domains=authorized_domains,
                    spoof_subject=args.spoof_subject,
                    smtp_timeout=args.smtp_timeout,
                    max_attachment_bytes=args.max_attachment_bytes,
                    quiet=True,
                    add_forensic_headers=args.add_forensic_headers,
                    no_interactive=args.no_interactive,
                    relay_host=args.relay_host,
                    relay_port=args.relay_port,
                    relay_user=args.relay_user,
                    relay_pass=relay_pass,
                    track_capture_url=args.capture_url if args.track else None,
                    tracker=tracker,
                    session_id=_resolve_campaign_name(args),
                )
            except ValueError as exc:
                return _emit_error(args, str(exc), code="spoof_failed")
        else:
            spoof_domain_missing = True

    if args.json:
        payload = {
            "schema_version": report.metadata.get("schema_version", SCHEMA_VERSION),
            "from_domain": report.from_domain,
            "return_path_domain": report.return_path_domain,
            "envelope_from_domain": report.envelope_from_domain,
            "input_mode": report.input_mode,
            "target": report.target,
            "dns_backend": report.dns_backend,
            "dns_errors": report.dns_errors,
            "metadata": report.metadata,
            "summary": report.summary,
            "checks": [asdict(c) for c in report.checks],
            "spoof_test": asdict(report.spoof_test) if report.spoof_test else None,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        # Rich renderer on TTY + no --no-color (better UX), fallback to plain.
        use_rich = (
            sys.stdout.isatty()
            and not args.no_color
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("SECEMAIL_PLAIN") is None
        )
        rendered = False
        if use_rich:
            try:
                from .ui_rich import render_report_rich
                render_report_rich(report)
                rendered = True
            except Exception:
                # If rich is missing or fails, fall back to the plain renderer.
                # Set SECEMAIL_DEBUG=1 to surface the underlying exception.
                if os.environ.get("SECEMAIL_DEBUG"):
                    raise
                rendered = False
        if not rendered:
            print(render_text(report, style=style))
            if report.spoof_test is not None:
                render_spoof_result(report.spoof_test, style)
        if spoof_domain_missing:
            print(
                f"  {style.color('[-] ERROR:', 'red')} "
                "Could not determine the spoof domain from the analyzed data."
            )

    fail_count = report.summary.get("FAIL", 0)
    spoof_failed = (
        report.spoof_test is not None
        and report.spoof_test.mode == "send"
        and not any(a.accepted for a in report.spoof_test.attempts)
    )
    return 1 if (fail_count > 0 or spoof_failed) else 0
