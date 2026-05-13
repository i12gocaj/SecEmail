"""Simplified subcommand layer that rewrites into the classic CLI.

Design: NO duplicated logic. Each modern subcommand (`audit`, `spoof`,
`serve`, `dash`, `wizard`) rewrites `argv` to the classic CLI format and
delegates to `cli.main()`. This keeps the 137 tests green and the old
flag matrix working.

Mapping:
    secemail audit X                  →  secemail --email|--file X
    secemail audit X --full           →  secemail ... --check-modern --enumerate-dkim
    secemail audit X --json           →  secemail ... --json
    secemail spoof TARGET --from F    →  secemail --spoof-test TARGET --spoof-from F
    secemail spoof T --from F --auth D→  ... --authorize-domain D
    secemail spoof T --from F --campaign --capture-url U
                                       →  ... --track --capture-url U --add-forensic-headers
    secemail serve                    →  secemail capture
    secemail dash                     →  secemail report
    secemail wizard                   →  interactive flow in wizard.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence


# Subcomandos simples reconocidos como PRIMER argumento posicional.
_SIMPLE_COMMANDS = {"audit", "spoof", "serve", "dash", "wizard"}


def maybe_rewrite_argv(argv: Optional[Sequence[str]]) -> Optional[List[str]]:
    """If `argv[0]` is a simple subcommand, return argv rewritten to the
    classic format. Otherwise return None (meaning: use argv as-is)."""
    if argv is None:
        argv = sys.argv[1:]
    args = list(argv)
    if not args:
        return None  # no args: classic behavior (shows help/stdin)

    cmd = args[0]
    if cmd not in _SIMPLE_COMMANDS:
        return None

    rest = args[1:]
    if cmd == "audit":
        return _rewrite_audit(rest)
    if cmd == "spoof":
        return _rewrite_spoof(rest)
    if cmd == "serve":
        return ["capture"] + rest
    if cmd == "dash":
        return ["report"] + rest
    if cmd == "wizard":
        return _rewrite_wizard(rest)
    return None  # unreachable


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def _rewrite_audit(rest: List[str]) -> List[str]:
    """`secemail audit TARGET [--full] [--json] [...flags]`

    Target autodetected:
      - Existing path → --file
      - Ends in .eml → --file
      - Otherwise → --email
    """
    if not rest:
        _exit_usage(
            "audit requires a TARGET (domain or path to .eml).\n"
            "  secemail audit company.com\n"
            "  secemail audit ./mail.eml\n"
            "  secemail audit company.com --full     # includes MTA-STS/TLS-RPT/DANE/BIMI"
        )

    target = rest[0]
    extra = rest[1:]
    out: List[str] = []

    is_file = target.endswith(".eml") or Path(target).is_file()
    out.extend(["--file", target] if is_file else ["--email", target])

    i = 0
    while i < len(extra):
        a = extra[i]
        if a == "--full":
            out.extend(["--check-modern", "--enumerate-dkim"])
        elif a == "--quick":
            # default is already "quick"; nothing explicit to do.
            pass
        elif a == "--no-color" or a == "--no-animate" or a == "--json":
            out.append(a)
        else:
            # Pass-through: any other classic flag is forwarded as-is
            # (e.g. --dkim-selector, --trusted-authserv-id, etc.).
            out.append(a)
        i += 1
    return out


# ---------------------------------------------------------------------------
# spoof
# ---------------------------------------------------------------------------


def _rewrite_spoof(rest: List[str]) -> List[str]:
    """`secemail spoof TARGET --from FROM [--auth DOM] [--campaign] [--capture-url URL]`

    Short aliases:
      --from     →  --spoof-from
      --name     →  --spoof-name
      --to       →  --spoof-to
      --subject  →  --spoof-subject
      --auth DOM →  --authorize-domain DOM (repeatable)
      --campaign →  --track + --add-forensic-headers (recommended for a real campaign)
    """
    if not rest or rest[0].startswith("-"):
        _exit_usage(
            "spoof requires a TARGET (recipient email).\n"
            "  secemail spoof employee@client.com --from ceo@client.com\n"
            "  secemail spoof employee@client.com --from ceo@client.com --auth client.com\n"
            "  secemail spoof employee@client.com --from ceo@client.com --auth client.com "
            "--campaign --capture-url https://lure.your-operator.tld"
        )

    target = rest[0]
    extra = rest[1:]
    out: List[str] = ["--spoof-test", target]

    i = 0
    campaign = False
    while i < len(extra):
        a = extra[i]
        if a in ("--from", "-F"):
            i += 1
            out.extend(["--spoof-from", extra[i]])
        elif a == "--name":
            i += 1
            out.extend(["--spoof-name", extra[i]])
        elif a == "--to":
            i += 1
            out.extend(["--spoof-to", extra[i]])
        elif a == "--subject":
            i += 1
            out.extend(["--spoof-subject", extra[i]])
        elif a == "--auth":
            i += 1
            out.extend(["--authorize-domain", extra[i]])
        elif a == "--campaign":
            campaign = True
        elif a in ("--html", "--attach", "--capture-url", "--relay-host",
                   "--relay-port", "--relay-user", "--relay-pass",
                   "--relay-pass-env", "--smtp-timeout", "--targets-file",
                   "--max-recipients", "--rate-per-minute"):
            # classic value flags
            i += 1
            out.extend([a, extra[i]])
        elif a in ("--track", "--add-forensic-headers", "--no-interactive",
                   "--send-spoof", "--i-have-authorization",
                   "--json", "--no-color", "--no-animate"):
            # classic boolean flags
            out.append(a)
        else:
            # any other flag is passed through
            out.append(a)
        i += 1

    if campaign:
        if "--track" not in out:
            out.append("--track")
        if "--add-forensic-headers" not in out:
            out.append("--add-forensic-headers")
    return out


# ---------------------------------------------------------------------------
# wizard (delega a wizard.py, no devuelve argv: ejecuta y exit)
# ---------------------------------------------------------------------------


def _rewrite_wizard(rest: List[str]) -> List[str]:
    """The wizard is not translated to argv: it has its own interactive flow.

    We pass a sentinel argv that main() will recognize and dispatch to the wizard.
    """
    return ["__wizard__"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _exit_usage(msg: str, code: int = 2) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)
