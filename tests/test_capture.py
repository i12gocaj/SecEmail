"""Tests del capture server: /lure, /pixel, /capture, /click.

Levanta el servidor en un puerto efímero y hace HTTP real contra localhost
para verificar tanto las respuestas como la escritura del JSONL.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from secemail.capture import CaptureConfig, CaptureState, build_server
from secemail.tracking import Tracker


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def capture_env(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "index.html").write_text(
        "<html><body>Hello {{TARGET_EMAIL}} token={{TOKEN}} capture={{CAPTURE_URL}}"
        "<img src='{{PIXEL_URL}}'></body></html>",
        encoding="utf-8",
    )
    captures = tmp_path / "captures.jsonl"
    tracking = tmp_path / "tracking.jsonl"

    # Tracker isolation
    from secemail import tracking as tmod

    tmod.DEFAULT_TRACKING_PATH = tracking  # type: ignore[assignment]

    # Capture default storage isolation
    from secemail import capture as cap_mod

    cap_mod.DEFAULT_CAPTURE_PATH = captures  # type: ignore[assignment]

    cfg = CaptureConfig(
        templates_dir=templates,
        storage_path=captures,
        default_template="index.html",
    )
    port = _free_port()
    server = build_server("127.0.0.1", port, cfg)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"

    # Pre-existing token mapped to a victim
    tracker = Tracker(storage_path=tracking)
    token = tracker.tokenize_for(
        "victim@example.com",
        capture_base_url=base,
        notes={"session_id": "test-session"},
    )

    try:
        yield {
            "base": base,
            "templates": templates,
            "captures": captures,
            "tracking": tracking,
            "token": token,
        }
    finally:
        server.shutdown()
        server.server_close()


def _http_get(url: str, follow_redirects: bool = True) -> urllib.request.addinfourl:
    if not follow_redirects:
        # urllib follows by default; use a non-following opener
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)
        return opener.open(url, timeout=5)
    return urllib.request.urlopen(url, timeout=5)


def _http_post(url: str, data: bytes, content_type: str) -> urllib.request.addinfourl:
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", content_type)
    return urllib.request.urlopen(req, timeout=5)


def test_lure_serves_template_with_target_substituted(capture_env):
    base = capture_env["base"]
    token = capture_env["token"]

    resp = _http_get(f"{base}/lure/{token}")
    body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert "victim@example.com" in body
    assert token in body
    # Capture URL apunta al server propio
    assert f"/capture/{token}" in body
    # Pixel URL embebido
    assert f"/pixel/{token}.png" in body

    # Evento lure_view en el JSONL
    captures_path = capture_env["captures"]
    events = [json.loads(l) for l in captures_path.read_text(encoding="utf-8").splitlines() if l]
    assert any(e["event"] == "lure_view" and e["token"] == token for e in events)


def test_pixel_returns_png_and_logs_open(capture_env):
    base = capture_env["base"]
    token = capture_env["token"]

    resp = _http_get(f"{base}/pixel/{token}.png")
    body = resp.read()
    assert resp.status == 200
    assert resp.headers.get("Content-Type") == "image/png"
    assert body.startswith(b"\x89PNG\r\n\x1a\n"), "magic bytes PNG"

    events = [
        json.loads(l)
        for l in capture_env["captures"].read_text(encoding="utf-8").splitlines()
        if l
    ]
    opens = [e for e in events if e["event"] == "open" and e["token"] == token]
    assert opens, "Falta evento open"
    assert opens[0]["target_email"] == "victim@example.com"


def test_capture_post_form_logs_submit(capture_env):
    base = capture_env["base"]
    token = capture_env["token"]

    form = urllib.parse.urlencode({"username": "alice", "password": "hunter2"}).encode("utf-8")
    resp = _http_post(
        f"{base}/capture/{token}",
        data=form,
        content_type="application/x-www-form-urlencoded",
    )
    assert resp.status == 200

    events = [
        json.loads(l)
        for l in capture_env["captures"].read_text(encoding="utf-8").splitlines()
        if l
    ]
    submits = [e for e in events if e["event"] == "submit" and e["token"] == token]
    assert submits, "Falta evento submit"
    body = submits[0]["body"]
    assert body.get("username") == "alice"
    assert body.get("password") == "hunter2"


def test_capture_post_json_logs_submit(capture_env):
    base = capture_env["base"]
    token = capture_env["token"]

    payload = json.dumps({"email": "victim@example.com", "otp": "123456"}).encode("utf-8")
    resp = _http_post(
        f"{base}/capture/{token}",
        data=payload,
        content_type="application/json",
    )
    assert resp.status == 200

    events = [
        json.loads(l)
        for l in capture_env["captures"].read_text(encoding="utf-8").splitlines()
        if l
    ]
    submits = [e for e in events if e["event"] == "submit" and e["token"] == token]
    assert submits[-1]["body"]["otp"] == "123456"


def test_click_logs_event_and_redirects(capture_env):
    base = capture_env["base"]
    token = capture_env["token"]

    target = "https://example.com/landing"
    url = f"{base}/click/{token}?" + urllib.parse.urlencode({"url": target})

    # Sin seguir redirect
    try:
        _http_get(url, follow_redirects=False)
    except urllib.error.HTTPError as exc:
        assert exc.code == 302
        assert exc.headers.get("Location") == target

    events = [
        json.loads(l)
        for l in capture_env["captures"].read_text(encoding="utf-8").splitlines()
        if l
    ]
    clicks = [e for e in events if e["event"] == "click" and e["token"] == token]
    assert clicks
    assert clicks[0]["body"]["requested_url"] == target


def test_unknown_token_path_returns_404(capture_env):
    base = capture_env["base"]
    try:
        _http_get(f"{base}/nope/zzz")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


# ---------------------------------------------------------------------------
# Regresión P0: hardening del capture server.
# ---------------------------------------------------------------------------


def test_capture_invalid_content_length_returns_400(capture_env):
    """P0-1: Content-Length no numérico debe devolver 400, no crashear el thread."""
    base = capture_env["base"]
    token = capture_env["token"]

    parsed = urllib.parse.urlparse(f"{base}/capture/{token}")
    conn_class = (
        __import__("http.client", fromlist=["HTTPConnection"]).HTTPConnection
    )
    conn = conn_class(parsed.hostname, parsed.port, timeout=5)
    conn.putrequest("POST", parsed.path)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "abc")  # malformado
    conn.endheaders()
    response = conn.getresponse()
    assert response.status == 400, f"Esperado 400, recibido {response.status}"


def test_capture_chunked_returns_411(capture_env):
    """P0-1: Transfer-Encoding chunked → 411 (no soportado), no descarte silencioso."""
    base = capture_env["base"]
    token = capture_env["token"]

    parsed = urllib.parse.urlparse(f"{base}/capture/{token}")
    conn_class = (
        __import__("http.client", fromlist=["HTTPConnection"]).HTTPConnection
    )
    conn = conn_class(parsed.hostname, parsed.port, timeout=5)
    conn.putrequest("POST", parsed.path)
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    response = conn.getresponse()
    assert response.status == 411


def test_click_blocks_dangerous_schemes_even_without_allowlist(capture_env):
    """P0-3: aunque la allowlist esté vacía (default), nunca permitir
    javascript:/data:/file: schemes en /click/?url=."""
    base = capture_env["base"]
    token = capture_env["token"]

    for bad in ("javascript:alert(1)", "data:text/html,xss", "file:///etc/passwd"):
        url = f"{base}/click/{token}?" + urllib.parse.urlencode({"url": bad})
        try:
            _http_get(url, follow_redirects=False)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, f"esquema {bad!r} debió ser rechazado: status={exc.code}"
        else:
            pytest.fail(f"esquema {bad!r} no fue rechazado (debería ser 400)")
