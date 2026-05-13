"""OPSEC tests for spoof.py: allowlist validation, audit log, rate limit,
TTY confirmation, forensic headers, and the --authorize-domain shortcut.
"""

from __future__ import annotations

import io
import json
import os
import smtplib
import sys
from pathlib import Path

import pytest

from secemail.spoof import (
    DEFAULT_RATE_PER_MINUTE,
    run_spoof_campaign,
    run_spoof_test,
    validate_authorized_domains,
)
from secemail.ui import UIStyle


class FakeResolver:
    backend = "fake"
    errors = []

    def __init__(self, mx_records=None):
        self.mx_records = mx_records or {}

    def txt(self, name):
        return []

    def cname(self, name):
        return []

    def mx(self, name):
        return self.mx_records.get(name.lower(), [])


@pytest.fixture(autouse=True)
def _isolate_audit(tmp_path, monkeypatch):
    """Cada test escribe en su propio JSONL para no pisar el del operador."""

    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("SECEMAIL_AUDIT_LOG", str(audit))
    yield audit


# ---------------------------------------------------------------------------
# A1: validación dura de allowlist
# ---------------------------------------------------------------------------


def test_allowlist_rejects_bare_tld_com():
    with pytest.raises(ValueError) as exc:
        validate_authorized_domains(["com"])
    assert "public suffix" in str(exc.value).lower() or "labels" in str(exc.value).lower()


def test_allowlist_rejects_single_label_example():
    with pytest.raises(ValueError) as exc:
        validate_authorized_domains(["example"])
    assert "labels" in str(exc.value).lower() or "syntax" in str(exc.value).lower() or "label" in str(exc.value).lower()


def test_allowlist_rejects_public_suffix_co_uk():
    with pytest.raises(ValueError) as exc:
        validate_authorized_domains(["co.uk"])
    assert "public suffix" in str(exc.value).lower()


def test_allowlist_accepts_example_com():
    assert validate_authorized_domains(["example.com"]) == ["example.com"]


def test_allowlist_accepts_example_co_uk():
    assert validate_authorized_domains(["example.co.uk"]) == ["example.co.uk"]


def test_allowlist_dedups_preserving_order():
    assert validate_authorized_domains(["a.com", "b.com", "a.com"]) == ["a.com", "b.com"]


def test_allowlist_normalizes_case_and_trailing_dot():
    assert validate_authorized_domains([" Example.COM. "]) == ["example.com"]


# ---------------------------------------------------------------------------
# A4: log JSONL forense
# ---------------------------------------------------------------------------


def test_audit_log_dry_run_writes_jsonl(_isolate_audit, monkeypatch):
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("SMTP not allowed in dry-run")

    monkeypatch.setattr(smtplib, "SMTP", fail_if_called)

    result = run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        send_spoof=False,  # rama dry-run explícita para tests programáticos
        quiet=True,
    )

    assert result.status == "dry_run_ready"
    assert _isolate_audit.exists()
    lines = _isolate_audit.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["operation"] == "spoof_dry_run"
    assert entry["target_email"] == "victim@example.com"
    assert entry["session_id"]
    assert entry["eml_sha256"]


def test_audit_log_env_var_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom_audit.jsonl"
    monkeypatch.setenv("SECEMAIL_AUDIT_LOG", str(custom))

    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})
    run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        send_spoof=False,  # rama dry-run para test
        quiet=True,
    )

    assert custom.exists()
    entries = [json.loads(line) for line in custom.read_text(encoding="utf-8").splitlines() if line]
    assert any(e["operation"] == "spoof_dry_run" for e in entries)


# ---------------------------------------------------------------------------
# A2: rate-limit en campaña
# ---------------------------------------------------------------------------


def test_rate_per_minute_paces_campaign(monkeypatch):
    """Con 60/min => 1 segundo entre envíos; con sleep mockeado verificamos
    la suma de delays solicitada (4 pausas para 5 targets)."""

    resolver = FakeResolver(
        mx_records={"example.com": [(10, "mx.example.com")]}
    )

    sleeps = []
    fake_time = {"v": 1000.0}

    def fake_sleep(seconds):
        sleeps.append(seconds)
        fake_time["v"] += seconds

    def fake_monotonic():
        return fake_time["v"]

    campaign = run_spoof_campaign(
        targets=[f"u{i}@example.com" for i in range(5)],
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        rate_per_minute=60,
        max_recipients=100,
        spoof_from="ceo@example.com",
        sleep_fn=fake_sleep,
        monotonic_fn=fake_monotonic,
        quiet=True,
    )

    assert campaign.targets_processed == 5
    # 4 gaps esperados con ~1s cada uno (60/min = 1s/msg). Total >= 4s.
    assert sum(sleeps) >= 4.0
    assert len(sleeps) == 4


def test_max_recipients_blocks_campaign():
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})
    campaign = run_spoof_campaign(
        targets=[f"u{i}@example.com" for i in range(10)],
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        rate_per_minute=DEFAULT_RATE_PER_MINUTE,
        max_recipients=5,
        spoof_from="ceo@example.com",
        sleep_fn=lambda s: None,
        quiet=True,
    )
    assert campaign.aborted_reason is not None
    assert campaign.targets_processed == 0


# ---------------------------------------------------------------------------
# A3: confirmación TTY
# ---------------------------------------------------------------------------


def test_send_proceeds_without_tty_confirmation(monkeypatch):
    """Comportamiento actualizado: ya no se pide confirmación TTY 'SI ENVIAR'.
    El envío procede directamente — autorización asumida del operador."""
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    smtp_called = {"n": 0}

    class _FakeSMTP:
        def __init__(self, *a, **kw):
            smtp_called["n"] += 1

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self, *a, **kw):
            return None

        def has_extn(self, name):
            return False

        def send_message(self, *a, **kw):
            raise smtplib.SMTPException("simulated relay down")

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    result = run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        authorized_domains=["example.com"],
        quiet=True,
        # No pasamos isatty_fn ni confirm_callback: por defecto envía.
    )

    assert smtp_called["n"] == 1
    assert result.status == "rejected_by_all_mx"


def test_send_proceeds_in_non_tty_too(monkeypatch):
    """En no-TTY (CI / pipes) también envía directo, sin requerir --no-interactive."""
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    smtp_called = {"n": 0}

    class _FakeSMTP:
        def __init__(self, *a, **kw):
            smtp_called["n"] += 1
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self, *a, **kw): return None
        def has_extn(self, name): return False
        def send_message(self, *a, **kw):
            raise smtplib.SMTPException("simulated")

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    result = run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        authorized_domains=["example.com"],
        quiet=True,
        isatty_fn=lambda: False,  # no-TTY
    )

    assert smtp_called["n"] == 1, "Debe enviar incluso en no-TTY (sin confirmación)"
    assert result.status == "rejected_by_all_mx"


# ---------------------------------------------------------------------------
# A5: header forense opt-in
# ---------------------------------------------------------------------------


def test_forensic_headers_off_by_default(monkeypatch):
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    captured = {}

    class _RecordingSMTP:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self, *a, **kw):
            return None

        def has_extn(self, name):
            return False

        def send_message(self, msg, **kw):
            captured["msg"] = msg
            return None

    monkeypatch.setattr(smtplib, "SMTP", _RecordingSMTP)

    run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        send_spoof=True,
        i_have_authorization=True,
        authorized_domains=["example.com"],
        quiet=True,
        isatty_fn=lambda: False,
        no_interactive=True,
        add_forensic_headers=False,
    )

    msg = captured["msg"]
    for key in list(msg.keys()):
        assert not key.lower().startswith("x-secemail"), f"forensic header found: {key}"


def test_forensic_headers_on_adds_three_headers(monkeypatch):
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    captured = {}

    class _RecordingSMTP:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self, *a, **kw):
            return None

        def has_extn(self, name):
            return False

        def send_message(self, msg, **kw):
            captured["msg"] = msg
            return None

    monkeypatch.setattr(smtplib, "SMTP", _RecordingSMTP)

    run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        send_spoof=True,
        i_have_authorization=True,
        authorized_domains=["example.com"],
        quiet=True,
        isatty_fn=lambda: False,
        no_interactive=True,
        add_forensic_headers=True,
    )

    msg = captured["msg"]
    assert msg.get("X-SecEmail-Test") == "authorized-red-team-simulation"
    assert msg.get("X-SecEmail-Session-Id")
    assert msg.get("X-SecEmail-Operator")


# ---------------------------------------------------------------------------
# A6: atajo --authorize-domain (cli-level)
# ---------------------------------------------------------------------------


def test_authorize_domain_shortcut_implies_full_auth(monkeypatch, tmp_path):
    """Sólo --authorize-domain ya basta para que pase la autorización
    (sin pasar las 3 flags antiguas)."""

    from secemail.cli import _resolve_authorization, parse_args

    args = parse_args(["--authorize-domain", "example.com", "--spoof-test", "v@example.com"])
    send, auth, domains = _resolve_authorization(args)
    assert send is True
    assert auth is True
    assert domains == ["example.com"]


def test_legacy_three_flags_still_work():
    from secemail.cli import _resolve_authorization, parse_args

    args = parse_args(
        [
            "--send-spoof",
            "--i-have-authorization",
            "--authorized-domain",
            "example.com",
            "--spoof-test",
            "v@example.com",
        ]
    )
    send, auth, domains = _resolve_authorization(args)
    assert send is True
    assert auth is True
    assert domains == ["example.com"]


# ---------------------------------------------------------------------------
# A7: WARN si --spoof-to apunta fuera de allowlist
# ---------------------------------------------------------------------------


def test_spoof_to_outside_allowlist_emits_warn_reason():
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    result = run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        spoof_to="external@other-domain.tld",
        authorized_domains=["example.com"],
        quiet=True,
    )

    assert any("outside the allowlist" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Regresión P0/P1/UX adicional.
# ---------------------------------------------------------------------------


def test_p0_2_date_header_is_utc_not_localtime(monkeypatch):
    """P0-2: el header Date debe construirse con formatdate(localtime=False)
    para no filtrar la timezone local del operador en las cabeceras."""
    import secemail.spoof as spoof_mod
    from secemail.ui import UIStyle

    calls = []
    real_formatdate = spoof_mod.formatdate

    def spy_formatdate(*args, **kwargs):
        calls.append(kwargs)
        return real_formatdate(*args, **kwargs)

    monkeypatch.setattr(spoof_mod, "formatdate", spy_formatdate)

    class _R:
        backend = "fake"; errors = []
        def __init__(self, *a, **kw): pass
        def txt(self, n): return []
        def cname(self, n): return []
        def mx(self, n): return [(10, "mx.example.com")]
        def tlsa(self, n): return []

    import email_auth_audit as audit
    audit.run_spoof_test(
        target_email="victim@example.com",
        spoof_domain="example.com",
        resolver=_R(),
        style=UIStyle(False),
        spoof_from="ceo@example.com",
        quiet=True,
    )
    assert calls, "formatdate no fue invocada al construir el mensaje"
    assert all(c.get("localtime") is False for c in calls), (
        f"Date debe usar localtime=False (UTC). calls={calls}"
    )


def test_p1_2_dkim_verified_domains_dedup_with_real_crypto():
    """P1-2: si el mismo `d=` aparece en dos firmas legítimas verificadas
    (caso de rotación de selector durante migración), verified_domains
    no debe contener duplicados."""
    import dkim as dkim_lib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import base64

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    msg = (
        b"From: alice@example.test\r\n"
        b"To: bob@bob.test\r\n"
        b"Subject: dup\r\n"
        b"Date: Wed, 13 May 2026 00:00:00 -0000\r\n"
        b"Message-ID: <t@example.test>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"cuerpo\r\n"
    )
    # Dos firmas con MISMO d= pero distintos selectores (caso rotación).
    sig1 = dkim_lib.sign(msg, b"s1", b"example.test", priv,
                         canonicalize=(b"relaxed", b"relaxed"))
    once = sig1 + msg
    sig2 = dkim_lib.sign(once, b"s2", b"example.test", priv,
                         canonicalize=(b"relaxed", b"relaxed"))
    twice = sig2 + once

    class _R:
        backend = "fake"; errors = []
        def __init__(self, *a, **kw): pass
        def txt(self, n):
            n = n.lower().rstrip(".")
            if n.startswith("s1._domainkey.example.test") or n.startswith("s2._domainkey.example.test"):
                return [f"v=DKIM1; k=rsa; p={pub.decode()}"]
            return []
        def cname(self, n): return []
        def mx(self, n): return []
        def tlsa(self, n): return []

    from email import policy
    from email.parser import BytesParser
    parsed = BytesParser(policy=policy.default).parsebytes(twice)
    dkim_headers = parsed.get_all("DKIM-Signature", [])
    assert len(dkim_headers) == 2

    import secemail
    ev = secemail.audit_email.__module__  # noqa: just to ensure import
    from secemail.checks.dkim import verify_dkim_message
    result = verify_dkim_message(twice, _R(), dkim_headers)

    assert result.result == "pass"
    # Sin dedup, verified_domains tendría ['example.test', 'example.test'].
    assert result.verified_domains == ["example.test"], (
        f"Esperado dedup; got {result.verified_domains}"
    )


def test_ux1_json_error_format_on_input_error(monkeypatch, capsys):
    """UX-1: cuando se pasa --json y la input es inválida, el error debe ir
    también como JSON a stdout (para que jq/SIEM lo parseen)."""
    import secemail.cli as cli
    # --email INVALIDOOO debería disparar input_error.
    rc = cli.main(["--email", "INVALIDOOO", "--json", "--no-color", "--no-animate"])
    captured = capsys.readouterr()
    assert rc != 0, "exit code debe reflejar error"
    # stdout debe ser JSON parseable con clave error.
    import json
    payload = json.loads(captured.out)
    assert "error" in payload, payload
    assert "schema_version" in payload
    assert payload["error"]["code"]


def test_send_flags_without_target_now_ignored_silently(capsys):
    """Comportamiento actualizado: la herramienta asume autorización del operador.
    Las flags --send-spoof/--i-have-authorization/--authorized-domain sin
    --spoof-test ni --targets-file ya NO bloquean (eran un check de UX que
    se quitó al simplificar el camino feliz). Simplemente se ignoran y la
    auditoría sigue su curso."""
    import secemail.cli as cli
    rc = cli.main([
        "--email", "INVALIDOOO",  # provocamos error de input legítimo
        "--send-spoof",
        "--i-have-authorization",
        "--authorized-domain", "example.com",
        "--no-color", "--no-animate",
    ])
    captured = capsys.readouterr()
    # El error es de input, no de "send_without_target" (que ya no existe).
    assert rc == 2
    assert "send_without_target" not in captured.out


def test_ux3_partial_spf_local_flags_is_error(capsys, tmp_path):
    """UX-3: pasar solo --source-ip sin --mail-from y --helo en modo --file
    debe rechazarse con error claro."""
    import secemail.cli as cli
    # Crear un .eml mínimo.
    eml = tmp_path / "x.eml"
    eml.write_bytes(b"From: a@x.com\r\nTo: b@y.com\r\nSubject: x\r\n\r\nbody\r\n")
    rc = cli.main([
        "--file", str(eml),
        "--source-ip", "1.2.3.4",
        "--no-color", "--no-animate",
    ])
    captured = capsys.readouterr()
    assert rc == 2
    assert "interdependent" in captured.err or "incomplete_spf_local" in captured.out
