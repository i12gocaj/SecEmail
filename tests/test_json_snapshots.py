"""Snapshot tests del JSON schema de salida.

Congelan el formato de `secemail` para que cambios accidentales rompan CI antes
de llegar a integraciones SIEM/automatización del cliente. Si necesitas regenerar
los snapshots tras un cambio intencional, ejecuta:

    UPDATE_SNAPSHOTS=1 /opt/homebrew/bin/python3.12 -m pytest tests/test_json_snapshots.py

Los snapshots están en ``tests/snapshots/*.json`` — revisa el diff antes de commit.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

import pytest

import secemail.checks.runner as runner
from secemail.dns import DnsResolverError


SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"
UPDATE_ENV_VAR = "UPDATE_SNAPSHOTS"


class StubResolver:
    """Resolver determinista para tests de snapshot. Sin red."""

    backend = "stub"
    errors: list = []

    def __init__(self, txt=None, cname=None, mx=None, tlsa=None, timeout=0.0):
        self._txt = txt or {}
        self._cname = cname or {}
        self._mx = mx or {}
        self._tlsa = tlsa or {}

    def txt(self, name: str):
        return self._txt.get(name.lower().rstrip("."), [])

    def cname(self, name: str):
        return self._cname.get(name.lower().rstrip("."), [])

    def mx(self, name: str):
        return self._mx.get(name.lower().rstrip("."), [])

    def tlsa(self, name: str):
        return self._tlsa.get(name.lower().rstrip("."), [])


def _report_to_payload(report) -> Dict[str, Any]:
    """Serializa el AuditReport a un dict deterministic (sin timestamps / backend)."""
    payload = {
        "schema_version": report.metadata.get("schema_version"),
        "from_domain": report.from_domain,
        "return_path_domain": report.return_path_domain,
        "envelope_from_domain": report.envelope_from_domain,
        "input_mode": report.input_mode,
        "target": report.target,
        "metadata": {k: v for k, v in report.metadata.items() if k not in {"helo", "source_ip"}},
        "summary": report.summary,
        "checks": [asdict(c) for c in report.checks],
    }
    return payload


def _compare_or_write(name: str, payload: Dict[str, Any]) -> None:
    """Compara payload contra snapshot, o lo escribe si UPDATE_SNAPSHOTS=1 o no existe."""
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    snap_path = SNAPSHOTS_DIR / f"{name}.json"
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)

    if os.environ.get(UPDATE_ENV_VAR) == "1" or not snap_path.exists():
        snap_path.write_text(serialized + "\n", encoding="utf-8")
        if not snap_path.exists():
            pytest.fail(f"Snapshot escrito en {snap_path}; re-ejecuta para verificar.")
        # Cuando regeneramos intencionalmente, el test pasa.
        return

    expected = snap_path.read_text(encoding="utf-8").rstrip("\n")
    if expected != serialized:
        # Diff legible para que el reviewer entienda qué cambió.
        import difflib

        diff = "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                serialized.splitlines(),
                fromfile=f"snapshot/{name}.json",
                tofile=f"actual/{name}.json",
                lineterm="",
            )
        )
        pytest.fail(
            f"Snapshot {name} difiere del actual. Si el cambio es intencional, "
            f"regenera con UPDATE_SNAPSHOTS=1.\n\n{diff}"
        )


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """Bloquea cualquier intento accidental de hacer DNS real durante snapshots."""

    def _block(*a, **kw):
        raise RuntimeError("DNS real bloqueado en tests de snapshot — usa StubResolver")

    # No reemplazamos resolver.DnsResolver porque cada test lo hace explícito.
    yield


# --------------------------------------------------------------------------- #
# Snapshot 1: dominio limpio con SPF/DKIM/DMARC publicados.
# --------------------------------------------------------------------------- #


def test_snapshot_audit_domain_well_configured(monkeypatch):
    """Snapshot del JSON de audit_domain para un dominio con todo bien."""
    txt = {
        "example.test": ["v=spf1 -all"],
        "_dmarc.example.test": [
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.test"
        ],
        "default._domainkey.example.test": [
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
        ],
    }
    monkeypatch.setattr(runner, "DnsResolver", lambda timeout=0: StubResolver(txt=txt))
    report = runner.audit_domain(
        "example.test", dkim_selectors=["default"], dns_timeout=1
    )
    payload = _report_to_payload(report)
    _compare_or_write("audit_domain_well_configured", payload)


# --------------------------------------------------------------------------- #
# Snapshot 2: dominio sin nada publicado (caso "todo FAIL").
# --------------------------------------------------------------------------- #


def test_snapshot_audit_domain_unconfigured(monkeypatch):
    """Snapshot del caso adversarial: dominio sin SPF/DKIM/DMARC publicados."""
    monkeypatch.setattr(runner, "DnsResolver", lambda timeout=0: StubResolver())
    report = runner.audit_domain(
        "naked.test", dkim_selectors=["default"], dns_timeout=1
    )
    payload = _report_to_payload(report)
    _compare_or_write("audit_domain_unconfigured", payload)


# --------------------------------------------------------------------------- #
# Snapshot 3: dominio con SPF redirect (test típico Gmail-like).
# --------------------------------------------------------------------------- #


def test_snapshot_audit_domain_with_spf_redirect(monkeypatch):
    """Snapshot que valida que SPF redirect= se reconoce como política terminal."""
    txt = {
        "redirect.test": ["v=spf1 redirect=_spf.provider.test"],
        "_spf.provider.test": ["v=spf1 ip4:192.0.2.0/24 -all"],
        "_dmarc.redirect.test": ["v=DMARC1; p=quarantine"],
    }
    monkeypatch.setattr(runner, "DnsResolver", lambda timeout=0: StubResolver(txt=txt))
    report = runner.audit_domain(
        "redirect.test", dkim_selectors=[], dns_timeout=1
    )
    payload = _report_to_payload(report)
    _compare_or_write("audit_domain_spf_redirect", payload)


# --------------------------------------------------------------------------- #
# Snapshot 4: claves canónicas del schema (top-level + check structure).
# --------------------------------------------------------------------------- #


def test_snapshot_schema_keys_top_level(monkeypatch):
    """Verifica que las claves top-level del schema están y no aparecen otras nuevas
    sin querer. Si añades una clave intencionalmente, regenera el snapshot."""
    monkeypatch.setattr(runner, "DnsResolver", lambda timeout=0: StubResolver())
    report = runner.audit_domain(
        "schema.test", dkim_selectors=[], dns_timeout=1
    )
    payload = _report_to_payload(report)
    top_keys = sorted(payload.keys())
    expected_top_keys = sorted([
        "schema_version", "from_domain", "return_path_domain",
        "envelope_from_domain", "input_mode", "target",
        "metadata", "summary", "checks",
    ])
    assert top_keys == expected_top_keys, (
        f"Claves top-level del schema han cambiado.\nEsperadas: {expected_top_keys}\nActuales: {top_keys}"
    )
    # Claves de un Check.
    if payload["checks"]:
        check_keys = sorted(payload["checks"][0].keys())
        expected_check_keys = sorted([
            "protocol", "status", "evidence", "details", "missing",
            "recommendations", "exact_fixes", "implications", "verified_domains",
        ])
        assert check_keys == expected_check_keys, (
            f"Claves de Check han cambiado.\nEsperadas: {expected_check_keys}\nActuales: {check_keys}"
        )
