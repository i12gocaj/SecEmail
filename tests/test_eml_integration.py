"""Tests de integración end-to-end con fixtures .eml reales.

Cada test alimenta a `audit_email` un fichero `tests/fixtures/eml/*.eml`
construido para reproducir un escenario concreto que un Red Team encuentra
en la práctica (multi-DKIM, AR injection, LF-only exports, etc.).

Las firmas DKIM en las fixtures NO son criptográficamente válidas — `b=` y
`bh=` son base64 aleatorio. El objetivo no es verificar firmas reales sino
validar que el flujo de `audit_email` extrae correctamente dominios,
metadata, warnings y veredictos del check correspondiente sin lanzar
excepciones. Cuando dkimpy reporta `fail` por criptografía, eso es esperado
y forma parte del aserto.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

import email_auth_audit as audit


FIXTURES = Path(__file__).parent / "fixtures" / "eml"


# --------------------------------------------------------------------------- #
# Resolver mock vacío: ningún DNS público en CI; cada test controla qué
# devuelve si necesita TXT/CNAME/MX/TLSA específicos. Por defecto, todo []
# (NXDOMAIN-like).
# --------------------------------------------------------------------------- #


class EmptyResolver:
    backend = "fake"

    def __init__(
        self,
        timeout: float = 0,
        *,
        txt: Optional[Dict[str, List[str]]] = None,
        cname: Optional[Dict[str, List[str]]] = None,
        mx: Optional[Dict[str, List[Tuple[int, str]]]] = None,
        tlsa: Optional[Dict[str, List[Tuple[int, int, int, str]]]] = None,
    ) -> None:
        self._txt = {k.lower().rstrip("."): v for k, v in (txt or {}).items()}
        self._cname = {k.lower().rstrip("."): v for k, v in (cname or {}).items()}
        self._mx = {k.lower().rstrip("."): v for k, v in (mx or {}).items()}
        self._tlsa = {k.lower().rstrip("."): v for k, v in (tlsa or {}).items()}
        self.errors: List[str] = []

    def txt(self, name: str) -> List[str]:
        return list(self._txt.get(name.lower().rstrip("."), []))

    def cname(self, name: str) -> List[str]:
        return list(self._cname.get(name.lower().rstrip("."), []))

    def mx(self, name: str) -> List[Tuple[int, str]]:
        return list(self._mx.get(name.lower().rstrip("."), []))

    def tlsa(self, name: str) -> List[Tuple[int, int, int, str]]:
        return list(self._tlsa.get(name.lower().rstrip("."), []))


def _patch_resolver(monkeypatch, resolver_factory):
    """Sustituye `DnsResolver` por una factoría que ignora `timeout=`.

    audit_email instancia internamente DnsResolver(timeout=...), así que
    necesitamos un callable que devuelva un resolver pre-poblado.
    """
    monkeypatch.setattr("secemail.checks.runner.DnsResolver", resolver_factory)


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _checks_by_proto(report) -> Dict[str, "audit.CheckResult"]:
    return {c.protocol: c for c in report.checks}


# --------------------------------------------------------------------------- #
# 1) gmail_signed.eml
# --------------------------------------------------------------------------- #


def test_gmail_signed_baseline(monkeypatch):
    """Workspace outbound: DKIM/SPF/DMARC/ARC presentes, extracción correcta
    de From / Return-Path / envelope. Sin DNS, los checks fallan en sus DNS
    lookups (esperado), pero el flujo procesa el .eml sin excepciones y
    rellena los campos clave del report.
    """
    raw = _load("gmail_signed.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    assert report.from_domain == "example.com"
    assert report.return_path_domain == "example.com"
    assert report.envelope_from_domain == "example.com"
    assert report.input_mode == "eml"

    # No marcamos crlf_normalized porque el fichero ya viene CRLF.
    assert report.metadata.get("crlf_normalized") is not True

    by = _checks_by_proto(report)
    assert {"SPF", "DKIM", "DMARC", "ARC", "LOOKALIKE"}.issubset(set(by))

    # Hay 1 DKIM-Signature: el check NO es FAIL por ausencia, sino por
    # verificación criptográfica (sig hecha con material fake).
    dkim = by["DKIM"]
    assert dkim.evidence == "cryptographic_verification"
    # Como la firma no verifica, no debe declararse ningún dominio verificado.
    assert dkim.verified_domains == []


# --------------------------------------------------------------------------- #
# 2) m365_signed.eml
# --------------------------------------------------------------------------- #


def test_m365_signed_baseline(monkeypatch):
    """Microsoft 365 outbound: extracción de From, headers MS-Exchange y
    Microsoft-Antispam coexisten con la firma DKIM single-selector."""
    raw = _load("m365_signed.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    assert report.from_domain == "example.org"
    assert report.return_path_domain == "example.org"
    assert report.envelope_from_domain == "example.org"

    by = _checks_by_proto(report)
    dkim = by["DKIM"]
    assert dkim.evidence == "cryptographic_verification"
    assert dkim.verified_domains == []

    # No es 'FAIL por ausencia' (hay DKIM-Signature presente).
    assert "No DKIM-Signature header" not in " ".join(dkim.details)


# --------------------------------------------------------------------------- #
# 3) multi_dkim_attack.eml (P0-1)
# --------------------------------------------------------------------------- #


def test_multi_dkim_attack_victim_domain_not_verified(monkeypatch):
    """P0-1: dos DKIM-Signature, una con d=mailer.legitimo.tld (estructura
    legítima) y otra adversarial con d=victim.example y b= basura. Como
    ninguna verifica criptográficamente, `verified_domains` debe quedar
    vacío — y EN NINGÚN caso contener `victim.example`.

    Comprobación adicional: la alineación DMARC nunca acepta `victim.example`
    como d= verificado, así que el veredicto DMARC no puede ser PASS por
    DKIM.
    """
    raw = _load("multi_dkim_attack.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    assert report.from_domain == "victim.example"
    assert report.envelope_from_domain == "mailer.legitimo.tld"

    by = _checks_by_proto(report)
    dkim = by["DKIM"]

    # Lo crítico de P0-1: el d= adversarial NO entra en verified_domains.
    assert "victim.example" not in dkim.verified_domains, (
        f"victim.example NO debe constar como dominio DKIM verificado. "
        f"verified_domains={dkim.verified_domains}"
    )
    # Y como ninguna firma verificó realmente, la lista está vacía.
    assert dkim.verified_domains == []

    # DMARC no puede salir PASS: ni SPF alineado (mailer.legitimo.tld != victim.example),
    # ni DKIM verificado.
    dmarc = by["DMARC"]
    assert dmarc.status == "FAIL"


# --------------------------------------------------------------------------- #
# 4) crlf_mixed_thunderbird.eml (P1 A6)
# --------------------------------------------------------------------------- #


def test_crlf_normalized_flag_set_for_lf_export(monkeypatch):
    """P1 A6: un .eml exportado con LF puro debe activar
    `metadata["crlf_normalized"] = True` y registrar un warning explícito."""
    raw = _load("crlf_mixed_thunderbird.eml")

    # Sanity: la fixture es LF-only de verdad.
    assert b"\r\n" not in raw, "La fixture LF-only contiene CRLF; comprueba el archivo."
    assert b"\n" in raw

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    assert report.metadata.get("crlf_normalized") is True
    warnings = report.metadata.get("warnings") or []
    assert any("CRLF" in w for w in warnings), warnings
    # El parseo procede normalmente — el From sigue extrayéndose.
    assert report.from_domain == "example.com"


# --------------------------------------------------------------------------- #
# 5) auth_results_injection_attempt.eml (P1 A7)
# --------------------------------------------------------------------------- #


def test_auth_results_injection_default_untrusted(monkeypatch):
    """Sin pasar trusted-authserv-ids, ambos Authentication-Results son
    untrusted: no se consideran como evidencia para SPF/DKIM/DMARC.
    """
    raw = _load("auth_results_injection_attempt.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    by = _checks_by_proto(report)
    # SPF/DKIM/DMARC: sin AR confiable, evidence sigue siendo 'dns_only'.
    # Como no hay DNS poblado en el mock, las tres FAIL por ausencia.
    for proto in ("SPF", "DKIM", "DMARC"):
        assert by[proto].evidence == "dns_only", (proto, by[proto].evidence)
        assert by[proto].status == "FAIL"


def test_auth_results_injection_fail_wins_over_injected_pass(monkeypatch):
    """P1 A7 + RFC 8601 §5: cuando el adversario inyecta un Authentication-Results
    con el MISMO authserv_id que el receptor confiable (después del strip de
    comentarios), la defensa de deduplicación por (authserv_id, proto) descarta
    el AR inyectado (sólo el PRIMERO del header chain es legítimo, RFC 8601 §4.1).

    Resultado esperado:
      - Sólo el AR legítimo (`fail`) cuenta como evidencia trusted.
      - El AR inyectado (`pass`) queda degradado a trusted="false".
      - SPF/DMARC FAIL con evidence='trusted_authentication_results'.
      - report.metadata["ar_injection_warnings"] documenta la detección.
    """
    raw = _load("auth_results_injection_attempt.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(
        raw_email=raw,
        trusted_authserv_ids=["trusted-mx.example.com"],
    )

    by = _checks_by_proto(report)
    spf = by["SPF"]
    dmarc = by["DMARC"]

    # El AR legítimo es confiable y se usó como evidencia.
    assert spf.evidence == "trusted_authentication_results", spf.evidence
    assert dmarc.evidence == "trusted_authentication_results", dmarc.evidence

    # Veredicto FAIL — el `fail` legítimo es el único trusted.
    assert spf.status == "FAIL"
    assert dmarc.status == "FAIL"

    # El `fail` legítimo aparece en details.
    detail_blob = " ".join(spf.details + dmarc.details)
    assert "fail" in detail_blob.lower(), detail_blob

    # La inyección debe haber sido detectada y registrada en metadata.
    injection_warnings = report.metadata.get("ar_injection_warnings", [])
    assert injection_warnings, "Debe haber warnings de AR injection en metadata"
    blob = " ".join(injection_warnings).lower()
    assert "duplicated" in blob and "trusted-mx.example.com" in blob


# --------------------------------------------------------------------------- #
# 6) sender_fallback.eml (P1 A5)
# --------------------------------------------------------------------------- #


def test_sender_fallback_multi_from_warns_and_captures_sender(monkeypatch):
    """P1 A5: cuando From contiene múltiples direcciones (RFC 5322 §3.6.2),
    `audit_email` debe:
      - poblar `metadata["from_multi"]` con la lista de direcciones,
      - capturar Sender en `metadata["sender"]`,
      - emitir un warning de uso de Sender como identidad responsable para
        alineación DMARC.
    """
    raw = _load("sender_fallback.eml")

    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    from_multi = report.metadata.get("from_multi")
    assert from_multi, report.metadata
    assert len(from_multi) == 2
    assert any("alice@example.com" in entry for entry in from_multi)
    assert any("bob@example.com" in entry for entry in from_multi)

    assert report.metadata.get("sender") == "ceo@example.com"

    warnings = report.metadata.get("warnings") or []
    # Hay al menos dos warnings: uno por multi-From y otro por Sender fallback.
    assert any(
        "múltiples" in w.lower() or "multiple" in w.lower() for w in warnings
    ), warnings
    assert any(
        "sender" in w.lower() and "alignment" in w.lower() for w in warnings
    ), warnings


# --------------------------------------------------------------------------- #
# Cross-cutting: cada fixture procesa sin excepciones y schema_version se fija
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fixture",
    [
        "gmail_signed.eml",
        "m365_signed.eml",
        "multi_dkim_attack.eml",
        "crlf_mixed_thunderbird.eml",
        "auth_results_injection_attempt.eml",
        "sender_fallback.eml",
    ],
)
def test_each_fixture_parses_and_produces_full_report(monkeypatch, fixture):
    """Ninguna fixture debe lanzar excepción; cada report debe contener al
    menos los 4 checks core (SPF/DKIM/DMARC/ARC) + LOOKALIKE y
    `schema_version=2.0`."""
    raw = _load(fixture)
    _patch_resolver(monkeypatch, lambda timeout=0: EmptyResolver())
    report = audit.audit_email(raw_email=raw)

    assert report.metadata.get("schema_version") == "2.0"
    protocols = {c.protocol for c in report.checks}
    assert {"SPF", "DKIM", "DMARC", "ARC"}.issubset(protocols), protocols
    # LOOKALIKE sólo se añade si from_domain es válido (B6). El único caso en
    # que falta es sender_fallback.eml donde el From multi-address hace que
    # `parseaddr` devuelva vacío y from_domain quede None.
    if report.from_domain:
        assert "LOOKALIKE" in protocols, protocols


# --------------------------------------------------------------------------- #
# Combinado: P0-1 + DMARC con política publicada
# --------------------------------------------------------------------------- #


def test_multi_dkim_with_dmarc_record_rejects_unverified_domain(monkeypatch):
    """Refuerzo del P0-1: con `_dmarc.victim.example` publicado (p=reject)
    y ninguna firma DKIM realmente verificada, la firma adversarial
    `d=victim.example` no debe constar como verificada. Aun con una política
    DMARC formal publicada, el veredicto NO puede ser PASS para este
    mensaje.

    Nota: no inyectamos `source_ip` para evitar que pyspf intente DNS real
    en CI; sin SPF local y sin DKIM verificado el check DMARC queda en
    WARN (no FAIL puro) — lo importante es que NO sea PASS.
    """
    raw = _load("multi_dkim_attack.eml")

    def factory(timeout=0):
        return EmptyResolver(
            txt={
                "_dmarc.victim.example": [
                    "v=DMARC1; p=reject; rua=mailto:dmarc@victim.example"
                ],
            }
        )

    _patch_resolver(monkeypatch, factory)
    report = audit.audit_email(raw_email=raw)

    by = _checks_by_proto(report)
    dkim = by["DKIM"]
    dmarc = by["DMARC"]

    # P0-1: el d= adversarial NO entra como verificado.
    assert "victim.example" not in dkim.verified_domains

    # DMARC no puede ser PASS sin SPF/DKIM verificado que alinee con
    # victim.example.
    assert dmarc.status != "PASS", dmarc.details
