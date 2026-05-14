"""Tests para los P1 (BLOQUE A) y los nuevos checks Red Team 2026 (BLOQUE B)."""

from __future__ import annotations

import base64
from typing import Dict, List, Optional, Tuple

import pytest

import email_auth_audit as audit


# --------------------------------------------------------------------------- #
# Fake resolver con soporte para TLSA, parametrizable por nombre.
# --------------------------------------------------------------------------- #


class FakeResolver:
    backend = "fake"

    def __init__(
        self,
        txt_records: Optional[Dict[str, List[str]]] = None,
        cname_records: Optional[Dict[str, List[str]]] = None,
        mx_records: Optional[Dict[str, List[Tuple[int, str]]]] = None,
        tlsa_records: Optional[Dict[str, List[Tuple[int, int, int, str]]]] = None,
    ):
        self.txt_records = {k.lower(): v for k, v in (txt_records or {}).items()}
        self.cname_records = {k.lower(): v for k, v in (cname_records or {}).items()}
        self.mx_records = {k.lower(): v for k, v in (mx_records or {}).items()}
        self.tlsa_records = {k.lower(): v for k, v in (tlsa_records or {}).items()}
        self.errors: List[str] = []

    def txt(self, name: str) -> List[str]:
        return list(self.txt_records.get(name.lower().rstrip("."), []))

    def cname(self, name: str) -> List[str]:
        return list(self.cname_records.get(name.lower().rstrip("."), []))

    def mx(self, name: str) -> List[Tuple[int, str]]:
        return list(self.mx_records.get(name.lower().rstrip("."), []))

    def tlsa(self, name: str) -> List[Tuple[int, int, int, str]]:
        return list(self.tlsa_records.get(name.lower().rstrip("."), []))


# --------------------------------------------------------------------------- #
# A1: SPF recursive lookup count
# --------------------------------------------------------------------------- #


def test_a1_spf_recursive_exceeds_10_lookups():
    """Crear includes anidados que sumen >10 DNS lookups debe disparar FAIL."""
    # raíz incluye 3 includes; cada include suma 3 más → 3 + 9 = 12 (>10).
    resolver = FakeResolver(
        txt_records={
            "victim.com": ["v=spf1 include:a.tld include:b.tld include:c.tld -all"],
            "a.tld": ["v=spf1 include:a1.tld include:a2.tld include:a3.tld -all"],
            "b.tld": ["v=spf1 include:b1.tld include:b2.tld include:b3.tld -all"],
            "c.tld": ["v=spf1 include:c1.tld include:c2.tld include:c3.tld -all"],
            "a1.tld": ["v=spf1 -all"],
            "a2.tld": ["v=spf1 -all"],
            "a3.tld": ["v=spf1 -all"],
            "b1.tld": ["v=spf1 -all"],
            "b2.tld": ["v=spf1 -all"],
            "b3.tld": ["v=spf1 -all"],
            "c1.tld": ["v=spf1 -all"],
            "c2.tld": ["v=spf1 -all"],
            "c3.tld": ["v=spf1 -all"],
        }
    )
    result = audit.spf_lookup_count_recursive(resolver, "victim.com")
    assert result["lookups"] > 10, result
    assert result["exceeded"] is True

    check = audit.check_spf(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    assert check.status == "FAIL"
    assert any("10 cumulative DNS lookups" in d or "limit" in d.lower() for d in check.details)


def test_a1_spf_under_limit_passes():
    """3 lookups simples no deben hacer FAIL por límite."""
    resolver = FakeResolver(
        txt_records={
            "ok.tld": ["v=spf1 include:_spf.google.com -all"],
            "_spf.google.com": ["v=spf1 -all"],
        }
    )
    result = audit.spf_lookup_count_recursive(resolver, "ok.tld")
    assert result["exceeded"] is False
    assert result["lookups"] == 1


# --------------------------------------------------------------------------- #
# A2: SPF macros peligrosas
# --------------------------------------------------------------------------- #


def test_a2_spf_exists_macro_to_external_domain_is_fail():
    """exists:%{i}.lookup.attacker.tld debe disparar FAIL (exfiltración DNS)."""
    resolver = FakeResolver(
        txt_records={
            "victim.com": ["v=spf1 exists:%{i}.lookup.attacker.tld -all"],
        }
    )
    check = audit.check_spf(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    assert check.status == "FAIL"
    assert any("macro" in d.lower() and "exfiltration" in d.lower() for d in check.details), check.details


def test_a2_spf_macro_in_own_domain_is_warn_not_fail():
    """Macro %{i} dentro del propio organizational domain → solo WARN, no FAIL."""
    resolver = FakeResolver(
        txt_records={
            "example.com": ["v=spf1 exists:%{i}.spf.example.com -all"],
        }
    )
    check = audit.check_spf(
        resolver,
        "example.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    assert check.status == "WARN", check.details
    assert any("macro" in d.lower() for d in check.details)


# --------------------------------------------------------------------------- #
# A3: DKIM l=, rsa-sha1, t=y, key bits
# --------------------------------------------------------------------------- #


def test_a3_dkim_l_tag_is_fail():
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B"],
        }
    )
    check = audit.check_dkim(
        resolver,
        ["v=1; a=rsa-sha256; d=example.com; s=s1; l=100; bh=fake; b=fake"],
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    assert check.status == "FAIL"
    assert any("l=" in d and "append" in d.lower() for d in check.details), check.details


def test_a3_dkim_rsa_sha1_is_fail():
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B"],
        }
    )
    check = audit.check_dkim(
        resolver,
        ["v=1; a=rsa-sha1; d=example.com; s=s1; bh=fake; b=fake"],
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    assert check.status == "FAIL"
    assert any("rsa-sha1" in d for d in check.details), check.details


def test_a3_dkim_testing_flag_t_y_is_warn():
    """t=y en el TXT de la clave debe disparar WARN (no FAIL)."""
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": ["v=DKIM1; k=rsa; t=y; p=MIIBIjANBgkqhkiG9w0B"],
        }
    )
    check = audit.check_dkim(
        resolver,
        ["v=1; a=rsa-sha256; d=example.com; s=s1; bh=fake; b=fake"],
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    assert check.status in ("WARN",), check.details
    assert any("testing" in d.lower() for d in check.details), check.details


def test_a3_dkim_key_bits_weak_is_warn(monkeypatch):
    """Verifica que clave <1024 bits emita WARN. Monkeypatchea _dkim_key_bits
    para no depender de cryptography ni generar claves débiles en tiempo de test
    (las versiones modernas de la lib rechazan generar <1024 bits)."""
    monkeypatch.setattr(
        "secemail.checks.dkim._dkim_key_bits",
        lambda p_value: 512,
    )
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=ZmFrZS1kZXItYnl0ZXM="],
        }
    )
    check = audit.check_dkim(
        resolver,
        ["v=1; a=rsa-sha256; d=example.com; s=s1; bh=fake; b=fake"],
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    assert check.status == "WARN", check.details
    assert any("bits" in d.lower() and "weak" in d.lower() for d in check.details), check.details


# --------------------------------------------------------------------------- #
# A4: ARC cv=fail
# --------------------------------------------------------------------------- #


def test_a4_arc_seal_cv_fail_is_fail():
    seals = [
        "i=1; a=rsa-sha256; d=mailer.example; s=arc; cv=none; b=AAA",
        "i=2; a=rsa-sha256; d=mailer.example; s=arc; cv=fail; b=BBB",
    ]
    msgs = [
        "i=1; a=rsa-sha256; d=mailer.example; s=arc; b=CCC",
        "i=2; a=rsa-sha256; d=mailer.example; s=arc; b=DDD",
    ]
    auths = [
        "i=1; mx.local; spf=pass smtp.mailfrom=foo@bar",
        "i=2; mx.local; spf=pass smtp.mailfrom=foo@bar",
    ]
    resolver = FakeResolver(
        txt_records={
            "arc._domainkey.mailer.example": ["v=DKIM1; k=rsa; p=MIIBI"],
        }
    )
    check = audit.check_arc(
        resolver,
        arc_seal_headers=seals,
        arc_msg_headers=msgs,
        arc_auth_headers=auths,
        auth_data={"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    assert check.status == "FAIL"
    assert any("cv=fail" in d for d in check.details), check.details


def test_a4_arc_seal_missing_cv_is_warn():
    seals = ["i=1; a=rsa-sha256; d=mailer.example; s=arc; b=AAA"]
    msgs = ["i=1; a=rsa-sha256; d=mailer.example; s=arc; b=BBB"]
    auths = ["i=1; mx.local; spf=pass"]
    resolver = FakeResolver(
        txt_records={
            "arc._domainkey.mailer.example": ["v=DKIM1; k=rsa; p=MIIBI"],
        }
    )
    check = audit.check_arc(
        resolver,
        arc_seal_headers=seals,
        arc_msg_headers=msgs,
        arc_auth_headers=auths,
        auth_data={"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )
    # WARN por cv= ausente, no FAIL (ARC structure válida si DNS está).
    assert check.status in ("WARN",), check.details
    assert any("missing required cv= tag" in d for d in check.details), check.details


# --------------------------------------------------------------------------- #
# A5: Sender fallback DMARC + multi-From warning
# --------------------------------------------------------------------------- #


def test_a5_sender_fallback_when_multi_from(monkeypatch):
    raw = b"""From: alice@a.tld, bob@b.tld\r
Sender: alice@a.tld\r
To: user@example.com\r
Subject: test\r
\r
hi
"""

    class _Resolver:
        backend = "fake"
        errors: List[str] = []

        def __init__(self, timeout: float = 0):
            pass

        def txt(self, name: str) -> List[str]:
            return []

        def cname(self, name: str) -> List[str]:
            return []

        def mx(self, name: str) -> List[Tuple[int, str]]:
            return []

        def tlsa(self, name: str) -> List[Tuple[int, int, int, str]]:
            return []

    monkeypatch.setattr("secemail.checks.runner.DnsResolver", _Resolver)
    report = audit.audit_email(raw_email=raw)
    assert report.metadata.get("from_multi"), report.metadata
    assert report.metadata.get("sender") == "alice@a.tld"
    warnings = report.metadata.get("warnings") or []
    assert any("multiple" in w.lower() or "múltiples" in w.lower() for w in warnings), warnings
    assert any("alignment" in w.lower() and "sender" in w.lower() for w in warnings), warnings


def test_a5_resent_from_captured(monkeypatch):
    raw = b"""From: orig@example.com\r
Resent-From: forwarder@list.example\r
To: user@example.com\r
Subject: test\r
\r
hi
"""

    class _Resolver:
        backend = "fake"
        errors: List[str] = []

        def __init__(self, timeout: float = 0):
            pass

        def txt(self, name: str) -> List[str]:
            return []

        def cname(self, name: str) -> List[str]:
            return []

        def mx(self, name: str) -> List[Tuple[int, str]]:
            return []

        def tlsa(self, name: str) -> List[Tuple[int, int, int, str]]:
            return []

    monkeypatch.setattr("secemail.checks.runner.DnsResolver", _Resolver)
    report = audit.audit_email(raw_email=raw)
    assert report.metadata.get("resent_from"), report.metadata


# --------------------------------------------------------------------------- #
# A6: CRLF normalize
# --------------------------------------------------------------------------- #


def test_a6_crlf_normalize_flag(monkeypatch):
    raw_lf_only = b"From: alice@example.com\nTo: bob@example.com\nSubject: test\n\nbody"

    class _Resolver:
        backend = "fake"
        errors: List[str] = []

        def __init__(self, timeout: float = 0):
            pass

        def txt(self, name):
            return []

        def cname(self, name):
            return []

        def mx(self, name):
            return []

        def tlsa(self, name):
            return []

    monkeypatch.setattr("secemail.checks.runner.DnsResolver", _Resolver)
    report = audit.audit_email(raw_email=raw_lf_only)
    assert report.metadata.get("crlf_normalized") is True


def test_a6_already_crlf_not_marked(monkeypatch):
    raw_crlf = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: test\r\n\r\nbody"

    class _Resolver:
        backend = "fake"
        errors: List[str] = []

        def __init__(self, timeout: float = 0):
            pass

        def txt(self, name):
            return []

        def cname(self, name):
            return []

        def mx(self, name):
            return []

        def tlsa(self, name):
            return []

    monkeypatch.setattr("secemail.checks.runner.DnsResolver", _Resolver)
    report = audit.audit_email(raw_email=raw_crlf)
    assert report.metadata.get("crlf_normalized") is not True


# --------------------------------------------------------------------------- #
# A7: parse_authserv_id con comentarios y wildcard authserv
# --------------------------------------------------------------------------- #


def test_a7_parse_authserv_id_ignores_rfc5322_comments():
    header = "(verified by foo) mx.google.com; spf=pass smtp.mailfrom=user@google.com"
    assert audit.parse_authserv_id(header) == "mx.google.com"


def test_a7_parse_authserv_id_nested_comments():
    header = "(outer (nested) text) inbound.protection.outlook.com; dkim=pass"
    assert audit.parse_authserv_id(header) == "inbound.protection.outlook.com"


def test_a7_wildcard_trusted_authserv_matches_subdomain():
    """`google.com` debe matchear `mx.google.com` (sufijo .google.com)."""
    parsed = audit.parse_authentication_results(
        ["mx.google.com; spf=pass smtp.mailfrom=foo@google.com"],
        trusted_authserv_ids=["google.com"],
    )
    assert parsed["spf"][0]["trusted"] == "true"


def test_a7_wildcard_does_not_match_evil_lookalike():
    """`google.com` NO debe matchear `evil-google.com`."""
    parsed = audit.parse_authentication_results(
        ["evil-google.com; spf=pass smtp.mailfrom=foo@evil.tld"],
        trusted_authserv_ids=["google.com"],
    )
    assert parsed["spf"][0]["trusted"] == "false"


# --------------------------------------------------------------------------- #
# B1: MTA-STS
# --------------------------------------------------------------------------- #


def test_b1_mta_sts_enforce(monkeypatch):
    resolver = FakeResolver(
        txt_records={"_mta-sts.example.com": ["v=STSv1; id=20260101000000"]}
    )

    policy_text = (
        "version: STSv1\n"
        "mode: enforce\n"
        "mx: mail.example.com\n"
        "max_age: 86400\n"
    )

    monkeypatch.setattr(
        "secemail.checks.modern._fetch_mta_sts_policy",
        lambda domain, timeout=5.0: policy_text,
    )
    check = audit.check_mta_sts(resolver, "example.com")
    assert check.status == "PASS"
    assert check.evidence == "mta_sts_enforce"


def test_b1_mta_sts_testing(monkeypatch):
    resolver = FakeResolver(
        txt_records={"_mta-sts.example.com": ["v=STSv1; id=20260101000000"]}
    )
    policy_text = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n"
    monkeypatch.setattr(
        "secemail.checks.modern._fetch_mta_sts_policy",
        lambda domain, timeout=5.0: policy_text,
    )
    check = audit.check_mta_sts(resolver, "example.com")
    assert check.status == "WARN"


def test_b1_mta_sts_txt_without_policy(monkeypatch):
    resolver = FakeResolver(
        txt_records={"_mta-sts.example.com": ["v=STSv1; id=20260101000000"]}
    )
    monkeypatch.setattr(
        "secemail.checks.modern._fetch_mta_sts_policy",
        lambda domain, timeout=5.0: None,
    )
    check = audit.check_mta_sts(resolver, "example.com")
    assert check.status == "WARN"


def test_b1_mta_sts_no_txt():
    resolver = FakeResolver(txt_records={})
    check = audit.check_mta_sts(resolver, "example.com")
    assert check.status == "INFO"


# --------------------------------------------------------------------------- #
# B2: TLS-RPT
# --------------------------------------------------------------------------- #


def test_b2_tls_rpt_present():
    resolver = FakeResolver(
        txt_records={"_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"]}
    )
    check = audit.check_tls_rpt(resolver, "example.com")
    assert check.status == "PASS"


def test_b2_tls_rpt_absent():
    resolver = FakeResolver(txt_records={})
    check = audit.check_tls_rpt(resolver, "example.com")
    assert check.status == "INFO"


def test_b2_tls_rpt_missing_rua():
    resolver = FakeResolver(
        txt_records={"_smtp._tls.example.com": ["v=TLSRPTv1"]}
    )
    check = audit.check_tls_rpt(resolver, "example.com")
    assert check.status == "WARN"


# --------------------------------------------------------------------------- #
# B3: DANE
# --------------------------------------------------------------------------- #


def test_b3_dane_full_coverage():
    resolver = FakeResolver(
        mx_records={"example.com": [(10, "mx1.example.com"), (20, "mx2.example.com")]},
        tlsa_records={
            "_25._tcp.mx1.example.com": [(3, 1, 1, "abcd")],
            "_25._tcp.mx2.example.com": [(3, 1, 1, "efgh")],
        },
    )
    check = audit.check_dane(resolver, "example.com")
    assert check.status == "PASS"


def test_b3_dane_partial_coverage_is_warn():
    resolver = FakeResolver(
        mx_records={"example.com": [(10, "mx1.example.com"), (20, "mx2.example.com")]},
        tlsa_records={"_25._tcp.mx1.example.com": [(3, 1, 1, "abcd")]},
    )
    check = audit.check_dane(resolver, "example.com")
    assert check.status == "WARN"


def test_b3_dane_none_is_info():
    resolver = FakeResolver(
        mx_records={"example.com": [(10, "mx1.example.com")]},
        tlsa_records={},
    )
    check = audit.check_dane(resolver, "example.com")
    assert check.status == "INFO"


# --------------------------------------------------------------------------- #
# B4: BIMI
# --------------------------------------------------------------------------- #


def test_b4_bimi_with_vmc_is_pass():
    resolver = FakeResolver(
        txt_records={
            "default._bimi.example.com": [
                "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
            ]
        }
    )
    check = audit.check_bimi(resolver, "example.com")
    assert check.status == "PASS"


def test_b4_bimi_without_vmc_is_warn():
    resolver = FakeResolver(
        txt_records={"default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg"]}
    )
    check = audit.check_bimi(resolver, "example.com")
    assert check.status == "WARN"


def test_b4_bimi_l_without_https_is_fail():
    resolver = FakeResolver(
        txt_records={"default._bimi.example.com": ["v=BIMI1; l=http://example.com/logo.svg"]}
    )
    check = audit.check_bimi(resolver, "example.com")
    assert check.status == "FAIL"


# --------------------------------------------------------------------------- #
# B6: Lookalike
# --------------------------------------------------------------------------- #


def test_b6_lookalike_paypal_with_capital_I_is_warn():
    check = audit.check_lookalike("paypaI.com")
    assert check.status == "WARN", check.details
    assert any("`I`" in d or "I parecido" in d for d in check.details)


def test_b6_lookalike_microsoft_rn_substitution():
    check = audit.check_lookalike("rnicrosoft.com")
    assert check.status == "WARN"
    assert any("`rn`" in d for d in check.details)


def test_b6_lookalike_clean_domain_is_info():
    check = audit.check_lookalike("anthropic.com")
    assert check.status == "INFO"


def test_b6_lookalike_punycode_detected():
    # xn--pypal-4ve.com decodifica a `pаypal.com` (con Cyrillic 'а') — IDN homograph clásico.
    check = audit.check_lookalike("xn--pypal-4ve.com")
    assert check.status == "WARN"
    assert any("punycode" in d.lower() or "decodes" in d.lower() for d in check.details), check.details


def test_b6_lookalike_via_audit_domain_preserves_case():
    """Regresión: el flujo `audit_domain('paypaI.com')` debe propagar el case original
    al lookalike check, aunque el dominio normalizado vaya en minúsculas. Sin este
    fix, la I se aplanaba y la heurística no disparaba (P2 reportado por usuario)."""
    report = audit.audit_domain("paypaI.com", dkim_selectors=[], dns_timeout=1)
    lk = [c for c in report.checks if c.protocol == "LOOKALIKE"]
    assert lk, "Debe existir un check LOOKALIKE"
    assert lk[0].status == "WARN", (
        f"audit_domain('paypaI.com') debió detectar la I mayúscula. detalles: {lk[0].details}"
    )


def test_b6_lookalike_via_audit_domain_with_email_form():
    """Idéntico al anterior pero pasando una dirección email en lugar de dominio."""
    report = audit.audit_domain("user@paypaI.com", dkim_selectors=[], dns_timeout=1)
    lk = [c for c in report.checks if c.protocol == "LOOKALIKE"]
    assert lk
    assert lk[0].status == "WARN", lk[0].details


def test_ar_injection_with_same_authservid_first_wins_rfc8601():
    """RFC 8601 §4.1: el MTA receptor prepend su AR al header chain, así que el
    PRIMER AR es el más reciente y legítimo. Si un atacante inyecta otro AR con
    el mismo authserv_id, los items duplicados (mismo proto) se degradan a
    trusted='false' y se reporta warning."""
    headers = [
        # AR legítimo añadido por el MTA receptor (top del chain = más reciente).
        "mx.empresa.com; spf=fail smtp.mailfrom=evil.com; dkim=fail header.d=evil.com; dmarc=fail",
        # AR inyectado por el atacante en el cuerpo original.
        "mx.empresa.com; spf=pass smtp.mailfrom=evil.com; dkim=pass header.d=evil.com; dmarc=pass",
    ]
    warnings = []
    data = audit.parse_authentication_results(
        headers,
        trusted_authserv_ids=["mx.empresa.com"],
        warnings_out=warnings,
    )
    # SPF: dos items totales, sólo el primero es trusted.
    spf = data["spf"]
    assert len(spf) == 2
    assert spf[0]["trusted"] == "true" and spf[0]["result"] == "fail"
    assert spf[1]["trusted"] == "false" and spf[1]["result"] == "pass"
    # Misma defensa en DKIM y DMARC.
    assert data["dkim"][0]["result"] == "fail" and data["dkim"][0]["trusted"] == "true"
    assert data["dkim"][1]["trusted"] == "false"
    assert data["dmarc"][0]["result"] == "fail" and data["dmarc"][0]["trusted"] == "true"
    assert data["dmarc"][1]["trusted"] == "false"
    # 3 warnings: uno por proto duplicado (spf, dkim, dmarc).
    assert len(warnings) == 3
    assert all("duplicated" in w and "mx.empresa.com" in w for w in warnings)


def test_ar_legitimate_followed_by_different_authservid_both_stay_trusted_if_both_in_allowlist():
    """Cuando los authserv_id son DISTINTOS y AMBOS están en allowlist, ambos
    son trusted (no es el caso de inyección). Sólo deduplicamos cuando un mismo
    authserv_id aparece más de una vez."""
    headers = [
        "mx1.empresa.com; spf=pass smtp.mailfrom=ok.com",
        "mx2.empresa.com; spf=pass smtp.mailfrom=ok.com",
    ]
    warnings = []
    data = audit.parse_authentication_results(
        headers,
        trusted_authserv_ids=["mx1.empresa.com", "mx2.empresa.com"],
        warnings_out=warnings,
    )
    assert data["spf"][0]["trusted"] == "true"
    assert data["spf"][1]["trusted"] == "true"
    assert warnings == []


def test_b6_lookalike_cyrillic_homograph_without_punycode():
    """Si llega un dominio con caracteres no-ASCII raw (sin punycode), debe flag."""
    # 'а' es U+0430 (cirílica), parece 'a' ASCII.
    check = audit.check_lookalike("paypal.com", raw_domain="pаypal.com")
    assert check.status == "WARN"
    assert any("ASCII" in d and "non-ASCII" in d for d in check.details), check.details


# --------------------------------------------------------------------------- #
# B7: DMARC external rua/ruf authorization
# --------------------------------------------------------------------------- #


def test_b7_dmarc_external_rua_without_authorization_is_warn():
    resolver = FakeResolver(
        txt_records={
            "_dmarc.victim.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@reporter.tld"],
            # NO publicamos victim.com._report._dmarc.reporter.tld
        }
    )
    check = audit.check_dmarc(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    # Puede ser WARN o FAIL si encadena con otros problemas; mínimo, hay aviso.
    assert any(
        "external" in d.lower()
        or "externo" in d.lower()
        or "_report._dmarc" in d
        for d in check.details
    ), check.details


def test_b7_dmarc_external_rua_with_authorization_is_ok():
    resolver = FakeResolver(
        txt_records={
            "_dmarc.victim.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@reporter.tld"],
            "victim.com._report._dmarc.reporter.tld": ["v=DMARC1"],
        }
    )
    check = audit.check_dmarc(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    # No debe aparecer la advertencia de external sin autorización.
    assert not any(
        "sin txt de autorización" in d.lower() or "sin autorización" in d.lower()
        for d in check.details
    ), check.details


def test_b7_dmarc_internal_rua_no_warning():
    resolver = FakeResolver(
        txt_records={
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        }
    )
    check = audit.check_dmarc(
        resolver,
        "example.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )
    # Sin warning de external porque está en el mismo dominio.
    assert not any("externo" in d.lower() for d in check.details), check.details
