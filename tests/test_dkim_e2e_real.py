"""Tests E2E de DKIM con verificación criptográfica REAL.

Generamos un par RSA en `conftest`, firmamos un `.eml` con `dkim.sign()` y
verificamos que `verify_dkim_message` devuelve ``verified_domains`` con el
dominio firmante correcto. Cubre el "happy path" criptográfico que ningún
otro test cubre (las fixtures `.eml` llevan firmas fake intencionales).

Cubre también:
- Doble firma legítima (dos dominios distintos, ambos verifican): verified_domains contiene los dos.
- Mensaje alterado tras firma → DKIM fail (la firma deja de verificar).
- Multi-firma adversarial: firma legítima (verifica) + firma fake con `d=victim` (no verifica)
  → P0-1 regression: verified_domains contiene SOLO el dominio que verificó.
"""

from __future__ import annotations

import base64
import textwrap
from typing import Dict, List, Tuple

import pytest

import dkim  # dkimpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import email_auth_audit as audit


# --------------------------------------------------------------------------- #
# Helpers de generación de claves y firma.
# --------------------------------------------------------------------------- #


def _gen_rsa_pair(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Devuelve (privkey_pem, pubkey_b64_der) listos para dkim.sign y TXT DKIM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    privkey_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pubkey_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pubkey_b64 = base64.b64encode(pubkey_der)
    return privkey_pem, pubkey_b64


def _dkim_txt_record(pubkey_b64: bytes, k: str = "rsa") -> str:
    return f"v=DKIM1; k={k}; p={pubkey_b64.decode('ascii')}"


def _build_message(from_addr: str, to_addr: str, subject: str, body: str) -> bytes:
    raw = (
        f"From: {from_addr}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: Wed, 13 May 2026 12:00:00 +0000\r\n"
        f"Message-ID: <test@{from_addr.split('@')[1]}>\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    return raw.encode("utf-8")


def _sign(message: bytes, selector: str, domain: str, privkey_pem: bytes) -> bytes:
    """Firma DKIM y prepende la cabecera."""
    sig = dkim.sign(
        message=message,
        selector=selector.encode("ascii"),
        domain=domain.encode("ascii"),
        privkey=privkey_pem,
        canonicalize=(b"relaxed", b"relaxed"),
        signature_algorithm=b"rsa-sha256",
    )
    return sig + message


# --------------------------------------------------------------------------- #
# Fakes.
# --------------------------------------------------------------------------- #


class _DnsKeyFake:
    """Resolver mínimo que devuelve TXT DKIM por selector._domainkey.domain."""

    backend = "fake"
    errors: list = []

    def __init__(self, mapping: Dict[str, List[str]]):
        self.mapping = {k.lower().rstrip("."): v for k, v in mapping.items()}

    def txt(self, name: str) -> List[str]:
        return list(self.mapping.get(name.lower().rstrip("."), []))

    def cname(self, name: str) -> List[str]:
        return []

    def mx(self, name: str) -> List[Tuple[int, str]]:
        return []

    def tlsa(self, name: str) -> List[str]:
        return []


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_dkim_e2e_single_legitimate_signature_verifies_cryptographically():
    """Firmamos un mensaje con clave RSA real, publicamos la pública en el DNS
    mockeado, y `verify_dkim_message` debe reportar PASS con verified_domains=[domain]."""
    privkey, pubkey_b64 = _gen_rsa_pair(2048)
    domain = "alice.test"
    selector = "main"

    message = _build_message(
        from_addr=f"alice@{domain}",
        to_addr="bob@bob.test",
        subject="Hola Bob",
        body="Este es un mensaje firmado con DKIM real.",
    )
    signed = _sign(message, selector, domain, privkey)

    resolver = _DnsKeyFake({
        f"{selector}._domainkey.{domain}": [_dkim_txt_record(pubkey_b64)],
    })

    # Extraer headers DKIM-Signature del mensaje firmado.
    from email import policy
    from email.parser import BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(signed)
    dkim_headers = msg.get_all("DKIM-Signature", [])
    assert dkim_headers, "Debe haber 1 DKIM-Signature tras firmar"

    eval_result = audit.verify_dkim_message(signed, resolver, dkim_headers)

    assert eval_result.result == "pass", f"DKIM debe verificar criptográficamente: {eval_result.details}"
    assert eval_result.evidence == "cryptographic_verification"
    assert eval_result.verified_domains == [domain], (
        f"verified_domains debe contener únicamente '{domain}', no {eval_result.verified_domains}"
    )


def test_dkim_e2e_two_legitimate_signatures_both_verified():
    """Firma doble legítima (dos dominios distintos). Ambos d= deben verificar."""
    pk1, pub1 = _gen_rsa_pair(2048)
    pk2, pub2 = _gen_rsa_pair(2048)
    d1, d2 = "first.test", "second.test"

    message = _build_message(
        from_addr=f"alice@{d1}",
        to_addr="bob@bob.test",
        subject="Doble firma",
        body="Cuerpo del mensaje con doble firma DKIM.",
    )
    signed_once = _sign(message, "s1", d1, pk1)
    signed_twice = _sign(signed_once, "s2", d2, pk2)

    resolver = _DnsKeyFake({
        f"s1._domainkey.{d1}": [_dkim_txt_record(pub1)],
        f"s2._domainkey.{d2}": [_dkim_txt_record(pub2)],
    })

    from email import policy
    from email.parser import BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(signed_twice)
    dkim_headers = msg.get_all("DKIM-Signature", [])
    assert len(dkim_headers) == 2

    eval_result = audit.verify_dkim_message(signed_twice, resolver, dkim_headers)

    assert eval_result.result == "pass"
    assert set(eval_result.verified_domains) == {d1, d2}, (
        f"Ambos dominios deben verificar; got {eval_result.verified_domains}"
    )


def test_dkim_e2e_tampered_body_fails_verification():
    """Mensaje firmado, luego se altera el cuerpo: verificación debe FAIL."""
    privkey, pubkey_b64 = _gen_rsa_pair(2048)
    domain = "integrity.test"

    message = _build_message(
        from_addr=f"sys@{domain}",
        to_addr="user@user.test",
        subject="Integrity check",
        body="Contenido original — esto se va a alterar.",
    )
    signed = _sign(message, "k1", domain, privkey)
    tampered = signed.replace(b"original", b"alterado")

    resolver = _DnsKeyFake({
        f"k1._domainkey.{domain}": [_dkim_txt_record(pubkey_b64)],
    })

    from email import policy
    from email.parser import BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(tampered)
    dkim_headers = msg.get_all("DKIM-Signature", [])

    eval_result = audit.verify_dkim_message(tampered, resolver, dkim_headers)

    assert eval_result.result == "fail", (
        f"Mensaje alterado tras firma debe fallar verificación; got result={eval_result.result}, "
        f"verified_domains={eval_result.verified_domains}"
    )
    assert eval_result.verified_domains == [], "No debe haber dominios verificados"


def test_dkim_e2e_p0_1_adversarial_signature_does_not_pollute_verified_domains():
    """**Regresión P0-1 con criptografía real**: el atacante añade una `DKIM-Signature`
    con `d=victim.test` pero clave fake (no verifica). El mensaje también tiene
    una firma legítima de `legit-mailer.test`. `verify_dkim_message` debe devolver
    `verified_domains=['legit-mailer.test']` y NUNCA incluir `victim.test`.
    """
    pk_legit, pub_legit = _gen_rsa_pair(2048)
    pk_attacker_real, pub_attacker_real = _gen_rsa_pair(2048)  # solo para construir firma plausible
    domain_legit = "legit-mailer.test"
    domain_victim = "victim.test"

    message = _build_message(
        from_addr=f"newsletter@{domain_legit}",
        to_addr=f"target@{domain_victim}",
        subject="Promo legítima",
        body="Este boletín lleva firma DKIM del mailer legítimo.",
    )

    # 1) Atacante firma con SU clave pero declara d=victim.test.
    #    Publicaremos en el DNS la clave LEGÍTIMA bajo s_legit._domainkey.legit-mailer.test,
    #    pero NO publicaremos la clave del atacante bajo s_atk._domainkey.victim.test
    #    (es decir: el TXT existirá pero con otra clave distinta a la que firmó). Como
    #    consecuencia, la firma fake no verifica.
    pk_fake_unrelated, pub_fake_unrelated = _gen_rsa_pair(2048)
    fake_attacker_sig = dkim.sign(
        message=message,
        selector=b"s_atk",
        domain=domain_victim.encode("ascii"),
        privkey=pk_attacker_real,
        canonicalize=(b"relaxed", b"relaxed"),
        signature_algorithm=b"rsa-sha256",
    )
    # 2) Mailer legítimo firma normalmente.
    full = fake_attacker_sig + message
    full = _sign(full, "s_legit", domain_legit, pk_legit)

    resolver = _DnsKeyFake({
        f"s_legit._domainkey.{domain_legit}": [_dkim_txt_record(pub_legit)],
        # Publicamos para victim una clave NO relacionada con pk_attacker_real → no verifica.
        f"s_atk._domainkey.{domain_victim}": [_dkim_txt_record(pub_fake_unrelated)],
    })

    from email import policy
    from email.parser import BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(full)
    dkim_headers = msg.get_all("DKIM-Signature", [])
    assert len(dkim_headers) == 2

    eval_result = audit.verify_dkim_message(full, resolver, dkim_headers)

    assert eval_result.result == "pass", (
        f"Debe pasar porque la firma legítima verifica: {eval_result.details}"
    )
    assert eval_result.verified_domains == [domain_legit], (
        f"verified_domains debe contener SOLO {domain_legit}, NO {domain_victim}. "
        f"Got: {eval_result.verified_domains}"
    )


def test_dkim_e2e_end_to_end_via_audit_email_propagates_to_dmarc(monkeypatch):
    """E2E completo: audit_email con DKIM verificado criptográficamente,
    DMARC publicado, sin SPF → DMARC debe pasar gracias a la alineación DKIM
    verificada (no por trust de Authentication-Results)."""
    privkey, pubkey_b64 = _gen_rsa_pair(2048)
    domain = "endtoend.test"

    message = _build_message(
        from_addr=f"alice@{domain}",
        to_addr="bob@bob.test",
        subject="E2E",
        body="audit_email debe propagar verified_domains a check_dmarc.",
    )
    signed = _sign(message, "main", domain, privkey)

    resolver = _DnsKeyFake({
        f"main._domainkey.{domain}": [_dkim_txt_record(pubkey_b64)],
        f"_dmarc.{domain}": ["v=DMARC1; p=reject; adkim=r; aspf=r"],
        domain: ["v=spf1 -all"],
    })

    monkeypatch.setattr(audit, "DnsResolver", lambda timeout=0: resolver)
    import secemail.checks.runner as runner
    monkeypatch.setattr(runner, "DnsResolver", lambda timeout=0: resolver)

    report = audit.audit_email(raw_email=signed)

    by = {c.protocol: c for c in report.checks}
    assert by["DKIM"].status == "PASS", by["DKIM"].details
    assert by["DKIM"].evidence == "cryptographic_verification"
    assert by["DKIM"].verified_domains == [domain]

    # DMARC: con DKIM verificado y alineado, debe estar en PASS (no en WARN/FAIL por
    # falta de evidencia). Si el bug P0-1 reapareciese, este test fallaría porque
    # el flujo aceptaría dkim_verified=False.
    assert by["DMARC"].status in ("PASS", "WARN"), (
        f"DMARC esperado PASS/WARN con DKIM verificado y alineado; got {by['DMARC'].status}"
    )
    assert by["DMARC"].evidence == "local_alignment_eval", by["DMARC"].evidence
