"""Orquestación: arranca todos los checks contra un .eml o un dominio."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from typing import Optional, Sequence

from ..dns import DnsResolver
from ..models import SCHEMA_VERSION, AuditReport
from ..parsing import (
    domains_align,
    get_domain_from_address,
    get_email_address,
    normalize_domain_or_email,
    parse_authentication_results,
    trusted_auth_items,
)
from .arc import check_arc, check_arc_domain_only
from .dkim import check_dkim, check_dkim_domain, enumerate_dkim_selectors
from .dmarc import check_dmarc
from .modern import check_bimi, check_dane, check_lookalike, check_mta_sts, check_tls_rpt
from .spf import check_spf, evaluate_spf


def _normalize_crlf(raw: bytes) -> tuple[bytes, bool]:
    """Normaliza line endings a CRLF según RFC 5322 §2.1.

    Detecta LF puro o CRLF mixto y reescribe. Devuelve (raw_normalizado, fue_modificado).
    """
    if not raw:
        return raw, False
    has_lf_only = b"\n" in raw and b"\r\n" not in raw
    has_mixed = b"\r\n" in raw and b"\n" in raw.replace(b"\r\n", b"")
    if not has_lf_only and not has_mixed:
        return raw, False
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return normalized, True


def attach_dns_diagnostics(report: AuditReport, resolver: DnsResolver) -> None:
    report.dns_backend = resolver.backend
    report.dns_errors = resolver.errors[:]


def audit_email(
    raw_email: bytes,
    dns_timeout: float = 4.0,
    trusted_authserv_ids: Sequence[str] = (),
    trust_all_auth_results: bool = False,
    source_ip: Optional[str] = None,
    mail_from: Optional[str] = None,
    helo: Optional[str] = None,
    expect_arc: bool = False,
    check_modern: bool = False,
    enumerate_dkim: bool = False,
) -> AuditReport:
    if not raw_email.strip():
        raise ValueError("Email content is empty.")

    # A6: normaliza line endings a CRLF antes de cualquier verificación criptográfica.
    raw_email, crlf_was_normalized = _normalize_crlf(raw_email)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception as exc:
        raise ValueError(f"Could not parse the message/headers: {exc}") from exc

    resolver = DnsResolver(timeout=dns_timeout)

    # A5: detección de From multi-address y captura de Sender / Resent-From.
    from_headers = msg.get_all("From", []) or []
    from_addresses = getaddresses([str(h) for h in from_headers]) if from_headers else []
    multi_from = len(from_addresses) > 1
    sender_addr = get_email_address(msg.get("Sender"))
    sender_domain = get_domain_from_address(msg.get("Sender"))
    resent_from = msg.get("Resent-From")
    resent_from_domain = get_domain_from_address(resent_from) if resent_from else None

    from_domain = get_domain_from_address(msg.get("From"))
    return_path_domain = get_domain_from_address(msg.get("Return-Path"))
    return_path_addr = get_email_address(msg.get("Return-Path"))

    auth_headers = msg.get_all("Authentication-Results", []) or []
    ar_warnings: list = []
    auth_data = parse_authentication_results(
        auth_headers,
        trusted_authserv_ids=trusted_authserv_ids,
        trust_all=trust_all_auth_results,
        warnings_out=ar_warnings,
    )
    if ar_warnings:
        # report aún no existe en este punto; los acumulamos para añadirlos a metadata
        # justo después de construir el AuditReport.
        pass

    envelope_from_domain = None
    envelope_sender = mail_from or return_path_addr
    if envelope_sender:
        envelope_from_domain = get_domain_from_address(envelope_sender)

    for item in trusted_auth_items(auth_data.get("spf", [])):
        value = item.get("smtp.mailfrom")
        if value and "@" in value:
            envelope_sender = value.lower().strip()
            envelope_from_domain = value.rsplit("@", 1)[1].lower().strip().rstrip(".")
            break
    if not envelope_from_domain:
        envelope_from_domain = return_path_domain

    report = AuditReport(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        envelope_from_domain=envelope_from_domain,
        input_mode="eml",
        metadata={
            "schema_version": SCHEMA_VERSION,
            "trusted_authserv_ids": list(trusted_authserv_ids),
            "trust_all_auth_results": trust_all_auth_results,
            "source_ip": source_ip,
            "mail_from": envelope_sender,
            "helo": helo,
        },
    )

    # A6: metadata sobre normalización CRLF.
    if crlf_was_normalized:
        report.metadata["crlf_normalized"] = True
        report.metadata.setdefault("warnings", []).append(
            "Line endings normalized to CRLF before cryptographic verification (DKIM/ARC)."
        )

    # Defensa RFC 8601 §5: warnings de Authentication-Results duplicados/inyectados.
    if ar_warnings:
        report.metadata.setdefault("ar_injection_warnings", []).extend(ar_warnings)
        report.metadata.setdefault("warnings", []).extend(ar_warnings)

    # A5: multi-From detection y captura de Sender / Resent-From.
    if multi_from:
        report.metadata["from_multi"] = [f"{name} <{addr}>" if name else addr for name, addr in from_addresses]
        report.metadata.setdefault("warnings", []).append(
            f"From header contains multiple addresses ({len(from_addresses)}); the first one is used. "
            "Ambiguous behaviour for DMARC; many receivers reject."
        )
    if sender_addr:
        report.metadata["sender"] = sender_addr
    if resent_from_domain:
        report.metadata["resent_from"] = str(resent_from)

    # A5: fallback Sender→DMARC cuando From es multi y Sender está presente.
    effective_dmarc_from_domain = from_domain
    if multi_from and sender_domain:
        effective_dmarc_from_domain = sender_domain
        report.metadata.setdefault("warnings", []).append(
            f"DMARC alignment: multi-address From; Sender ({sender_domain}) "
            "is used as the responsible identity (RFC 5322 §3.6.2)."
        )

    dkim_headers = msg.get_all("DKIM-Signature", []) or []

    spf_check = check_spf(
        resolver,
        envelope_from_domain,
        auth_data,
        envelope_sender=envelope_sender,
        source_ip=source_ip,
        helo=helo,
    )
    report.checks.append(spf_check)

    dkim_check = check_dkim(resolver, dkim_headers, auth_data, raw_email=raw_email)
    report.checks.append(dkim_check)

    # Sólo las firmas que verificaron criptográficamente cuentan para alineación DMARC.
    # Sin esto un atacante puede declarar d=victim.com en una firma falsa y, si cualquier
    # otra firma legítima del mensaje verifica, DMARC saldría PASS falso (P0-1).
    verified_dkim_domains = list(dkim_check.verified_domains)
    dkim_verified_crypto = (
        dkim_check.evidence == "cryptographic_verification" and bool(verified_dkim_domains)
    )

    spf_eval = evaluate_spf(source_ip, envelope_sender, helo)
    report.checks.append(
        check_dmarc(
            resolver,
            effective_dmarc_from_domain,
            auth_data,
            spf_domain=envelope_from_domain,
            spf_result=spf_eval.result if spf_eval else None,
            dkim_domains=verified_dkim_domains,
            dkim_verified=dkim_verified_crypto,
        )
    )
    arc_check = check_arc(
        resolver,
        msg.get_all("ARC-Seal", []) or [],
        msg.get_all("ARC-Message-Signature", []) or [],
        msg.get_all("ARC-Authentication-Results", []) or [],
        auth_data,
        raw_email=raw_email,
    )
    if expect_arc and arc_check.status == "INFO":
        arc_check.status = "WARN"
        arc_check.evidence = "expected_by_user"
        arc_check.details.append("The user enabled --expect-arc for this flow.")
    report.checks.append(arc_check)

    # B6: lookalike sobre el from_domain (siempre, es barato y NO requiere DNS).
    # Preservamos el case original del From: para detectar mayúsculas confusables
    # (I→l) que normalize_domain_or_email habría aplanado.
    if from_domain:
        raw_from = msg.get("From")
        raw_from_domain: Optional[str] = None
        if raw_from:
            try:
                _, raw_addr = parseaddr(str(raw_from))
                if raw_addr and "@" in raw_addr:
                    raw_from_domain = raw_addr.rsplit("@", 1)[1].strip().rstrip(".")
            except Exception:
                raw_from_domain = None
        report.checks.append(check_lookalike(from_domain, raw_domain=raw_from_domain))

    # B1..B4: checks modernos opcionales (requieren --check-modern).
    if check_modern and from_domain:
        report.checks.append(check_mta_sts(resolver, from_domain))
        report.checks.append(check_tls_rpt(resolver, from_domain))
        report.checks.append(check_dane(resolver, from_domain))
        report.checks.append(check_bimi(resolver, from_domain))

    # B5: enumeración de selectores DKIM opcional (--enumerate-dkim).
    if enumerate_dkim and from_domain:
        found = enumerate_dkim_selectors(resolver, from_domain)
        report.metadata["dkim_selectors_found"] = found

    attach_dns_diagnostics(report, resolver)
    return report


def audit_domain(
    email_or_domain: str,
    dkim_selectors: Sequence[str],
    dns_timeout: float = 4.0,
    check_modern: bool = False,
    enumerate_dkim: bool = False,
) -> AuditReport:
    domain = normalize_domain_or_email(email_or_domain)
    resolver = DnsResolver(timeout=dns_timeout)
    empty_auth_data = {"spf": [], "dkim": [], "dmarc": [], "arc": []}

    report = AuditReport(
        from_domain=domain,
        return_path_domain=domain,
        envelope_from_domain=domain,
        input_mode="domain",
        target=email_or_domain,
        metadata={"schema_version": SCHEMA_VERSION},
    )

    report.checks.append(check_spf(resolver, domain, auth_data=empty_auth_data, include_auth_results=False))
    report.checks.append(check_dkim_domain(resolver, domain=domain, selectors=dkim_selectors))
    report.checks.append(
        check_dmarc(
            resolver,
            from_domain=domain,
            auth_data=empty_auth_data,
            include_auth_results=False,
        )
    )
    report.checks.append(check_arc_domain_only())

    # B6: lookalike — siempre activo, no requiere DNS. Preservamos el case
    # original del parámetro `email_or_domain` para detectar I→l y similares.
    raw_domain: Optional[str] = None
    raw_input = (email_or_domain or "").strip().rstrip(".")
    if raw_input:
        if "@" in raw_input:
            try:
                raw_domain = raw_input.rsplit("@", 1)[1].strip().rstrip(".") or None
            except Exception:
                raw_domain = None
        else:
            raw_domain = raw_input
    report.checks.append(check_lookalike(domain, raw_domain=raw_domain))

    # B1..B4: modernos.
    if check_modern:
        report.checks.append(check_mta_sts(resolver, domain))
        report.checks.append(check_tls_rpt(resolver, domain))
        report.checks.append(check_dane(resolver, domain))
        report.checks.append(check_bimi(resolver, domain))

    # B5: enumeración de selectores DKIM.
    if enumerate_dkim:
        found = enumerate_dkim_selectors(resolver, domain)
        report.metadata["dkim_selectors_found"] = found

    attach_dns_diagnostics(report, resolver)
    return report
