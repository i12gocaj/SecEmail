"""Tests del módulo `explain`: traducciones humanas de tecnicismos."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import pytest

from secemail.explain import (
    explain_campaign,
    explain_check,
    explain_smtp_attempt,
    explain_spoof_outcome,
    explain_summary,
)
from secemail.models import AuditReport, CheckResult, SpoofAttempt, SpoofTestResult


# ---------------------------------------------------------------------------
# explain_smtp_attempt
# ---------------------------------------------------------------------------


def test_spamhaus_pbl_rejection_explained():
    msg = "5.7.1 Service unavailable, Client host [83.47.198.55] blocked using Spamhaus"
    human = explain_smtp_attempt(accepted=False, smtp_code=550, message=msg)
    assert human is not None
    assert "lista negra" in human.lower() or "spamhaus" in human.lower()
    assert "relay" in human.lower()


def test_other_blacklist_rejection_explained():
    for bl in ["SORBS", "SpamCop", "Barracuda"]:
        msg = f"550 {bl} blacklist hit"
        human = explain_smtp_attempt(accepted=False, smtp_code=550, message=msg)
        assert human is not None and "blocklist" in human.lower()


def test_generic_rbl_rejection_explained():
    msg = "550 rejected: client blocked using internal RBL"
    human = explain_smtp_attempt(accepted=False, smtp_code=550, message=msg)
    assert human is not None
    assert "blocklist" in human.lower() or "reputable" in human.lower()


def test_spf_fail_explained():
    msg = "550 SPF check failed: sender not authorized"
    human = explain_smtp_attempt(accepted=False, smtp_code=550, message=msg)
    assert human is not None
    assert "spf" in human.lower()


def test_dmarc_reject_explained():
    msg = "550 DMARC reject policy applied for sender domain"
    human = explain_smtp_attempt(accepted=False, smtp_code=550, message=msg)
    assert human is not None
    assert "dmarc" in human.lower()


def test_greylisting_explained():
    human = explain_smtp_attempt(accepted=False, smtp_code=421, message="421 greylisted, try later")
    assert human is not None
    assert "greylisting" in human.lower() or "temporal" in human.lower()


def test_accepted_direct_warns_about_inbox():
    """Aceptación SMTP ≠ llegada a inbox. Debe avisar."""
    human = explain_smtp_attempt(accepted=True, smtp_code=250, message="OK", via_relay=False)
    assert human is not None
    assert "junk" in human.lower() or "spam" in human.lower() or "inbox" in human.lower()


def test_accepted_via_relay_softer_message():
    human = explain_smtp_attempt(accepted=True, smtp_code=250, message="OK", via_relay=True)
    assert human is not None
    assert "relay" in human.lower()


def test_unknown_message_no_specific_explanation_returns_generic_or_none():
    """Mensaje sin patrones conocidos: o devuelve None o algo genérico por código."""
    result = explain_smtp_attempt(accepted=False, smtp_code=550, message="weird text")
    # Acepta None o explicación genérica por código 550.
    assert result is None or "550" in result or "rechazo" in result.lower()


# ---------------------------------------------------------------------------
# explain_check
# ---------------------------------------------------------------------------


def _check(protocol: str, status: str, details: List[str] = None, missing: List[str] = None) -> CheckResult:
    return CheckResult(
        protocol=protocol,
        status=status,
        evidence="dns_only",
        details=details or [],
        missing=missing or [],
    )


def test_dmarc_missing_explained_in_human_terms():
    check = _check("DMARC", "FAIL", details=["No existe registro DMARC efectivo."])
    human = explain_check(check)
    assert human is not None
    assert "dmarc" in human.lower() or "política" in human.lower()


def test_spf_open_all_is_explained_as_useless():
    check = _check("SPF", "FAIL", details=["SPF tiene +all, permite cualquier IP"])
    human = explain_check(check)
    assert human is not None
    assert "cualquier" in human.lower() or "+all" in human.lower()


def test_dkim_rsa_sha1_deprecated_explained():
    check = _check("DKIM", "FAIL", details=["Algoritmo rsa-sha1 deprecated"])
    human = explain_check(check)
    assert human is not None
    assert "rsa-sha1" in human.lower() or "deprecated" in human.lower()


def test_dkim_length_tag_abuse_explained():
    check = _check("DKIM", "FAIL", details=["Tag l= detectado, vulnerable a append abuse"])
    human = explain_check(check)
    assert human is not None
    assert "append" in human.lower() or "l=" in human.lower()


def test_arc_cv_fail_explained_as_forwarding_bypass():
    check = _check("ARC", "FAIL", details=["cv=fail en la última ARC-Seal"])
    human = explain_check(check)
    assert human is not None
    assert "forwarder" in human.lower() or "bypass" in human.lower() or "reenvío" in human.lower()


def test_pass_check_has_short_explanation():
    """Un PASS también debe tener una frase explicando qué significa."""
    for proto in ["SPF", "DKIM", "DMARC", "MTA-STS"]:
        check = _check(proto, "PASS", details=["registro encontrado"])
        human = explain_check(check)
        assert human is not None, f"PASS de {proto} debería tener explicación"


def test_info_arc_without_eml_no_useless_message():
    """ARC INFO cuando no hay .eml: NO añadir explicación (sería ruido)."""
    check = _check("ARC", "INFO", details=["Con solo dirección/dominio no aplica."])
    human = explain_check(check)
    assert human is None


# ---------------------------------------------------------------------------
# explain_summary
# ---------------------------------------------------------------------------


def _report(checks: List[CheckResult]) -> AuditReport:
    return AuditReport(
        from_domain="example.com",
        return_path_domain="example.com",
        envelope_from_domain="example.com",
        checks=checks,
    )


def test_summary_for_unprotected_domain_warns_about_spoofing():
    report = _report([
        _check("DMARC", "FAIL", details=["No existe registro DMARC."]),
        _check("DKIM", "WARN", missing=["selector"]),
    ])
    text = explain_summary(report)
    assert "suplantación" in text.lower() or "spoof" in text.lower()


def test_summary_for_good_config_is_positive():
    report = _report([
        _check("SPF", "PASS"),
        _check("DKIM", "PASS"),
        _check("DMARC", "PASS"),
    ])
    text = explain_summary(report)
    blob = text.lower()
    assert "solid" in blob or "aligned" in blob or "best practice" in blob


# ---------------------------------------------------------------------------
# explain_spoof_outcome
# ---------------------------------------------------------------------------


def test_spoof_outcome_spamhaus_rejection_traced_through():
    """El resumen del envío debe propagar la causa concreta del rechazo (Spamhaus)."""
    attempt = SpoofAttempt(
        mx_host="hotmail-com.olc.protection.outlook.com",
        preference=10,
        accepted=False,
        smtp_code=550,
        message="5.7.1 Service unavailable, Client host [83.47.198.55] blocked using Spamhaus",
        used_starttls=True,
    )
    result = SpoofTestResult(
        mode="send",
        target_email="x@hotmail.com",
        envelope_from="auditor@example.com",
        header_from="auditor@example.com",
        header_to="x@hotmail.com",
        authorized=True,
        dry_run=False,
        status="rejected_by_all_mx",
        mx_hosts=[attempt.mx_host],
        attempts=[attempt],
    )
    human = explain_spoof_outcome(result)
    assert "spamhaus" in human.lower() or "lista negra" in human.lower()
    assert "relay" in human.lower()


def test_spoof_outcome_no_mx_explained():
    result = SpoofTestResult(
        mode="send",
        target_email="x@nonexistent.example",
        envelope_from="a@b.com",
        header_from="a@b.com",
        header_to="x@nonexistent.example",
        authorized=True,
        dry_run=False,
        status="failed_no_mx",
        mx_hosts=[],
        attempts=[],
    )
    human = explain_spoof_outcome(result)
    assert "mx" in human.lower() or "nonexistent.example" in human.lower()


def test_spoof_outcome_accepted_warns_about_inbox():
    attempt = SpoofAttempt(
        mx_host="mx.example.com", preference=10, accepted=True,
        smtp_code=250, message="OK", used_starttls=True,
    )
    result = SpoofTestResult(
        mode="send",
        target_email="x@example.com",
        envelope_from="a@b.com",
        header_from="a@b.com",
        header_to="x@example.com",
        authorized=True,
        dry_run=False,
        status="accepted_by_mx",
        mx_hosts=[attempt.mx_host],
        attempts=[attempt],
    )
    human = explain_spoof_outcome(result)
    assert human is not None
    # Acepta llegada-a-inbox warnings o relay-mention según rama.
    blob = human.lower()
    assert "inbox" in blob or "junk" in blob or "spam" in blob or "relay" in blob


# ---------------------------------------------------------------------------
# explain_campaign: dashboard
# ---------------------------------------------------------------------------


def test_campaign_no_recipients_explains_how_to_start():
    rep = {"totals": {"recipients": 0, "opens": 0, "clicks": 0, "submits": 0,
                       "submits_with_credentials": 0,
                       "open_rate": "0.00%", "click_rate": "0.00%", "submit_rate": "0.00%"}}
    notes = explain_campaign(rep)
    assert notes
    blob = " ".join(notes).lower()
    assert "no data" in blob or "launch" in blob


def test_campaign_high_click_rate_flagged():
    rep = {"totals": {"recipients": 10, "opens": 10, "clicks": 5, "submits": 0,
                       "submits_with_credentials": 0,
                       "open_rate": "100.00%", "click_rate": "50.00%", "submit_rate": "0.00%"}}
    notes = explain_campaign(rep)
    blob = " ".join(notes).lower()
    assert "high" in blob or "very high" in blob


def test_campaign_credentials_warning_when_passwords_captured():
    rep = {"totals": {"recipients": 5, "opens": 5, "clicks": 3, "submits": 2,
                       "submits_with_credentials": 2,
                       "open_rate": "100.00%", "click_rate": "60.00%", "submit_rate": "40.00%"}}
    notes = explain_campaign(rep)
    blob = " ".join(notes).lower()
    assert "credential" in blob
    assert "captures.jsonl" in blob


def test_campaign_clicks_no_submits_is_positive_signal():
    rep = {"totals": {"recipients": 10, "opens": 8, "clicks": 5, "submits": 0,
                       "submits_with_credentials": 0,
                       "open_rate": "80.00%", "click_rate": "50.00%", "submit_rate": "0.00%"}}
    notes = explain_campaign(rep)
    blob = " ".join(notes).lower()
    assert "cautious" in blob or "no submits" in blob or "good sign" in blob
