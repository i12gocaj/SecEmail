import smtplib

import email_auth_audit as audit


class FakeResolver:
    backend = "fake"
    errors = []

    def __init__(self, txt_records=None, cname_records=None, mx_records=None):
        self.txt_records = txt_records or {}
        self.cname_records = cname_records or {}
        self.mx_records = mx_records or {}

    def txt(self, name):
        return self.txt_records.get(name.lower(), [])

    def cname(self, name):
        return self.cname_records.get(name.lower(), [])

    def mx(self, name):
        return self.mx_records.get(name.lower(), [])


def test_spf_redirect_is_terminal_policy():
    resolver = FakeResolver({"example.com": ["v=spf1 redirect=_spf.example.net"]})

    result = audit.check_spf(
        resolver,
        "example.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )

    assert result.status == "PASS"
    assert "does not define a terminal all" not in " ".join(result.details)


def test_dmarc_subdomain_inherits_parent_sp_policy():
    resolver = FakeResolver(
        {
            "_dmarc.example.com": [
                "v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@example.com"
            ]
        }
    )

    result = audit.check_dmarc(
        resolver,
        "alerts.example.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        include_auth_results=False,
    )

    assert result.status == "PASS"
    assert any("inherited" in detail for detail in result.details)
    assert any("quarantine" in detail for detail in result.details)


def test_authentication_results_are_untrusted_by_default():
    parsed = audit.parse_authentication_results(
        ["attacker.local; spf=pass smtp.mailfrom=evil.example; dkim=pass header.d=evil.example"]
    )

    assert parsed["spf"][0]["trusted"] == "false"
    assert audit.trusted_auth_items(parsed["spf"]) == []


def test_authentication_results_trusted_when_allowed():
    parsed = audit.parse_authentication_results(
        ["mx.example.com; spf=pass smtp.mailfrom=example.com"],
        trusted_authserv_ids=["mx.example.com"],
    )

    assert parsed["spf"][0]["trusted"] == "true"
    assert audit.trusted_auth_items(parsed["spf"])[0]["result"] == "pass"


def test_dkim_dns_key_without_raw_verification_is_not_pass():
    resolver = FakeResolver(
        {
            "s1._domainkey.example.com": [
                "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
            ]
        }
    )

    result = audit.check_dkim(
        resolver,
        ["v=1; a=rsa-sha256; d=example.com; s=s1; bh=fake; b=fake"],
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        raw_email=None,
        include_auth_results=False,
    )

    assert result.status == "WARN"
    assert result.evidence == "dns_key_found_only"


def test_spoof_explicit_dry_run_does_not_open_smtp(monkeypatch):
    """La rama dry-run sigue disponible para tests programáticos vía send_spoof=False.
    Ya NO es el modo por defecto del CLI, pero la API la conserva."""
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("SMTP should not be called in dry-run")

    monkeypatch.setattr(smtplib, "SMTP", fail_if_called)
    result = audit.run_spoof_test(
        target_email="user@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=audit.UIStyle(False),
        spoof_from="ceo@example.com",
        send_spoof=False,  # explícito: pruebas programáticas
        quiet=True,
    )

    assert result.status == "dry_run_ready"
    assert result.attempts == []


def test_spoof_sends_directly_without_tty_guard(monkeypatch):
    """La herramienta ya no pide confirmación TTY. Envía directo — la
    autorización contractual es responsabilidad del operador."""
    resolver = FakeResolver(mx_records={"example.com": [(10, "mx.example.com")]})

    class _FakeSMTP:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self, *a, **kw): return None
        def has_extn(self, name): return False
        def send_message(self, *a, **kw):
            raise smtplib.SMTPException("simulated")

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    result = audit.run_spoof_test(
        target_email="user@example.com",
        spoof_domain="example.com",
        resolver=resolver,
        style=audit.UIStyle(False),
        spoof_from="ceo@example.com",
        quiet=True,
        isatty_fn=lambda: False,  # no-TTY: ya no bloquea
    )

    # Status final es rejected_by_all_mx (porque _FakeSMTP simula fallo),
    # NO blocked_no_interactive_terminal — lo importante es que ya no se bloquea.
    assert result.status == "rejected_by_all_mx"


# ---------------------------------------------------------------------------
# Tests de regresión para los P0 detectados en la auditoría multi-agente.
# ---------------------------------------------------------------------------


def test_p0_4_publicsuffix2_is_mandatory(monkeypatch):
    """P0-4: si publicsuffix2 no está instalado, organizational_domain debe lanzar
    error claro en lugar de caer silenciosamente al heurístico parts[-2:] que rompe
    .co.uk, .com.br, .gov.es."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "publicsuffix2":
            raise ImportError("simulated missing publicsuffix2")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        audit.organizational_domain("example.co.uk")
    except RuntimeError as exc:
        assert "publicsuffix2" in str(exc)
    else:
        raise AssertionError(
            "organizational_domain debió lanzar RuntimeError sin publicsuffix2"
        )


def test_p0_4_publicsuffix2_handles_country_tlds_correctly():
    """P0-4 (positivo): con publicsuffix2 instalado, .co.uk se resuelve bien."""
    assert audit.organizational_domain("mail.example.co.uk") == "example.co.uk"
    assert audit.organizational_domain("sub.example.com.br") == "example.com.br"


def test_p0_2_dnsfunc_filters_vDKIM1_when_multiple_txt():
    """P0-2: dnsfunc debe priorizar el TXT con v=DKIM1 cuando hay varios TXT
    en el mismo nombre (p. ej. un comentario administrativo + la clave real)."""
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": [
                "administrative key — rotated, do not delete",
                "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
            ]
        }
    )
    dnsfunc = audit._make_dkim_dnsfunc(resolver)
    result = dnsfunc(b"s1._domainkey.example.com")
    assert result is not None
    assert b"v=DKIM1" in result
    assert b"administrative" not in result


def test_p0_2_dnsfunc_returns_none_on_empty():
    resolver = FakeResolver(txt_records={})
    dnsfunc = audit._make_dkim_dnsfunc(resolver)
    assert dnsfunc(b"s1._domainkey.nonexistent.example") is None


def test_p0_2_dnsfunc_falls_back_to_single_record_without_v_tag():
    """RFC 6376 §3.6.1: el tag v= es opcional. Debemos aceptar un TXT con p= aunque
    no declare v=DKIM1, para no romper setups antiguos."""
    resolver = FakeResolver(
        txt_records={
            "s1._domainkey.example.com": [
                "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
            ]
        }
    )
    dnsfunc = audit._make_dkim_dnsfunc(resolver)
    result = dnsfunc(b"s1._domainkey.example.com")
    assert result is not None
    assert b"p=MIIBIjAN" in result


def test_p0_1_dmarc_alignment_ignores_unverified_dkim_signature_domains():
    """P0-1: si un atacante declara una DKIM-Signature con d=victim.com pero no
    verifica criptográficamente, su d= NO debe contar para alineación DMARC,
    aunque exista OTRA firma DKIM (de otro dominio) que sí verifique.

    Comprobado a nivel de check_dmarc: solo los d= verificados criptográficamente
    deben pasar a este chequeo. La integración audit_email construye esa lista
    desde dkim_check.verified_domains y NO desde todos los headers."""
    resolver = FakeResolver(
        txt_records={"_dmarc.victim.com": ["v=DMARC1; p=reject; adkim=r; aspf=r"]}
    )

    # Caso A: el atacante mete d=victim.com pero NO lo pasamos como verificado.
    # Aunque haya otro d= verificado (de mailer.legítimo.tld), victim.com no alinea.
    result = audit.check_dmarc(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        spf_domain="bounces.mailer.tld",
        spf_result="pass",
        dkim_domains=["mailer.legitimo.tld"],  # SOLO los verificados criptográficamente
        dkim_verified=True,
        include_auth_results=False,
    )

    # SPF no alinea (bounces.mailer.tld != victim.com en relaxed). DKIM verificado
    # tampoco alinea (mailer.legitimo.tld != victim.com). DMARC debe ser FAIL.
    assert result.status == "FAIL", (
        f"DMARC debió fallar — ninguna identidad verificada alinea con From. "
        f"detalles: {result.details}"
    )


def test_p0_1_dmarc_passes_when_verified_dkim_aligns():
    """P0-1 (caso positivo): si un d= verificado SÍ alinea con From, DMARC pasa."""
    resolver = FakeResolver(
        txt_records={"_dmarc.victim.com": ["v=DMARC1; p=reject"]}
    )

    result = audit.check_dmarc(
        resolver,
        "victim.com",
        {"spf": [], "dkim": [], "dmarc": [], "arc": []},
        spf_domain=None,
        spf_result=None,
        dkim_domains=["victim.com"],  # verificada criptográficamente
        dkim_verified=True,
        include_auth_results=False,
    )

    assert result.status in ("PASS", "WARN"), (
        f"DMARC debió pasar con alineación DKIM verificada. detalles: {result.details}"
    )


def test_main_does_not_double_invoke_spoof(monkeypatch):
    """P1: tras el refactor, main() debe llamar a run_spoof_test exactamente UNA vez
    aunque sea en flujo --spoof-test + --email."""
    call_count = {"n": 0}

    real_run_spoof_test = audit.run_spoof_test

    def counting_spoof(*args, **kwargs):
        call_count["n"] += 1
        return real_run_spoof_test(*args, **kwargs)

    monkeypatch.setattr(audit, "run_spoof_test", counting_spoof)

    # Mock DnsResolver para no hacer red: devuelve dominio "ok".
    class _FakeResolver:
        backend = "fake"
        errors = []

        def __init__(self, timeout=0):
            pass

        def txt(self, name):
            return []

        def cname(self, name):
            return []

        def mx(self, name):
            return [(10, "mx.example.com")]

    monkeypatch.setattr(audit, "DnsResolver", _FakeResolver)

    rc = audit.main([
        "--email", "example.com",
        "--spoof-test", "user@example.com",
        "--spoof-from", "ceo@example.com",
        "--json",
        "--no-color",
        "--no-animate",
        "--dns-timeout", "1",
    ])
    # Una sola invocación, sin importar el exit code (puede ser 1 por checks FAIL).
    assert call_count["n"] == 1, (
        f"main() llamó a run_spoof_test {call_count['n']} veces — debe ser 1"
    )
    assert rc in (0, 1, 2)
