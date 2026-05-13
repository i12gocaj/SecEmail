"""Compat shim: el código vive en el paquete `secemail`.

Mantiene el entry-point histórico ``python3 email_auth_audit.py`` y la API que
los tests existentes consumen (``import email_auth_audit as audit``). Toda
lógica nueva debe ir directamente al paquete.
"""

from __future__ import annotations

from typing import Optional, Sequence

from secemail import cli as _cli
from secemail.checks import (
    audit_domain,
    audit_email,
    check_arc,
    check_arc_domain_only,
    check_bimi,
    check_dane,
    check_dkim,
    check_dkim_domain,
    check_dmarc,
    check_lookalike,
    check_mta_sts,
    check_spf,
    check_tls_rpt,
    enumerate_dkim_selectors,
)
from secemail.checks.arc import verify_arc_message
from secemail.checks.dkim import (
    _make_dkim_dnsfunc,
    resolve_dkim_key,
    verify_dkim_message,
)
from secemail.checks.dmarc import resolve_dmarc_policy
from secemail.checks.modern import (
    _fetch_mta_sts_policy,
    _idn_decode,
    _parse_mta_sts_policy,
)
from secemail.checks.spf import evaluate_spf
from secemail.dns import DnsResolver, DnsResolverError
from secemail.models import (
    AuditReport,
    CheckResult,
    DmarcPolicy,
    ProtocolEvaluation,
    SpoofAttempt,
    SpoofTestResult,
)
from secemail.parsing import (
    DKIM_RE,
    DMARC_RE,
    DOMAIN_RE,
    EMAIL_RE,
    SPF_RE,
    _authserv_matches,
    _strip_rfc5322_comments,
    domains_align,
    get_domain_from_address,
    get_email_address,
    is_valid_domain,
    max_status,
    normalize_domain_or_email,
    organizational_domain,
    parse_arc_instances,
    parse_authentication_results,
    parse_authserv_id,
    parse_semicolon_tags,
    select_dkim_record,
    select_dmarc_record,
    select_spf_record,
    spf_has_terminal_policy,
    spf_lookup_count,
    spf_lookup_count_recursive,
    spf_tokens,
    trusted_auth_items,
    validate_email,
)
from secemail.spoof import domain_allowed, render_spoof_result, run_spoof_test
from secemail.ui import Spinner, UIStyle, render_text


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Punto de entrada del CLI vía el shim.

    Propaga el estado de este módulo (que es donde los tests monkeypatchean
    ``DnsResolver`` y ``run_spoof_test``) al módulo ``secemail.cli`` antes de
    delegar, y lo restaura al terminar para no contaminar invocaciones
    posteriores.
    """
    _saved = (_cli.DnsResolver, _cli.run_spoof_test)
    _cli.DnsResolver = DnsResolver
    _cli.run_spoof_test = run_spoof_test
    try:
        return _cli.main(argv)
    finally:
        _cli.DnsResolver, _cli.run_spoof_test = _saved


if __name__ == "__main__":
    raise SystemExit(main())
