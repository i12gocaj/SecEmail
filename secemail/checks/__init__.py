"""Sub-paquete con los chequeos SPF/DKIM/DMARC/ARC y la orquestación."""

from .arc import check_arc, check_arc_domain_only, verify_arc_message
from .dkim import (
    _make_dkim_dnsfunc,
    check_dkim,
    check_dkim_domain,
    enumerate_dkim_selectors,
    resolve_dkim_key,
    verify_dkim_message,
)
from .dmarc import check_dmarc, resolve_dmarc_policy
from .modern import check_bimi, check_dane, check_lookalike, check_mta_sts, check_tls_rpt
from .runner import attach_dns_diagnostics, audit_domain, audit_email
from .spf import check_spf, evaluate_spf

__all__ = [
    "audit_domain",
    "audit_email",
    "attach_dns_diagnostics",
    "check_arc",
    "check_arc_domain_only",
    "check_bimi",
    "check_dane",
    "check_dkim",
    "check_dkim_domain",
    "check_dmarc",
    "check_lookalike",
    "check_mta_sts",
    "check_spf",
    "check_tls_rpt",
    "enumerate_dkim_selectors",
    "evaluate_spf",
    "resolve_dkim_key",
    "resolve_dmarc_policy",
    "verify_arc_message",
    "verify_dkim_message",
    "_make_dkim_dnsfunc",
]
