"""Comprobaciones DMARC: resolución de política, alineación SPF/DKIM y enforcement."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple

from ..dns import DnsResolver
from ..models import CheckResult, DmarcPolicy
from ..parsing import (
    add_exact_fix,
    domains_align,
    max_status,
    organizational_domain,
    parse_semicolon_tags,
    select_dmarc_record,
    trusted_auth_items,
)


_DMARC_REPORT_REPORT_RE = re.compile(r"v\s*=\s*DMARC1\b", re.IGNORECASE)


def _extract_rua_ruf_domains(value: str) -> List[str]:
    """Devuelve los dominios destino (sin esquema) de un tag rua/ruf DMARC."""
    out: List[str] = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # mailto:user@domain  o  https://domain/...
        lower = entry.lower()
        if lower.startswith("mailto:"):
            addr = entry[len("mailto:"):].split("!", 1)[0].strip()
            if "@" in addr:
                out.append(addr.rsplit("@", 1)[1].strip().rstrip(".").lower())
        elif lower.startswith("http://") or lower.startswith("https://"):
            try:
                from urllib.parse import urlparse

                host = urlparse(entry).hostname
                if host:
                    out.append(host.lower())
            except Exception:
                pass
    return out


def _verify_external_dmarc_reporter(
    resolver: DnsResolver, from_domain: str, reporter_domain: str
) -> bool:
    """RFC 7489 §7.1: el dominio externo debe publicar
    `<from_domain>._report._dmarc.<reporter>` con v=DMARC1.
    """
    name = f"{from_domain.rstrip('.')}._report._dmarc.{reporter_domain.rstrip('.')}".lower()
    try:
        txt = resolver.txt(name)
    except Exception:
        return False
    return any(_DMARC_REPORT_REPORT_RE.search(t) for t in txt)


def resolve_dmarc_policy(
    resolver: DnsResolver, from_domain: str
) -> Tuple[Optional[DmarcPolicy], List[str]]:
    searched: List[str] = []
    org = organizational_domain(from_domain) or from_domain

    for domain, inherited in ((from_domain, False), (org, True)):
        if inherited and domain == from_domain:
            continue
        host = f"_dmarc.{domain}"
        searched.append(host)
        dmarc_records = select_dmarc_record(resolver.txt(host))
        if len(dmarc_records) != 1:
            if len(dmarc_records) > 1:
                tags = {"__multiple__": str(len(dmarc_records))}
                return (
                    DmarcPolicy(
                        host=host,
                        domain=domain,
                        org_domain=org,
                        record="",
                        tags=tags,
                        inherited=inherited,
                        effective_policy=None,
                    ),
                    searched,
                )
            continue
        record = dmarc_records[0]
        tags = parse_semicolon_tags(record)
        for tag_name in ("p", "sp", "adkim", "aspf"):
            if tag_name in tags:
                tags[tag_name] = tags[tag_name].lower()
        p = tags.get("p")
        effective = tags.get("sp", p) if inherited else p
        return (
            DmarcPolicy(
                host=host,
                domain=domain,
                org_domain=org,
                record=record,
                tags=tags,
                inherited=inherited,
                effective_policy=effective,
            ),
            searched,
        )
    return None, searched


def check_dmarc(
    resolver: DnsResolver,
    from_domain: Optional[str],
    auth_data: Dict[str, List[Dict[str, str]]],
    spf_domain: Optional[str] = None,
    spf_result: Optional[str] = None,
    dkim_domains: Sequence[str] = (),
    dkim_verified: bool = False,
    include_auth_results: bool = True,
) -> CheckResult:
    check = CheckResult(protocol="DMARC", status="PASS")
    if not from_domain:
        check.status = "FAIL"
        check.details.append("Could not extract a domain from the From header.")
        check.missing.append("Valid From header")
        check.recommendations.append("Use a From header with RFC-compliant format and a real domain.")
        add_exact_fix(
            check,
            "Configure the application/MTA to send a valid From header consistent with the corporate domain.",
        )
        check.implications.append(
            "Without a valid From, DMARC alignment is broken and sender identity abuse is enabled."
        )
        return check

    policy, searched = resolve_dmarc_policy(resolver, from_domain)
    if not policy:
        check.status = "FAIL"
        check.details.append(f"No effective DMARC record. Queried: {', '.join(searched)}.")
        check.missing.append(f"TXT _dmarc.{from_domain} or inheritance from the organizational domain")
        check.recommendations.append(
            f"Publish DMARC starting with monitoring mode: \"v=DMARC1; p=none; rua=mailto:dmarc@{organizational_domain(from_domain) or from_domain}\" and escalate with pct after inventory."
        )
        add_exact_fix(
            check,
            f"DNS TXT -> host: _dmarc.{organizational_domain(from_domain) or from_domain} | suggested initial value: v=DMARC1; p=none; rua=mailto:dmarc@{organizational_domain(from_domain) or from_domain}; pct=100",
        )
        check.implications.append(
            "Receivers have no policy to block spoofing of the domain in the From field."
        )
    elif "__multiple__" in policy.tags:
        check.status = "FAIL"
        check.details.append(f"Multiple DMARC records found at {policy.host} ({policy.tags['__multiple__']}).")
        check.missing.append("A single DMARC record")
        check.recommendations.append("Keep a single consolidated DMARC TXT record.")
        add_exact_fix(
            check,
            f"DNS TXT -> remove duplicate DMARC records at {policy.host} and keep a single valid record.",
        )
        check.implications.append(
            "An ambiguous DMARC policy reduces filter effectiveness and opens room for impersonation."
        )
    else:
        tags = policy.tags
        inherited_note = f" inherited from organizational domain {policy.domain}" if policy.inherited else ""
        check.details.append(f"DMARC record found at {policy.host}{inherited_note}: {policy.record}")
        if policy.inherited:
            check.details.append(f"Effective policy for {from_domain}: {policy.effective_policy or 'N/A'} (org={policy.org_domain}).")
        if "__duplicates__" in tags:
            check.status = "FAIL"
            check.details.append(f"DMARC contains duplicated tags: {tags['__duplicates__']}.")
            check.recommendations.append("Remove duplicated tags; receivers may interpret the record inconsistently.")

        if tags.get("v", "").upper() != "DMARC1":
            check.status = "FAIL"
            check.details.append("DMARC v tag is not DMARC1.")
            check.recommendations.append("Set v=DMARC1 as the first tag.")
            add_exact_fix(check, f"DNS TXT -> at {policy.host}, use exactly: v=DMARC1 as the first tag.")
            check.implications.append(
                "An invalid DMARC may be ignored by receivers, leaving the domain exposed to spoofing."
            )

        p = tags.get("p")
        effective_policy = policy.effective_policy
        if not p:
            check.status = "FAIL"
            check.missing.append("p tag in DMARC")
            check.recommendations.append("Add p=none|quarantine|reject in the DMARC record.")
            add_exact_fix(check, f"DNS TXT -> at {policy.host}, add p=none initially and escalate to quarantine/reject after inventory.")
            check.implications.append(
                "Without a p= policy, receivers do not know how to treat spoofed mail."
            )
        elif p not in {"none", "quarantine", "reject"}:
            check.status = "FAIL"
            check.details.append(f"Invalid DMARC policy: p={p}")
            check.recommendations.append("Use p=none, p=quarantine or p=reject.")
            add_exact_fix(
                check,
                f"DNS TXT -> fix p={p} to p=none/quarantine/reject at {policy.host}.",
            )
            check.implications.append(
                "An invalid policy can void DMARC protection against phishing."
            )
        elif effective_policy not in {"none", "quarantine", "reject"}:
            check.status = "FAIL"
            check.details.append(f"Invalid effective DMARC policy: {effective_policy}")
        elif effective_policy == "none" and check.status == "PASS":
            check.status = "WARN"
            check.details.append("Effective DMARC is in monitor mode (p/sp=none).")
            check.recommendations.append("Escalate to quarantine/reject only after inventorying senders and validating reports.")
            add_exact_fix(
                check,
                f"Plan -> review rua for 2-4 weeks, fix unaligned senders and apply progressive pct before quarantine/reject at {policy.host}.",
            )
            check.implications.append(
                "With p=none, spoofed mail can still be delivered even if you detect it in reports."
            )

        if "rua" not in tags and check.status == "PASS":
            check.status = "WARN"
            check.details.append("DMARC does not define rua to receive aggregate reports.")
            check.recommendations.append(f"Add rua=mailto:dmarc@{from_domain} for monitoring.")
            add_exact_fix(check, f"DNS TXT -> at {policy.host}, add rua=mailto:dmarc@{organizational_domain(from_domain) or from_domain}.")
            check.implications.append(
                "Without aggregate reports you have less visibility into abuse attempts and domain spoofing."
            )

        # B7: verificar autorización de destinos externos rua/ruf (RFC 7489 §7.1).
        base_org = organizational_domain(from_domain) or from_domain
        for report_tag in ("rua", "ruf"):
            raw_value = tags.get(report_tag)
            if not raw_value:
                continue
            for rep_domain in _extract_rua_ruf_domains(raw_value):
                rep_org = organizational_domain(rep_domain) or rep_domain
                if rep_org == base_org or rep_domain == from_domain:
                    continue
                authorized = _verify_external_dmarc_reporter(resolver, from_domain, rep_domain)
                if not authorized:
                    check.status = max_status(check.status, "WARN")
                    check.details.append(
                        f"DMARC {report_tag}=...@{rep_domain} points to an external domain without authorization TXT "
                        f"`{from_domain}._report._dmarc.{rep_domain}` (RFC 7489 §7.1)."
                    )
                    check.recommendations.append(
                        f"Ask the external receiver to publish TXT `{from_domain}._report._dmarc.{rep_domain}` "
                        "with `v=DMARC1` to authorize reception, or use a destination within the organizational domain."
                    )
                    add_exact_fix(
                        check,
                        f"DNS TXT -> host: {from_domain}._report._dmarc.{rep_domain} | value: v=DMARC1",
                    )
                    check.implications.append(
                        "Without authorization, RFC-compliant receivers ignore the destination and reports can be hijacked."
                    )

        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()
        spf_aligned = spf_result == "pass" and domains_align(spf_domain, from_domain, aspf)
        dkim_aligned = dkim_verified and any(domains_align(d, from_domain, adkim) for d in dkim_domains)
        if spf_result or dkim_verified:
            if spf_aligned or dkim_aligned:
                check.evidence = "local_alignment_eval"
                check.details.append(
                    f"Local DMARC: valid {'SPF' if spf_aligned else ''}{' and ' if spf_aligned and dkim_aligned else ''}{'DKIM' if dkim_aligned else ''} alignment."
                )
            else:
                check.status = "FAIL"
                check.evidence = "local_alignment_eval"
                check.details.append("Local DMARC: neither SPF nor verified DKIM aligns with the Header From.")
                check.recommendations.append("Align MAIL FROM or DKIM d= with the Header From domain per aspf/adkim.")
                add_exact_fix(
                    check,
                    "Review senders: the visible From domain must align with SPF MAIL FROM or with a verified DKIM signature.",
                )

    if include_auth_results:
        all_dmarc_auth = auth_data.get("dmarc", [])
        dmarc_auth = trusted_auth_items(all_dmarc_auth)
        if dmarc_auth:
            check.evidence = "trusted_authentication_results" if check.evidence == "dns_only" else check.evidence
            results = [x.get("result", "") for x in dmarc_auth]
            if any(r in {"fail", "permerror", "temperror"} for r in results):
                check.status = "FAIL"
                check.details.append(f"Authentication-Results reports invalid DMARC: {', '.join(results)}.")
                check.recommendations.append(
                    "Review domain alignment (header.from vs smtp.mailfrom/header.d) and SPF/DKIM validity."
                )
                add_exact_fix(
                    check,
                    "Ensure DMARC alignment: header.from must align with d= (DKIM) or smtp.mailfrom (SPF).",
                )
                check.implications.append(
                    "Your outbound mail may be rejected and attackers can exploit domain identity confusion."
                )
            elif any(r in {"none"} for r in results) and check.status == "PASS":
                check.status = "WARN"
                check.details.append("Authentication-Results shows DMARC=none.")
                add_exact_fix(
                    check,
                    f"Configure DMARC in enforcement for {from_domain} (p=quarantine/reject).",
                )
                check.implications.append(
                    "Without effective DMARC enforcement the probability of successful phishing with your brand increases."
                )
        else:
            if all_dmarc_auth:
                check.details.append(
                    "Authentication-Results DMARC present, but not used as evidence because it does not match a trusted authserv-id."
                )
            else:
                check.details.append("No DMARC result found in Authentication-Results.")
            if check.status == "PASS" and not spf_result and not dkim_verified:
                check.status = "WARN"
                check.recommendations.append(
                    "Pass --trusted-authserv-id or data for local SPF/DKIM evaluation if you need to validate the message DMARC result."
                )

    return check
