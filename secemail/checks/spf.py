"""Comprobaciones SPF y evaluación local con pyspf."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Sequence

from ..dns import DnsResolver
from ..models import CheckResult, ProtocolEvaluation
from ..parsing import (
    SPF_DANGEROUS_MACROS,
    add_exact_fix,
    max_status,
    organizational_domain,
    select_spf_record,
    spf_has_terminal_policy,
    spf_lookup_count,
    spf_lookup_count_recursive,
    spf_tokens,
    trusted_auth_items,
)


def evaluate_spf(
    ip: Optional[str],
    sender: Optional[str],
    helo: Optional[str],
) -> Optional[ProtocolEvaluation]:
    if not ip or not sender:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ProtocolEvaluation(
            result="permerror",
            evidence="invalid_input",
            details=[f"Invalid source IP for local SPF evaluation: {ip}"],
        )
    try:
        import spf  # type: ignore
    except Exception:
        return ProtocolEvaluation(
            result="not_available",
            evidence="dependency_missing",
            details=["pyspf is not installed; SPF will not be evaluated locally."],
        )

    helo_name = helo or sender.rsplit("@", 1)[-1]
    try:
        spf_response = spf.check2(i=ip, s=sender, h=helo_name)
        if len(spf_response) == 2:
            result, text = spf_response
            code = ""
        else:
            result, code, text = spf_response
        return ProtocolEvaluation(
            result=str(result).lower(),
            evidence="local_protocol_eval",
            details=[f"Local SPF via pyspf: result={result}, smtp={code}, detail={text}"],
        )
    except Exception as exc:
        return ProtocolEvaluation(
            result="temperror",
            evidence="local_protocol_eval",
            details=[f"Local SPF evaluation failed: {exc}"],
        )


def check_spf(
    resolver: DnsResolver,
    envelope_domain: Optional[str],
    auth_data: Dict[str, List[Dict[str, str]]],
    envelope_sender: Optional[str] = None,
    source_ip: Optional[str] = None,
    helo: Optional[str] = None,
    include_auth_results: bool = True,
) -> CheckResult:
    check = CheckResult(protocol="SPF", status="PASS")
    if not envelope_domain:
        check.status = "FAIL"
        check.details.append("Could not determine the envelope-from domain (Return-Path/smtp.mailfrom).")
        check.missing.append("Identifiable envelope-from domain")
        check.recommendations.append(
            "Ensure the message includes a valid Return-Path or that Authentication-Results has smtp.mailfrom."
        )
        add_exact_fix(
            check,
            "Configure the MTA to emit a valid Return-Path and align smtp.mailfrom with the sending domain.",
        )
        check.implications.append(
            "Receivers lose traceability of the real sender and the risk of sender impersonation increases."
        )
        return check

    txt = resolver.txt(envelope_domain)
    spf_records = select_spf_record(txt)

    if not spf_records:
        check.status = "FAIL"
        check.details.append(f"No SPF record (v=spf1) found at {envelope_domain}.")
        check.missing.append(f"TXT {envelope_domain} with SPF")
        check.recommendations.append(
            f"Publish a TXT at {envelope_domain}: \"v=spf1 include:your-provider -all\" (adjust includes/IPs to real ones)."
        )
        add_exact_fix(
            check,
            f"DNS TXT -> host: {envelope_domain} | value: v=spf1 include:YOUR_PROVIDER -all | suggested TTL: 3600",
        )
        check.implications.append(
            "An attacker can send forged email using your domain and amplify phishing campaigns."
        )
    elif len(spf_records) > 1:
        check.status = "FAIL"
        check.details.append(f"Multiple SPF records found at {envelope_domain} ({len(spf_records)}).")
        check.missing.append("A single SPF record")
        check.recommendations.append("Consolidate SPF policies into a single v=spf1 TXT record.")
        add_exact_fix(
            check,
            f"DNS TXT -> remove duplicate SPF records at {envelope_domain} and keep a single consolidated v=spf1 record.",
        )
        check.implications.append(
            "SPF validation becomes ambiguous and attackers can exploit interpretation failures."
        )
    else:
        rec = spf_records[0]
        tokens = spf_tokens(rec)
        check.details.append(f"SPF record found at {envelope_domain}: {rec}")

        # Conteo recursivo de DNS lookups RFC 7208 §4.6.4 (A1).
        # Si el walker falla por cualquier motivo, caemos al conteo simple por compatibilidad.
        try:
            recursive = spf_lookup_count_recursive(resolver, envelope_domain)
        except Exception as exc:  # pragma: no cover - defensivo
            recursive = None
            check.details.append(f"Could not compute recursive SPF count: {exc}")

        lookup_count_simple = spf_lookup_count(tokens)

        if recursive is not None:
            total = int(recursive["lookups"])  # type: ignore[arg-type]
            voids = int(recursive["void_lookups"])  # type: ignore[arg-type]
            chain = recursive.get("chain") or []
            macros = recursive.get("macros") or []

            check.details.append(
                f"Recursive SPF DNS lookups: {total} (limit 10). Chain: {' -> '.join(recursive['visited'])}"  # type: ignore[arg-type]
            )

            if recursive["exceeded"]:
                check.status = "FAIL"
                check.details.append(
                    f"SPF exceeds RFC 7208 §4.6.4 limit: {total} > 10 cumulative DNS lookups."
                )
                check.recommendations.append(
                    "Flatten includes, remove unnecessary redirects or consolidate providers."
                )
                add_exact_fix(
                    check,
                    f"DNS TXT -> reduce the SPF of {envelope_domain} to <=10 DNS lookups (including nested includes).",
                )
                check.implications.append(
                    "Receivers will return permerror and all messages may be treated as unauthenticated."
                )

            if recursive["void_exceeded"]:
                check.status = "FAIL"
                check.details.append(
                    f"SPF exceeds void lookups limit RFC 7208 §4.6.4: {voids} > 2."
                )
                check.recommendations.append(
                    "Remove includes/exists pointing to domains without SPF to avoid accumulating void lookups."
                )
                add_exact_fix(
                    check,
                    f"DNS TXT -> at {envelope_domain}, remove broken includes/exists (without SPF) generating void lookups.",
                )

            # A2: macros peligrosas
            import re as _re

            for mdomain, token, macro in macros:  # type: ignore[union-attr]
                # Heurística de severidad: %{i} dentro de exists: que apunta a dominio externo es FAIL.
                token_l = token.lower()
                target = ""
                if ":" in token_l:
                    target = token_l.split(":", 1)[1].split("/", 1)[0]
                elif "=" in token_l:
                    target = token_l.split("=", 1)[1]
                # Quita los macros `%{...}` del target para obtener el sufijo de dominio real.
                target_clean = _re.sub(r"%\{[^}]*\}", "", target).strip(".")
                # Si tras quitar macros queda un dominio con TLD, calculamos org.
                target_org = organizational_domain(target_clean) if "." in target_clean else ""
                base_org = organizational_domain(envelope_domain) or envelope_domain
                exists_external = (
                    token_l.startswith("exists:")
                    and macro in SPF_DANGEROUS_MACROS
                    and target_org
                    and target_org != base_org
                )
                if exists_external:
                    check.status = "FAIL"
                    check.details.append(
                        f"SPF: macro {macro} in `{token}` points to an external domain ({target_org}); "
                        "typical DNS-log exfiltration pattern."
                    )
                    check.recommendations.append(
                        f"Remove the `{token}` mechanism from the SPF of {mdomain}: macros that send envelope data "
                        "to an external domain are an information exfiltration vector."
                    )
                    add_exact_fix(
                        check,
                        f"DNS TXT -> at {mdomain}, remove `{token}` (macro {macro} exfiltrating via DNS).",
                    )
                else:
                    check.status = max_status(check.status, "WARN")
                    check.details.append(
                        f"SPF: macro {macro} detected in `{token}` ({mdomain}). Confirm it is legitimate provider usage."
                    )

            if not recursive["exceeded"] and not recursive["void_exceeded"]:
                # Si la cuenta simple decía >10 pero la recursiva no, lo aclaramos.
                if lookup_count_simple > 10:
                    check.details.append(
                        f"Simple token count reported {lookup_count_simple} but the recursive count ({total}) is the one that applies."
                    )
        elif lookup_count_simple > 10:
            # Fallback al conteo simple
            check.status = "FAIL"
            check.details.append(f"SPF may exceed the 10 DNS lookups limit ({lookup_count_simple} mechanisms detected).")
            check.recommendations.append("Reduce includes/redirect/mx/a/exists to stay under the SPF limit.")
            add_exact_fix(
                check,
                f"DNS TXT -> simplify the SPF of {envelope_domain}; consolidate providers or IPs to <=10 DNS lookups.",
            )
            check.implications.append(
                "Receivers may return permerror and treat legitimate email as unauthenticated."
            )
        if any(token in {"+all", "all"} for token in tokens):
            check.status = "FAIL"
            check.details.append("SPF uses +all and allows any sender.")
            check.recommendations.append("Change +all to -all (or ~all temporarily) to restrict sending.")
            add_exact_fix(
                check,
                f"DNS TXT -> edit {envelope_domain}: replace +all with -all (or ~all temporarily).",
            )
            check.implications.append(
                "Any server can impersonate your domain without being blocked by SPF."
            )
        elif not spf_has_terminal_policy(tokens):
            check.status = max_status(check.status, "WARN")
            check.details.append("SPF does not define a terminal all mechanism.")
            check.recommendations.append("Add -all (recommended) or ~all at the end of the SPF record.")
            add_exact_fix(
                check,
                f"DNS TXT -> edit {envelope_domain}: append '-all' at the end of the SPF record.",
            )
            check.implications.append(
                "Some unauthorized email may bypass filters because no clear closing policy exists."
            )
        if any(token == "ptr" or token.startswith("ptr:") for token in tokens):
            check.status = max_status(check.status, "WARN")
            check.details.append("SPF uses ptr, a discouraged mechanism.")
            check.recommendations.append("Remove ptr and use specific ip4/ip6/include entries.")
            add_exact_fix(
                check,
                f"DNS TXT -> edit {envelope_domain}: remove 'ptr' and use specific 'ip4:', 'ip6:' and 'include:' entries.",
            )
            check.implications.append(
                "Using PTR reduces validation reliability and may facilitate bypass in some scenarios."
            )

    spf_eval = evaluate_spf(source_ip, envelope_sender, helo)
    if spf_eval:
        check.details.extend(spf_eval.details)
        if spf_eval.result == "pass":
            check.evidence = spf_eval.evidence
        elif spf_eval.result in {"fail", "permerror", "temperror"}:
            check.status = "FAIL"
            check.evidence = spf_eval.evidence
            check.recommendations.append("Fix SPF so the audited IP/MAIL FROM obtains a PASS result.")
            add_exact_fix(check, f"Authorize {source_ip} in the SPF of {envelope_domain} or use an aligned authorized MAIL FROM.")
        elif spf_eval.result in {"softfail", "neutral", "none"}:
            check.status = max_status(check.status, "WARN")
            check.evidence = spf_eval.evidence

    if include_auth_results:
        all_spf_auth = auth_data.get("spf", [])
        spf_auth = trusted_auth_items(all_spf_auth)
        if spf_auth:
            check.evidence = "trusted_authentication_results" if check.evidence == "dns_only" else check.evidence
            results = [x.get("result", "") for x in spf_auth]
            if any(r in {"fail", "permerror", "temperror"} for r in results):
                check.status = "FAIL"
                check.details.append(f"Authentication-Results reports invalid SPF: {', '.join(results)}.")
                check.recommendations.append(
                    "Verify sending IPs/include authorizations and that the envelope-from domain matches the real senders."
                )
                add_exact_fix(
                    check,
                    f"Ensure every real sending IP is authorized in the SPF of {envelope_domain}.",
                )
                check.implications.append(
                    "Your legitimate email may be rejected and attackers can gain credibility by spoofing domain variants."
                )
            elif any(r in {"softfail", "neutral", "none"} for r in results) and check.status == "PASS":
                check.status = "WARN"
                check.details.append(f"Authentication-Results SPF is not PASS: {', '.join(results)}.")
                add_exact_fix(
                    check,
                    f"Review the SPF of {envelope_domain} to obtain a PASS result at major receivers.",
                )
                check.implications.append(
                    "Anti-spoofing protection is incomplete and exposure to phishing increases."
                )
        else:
            if all_spf_auth:
                check.details.append(
                    "Authentication-Results SPF present, but not used as evidence because it does not match a trusted authserv-id."
                )
            else:
                check.details.append("No SPF result found in Authentication-Results.")
            if check.status == "PASS" and not source_ip:
                check.status = "WARN"
                check.recommendations.append(
                    "Pass --source-ip and --mail-from, or --trusted-authserv-id, to evaluate the message SPF with higher confidence."
                )

    return check
