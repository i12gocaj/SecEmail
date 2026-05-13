"""Comprobaciones ARC: estructura de cadena y verificación criptográfica."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..dns import DnsResolver
from ..models import CheckResult, ProtocolEvaluation
from ..parsing import (
    add_exact_fix,
    parse_arc_instances,
    select_dkim_record,
    trusted_auth_items,
)
from .dkim import _make_dkim_dnsfunc, resolve_dkim_key


def verify_arc_message(raw_email: Optional[bytes], resolver: DnsResolver) -> ProtocolEvaluation:
    if not raw_email:
        return ProtocolEvaluation(
            result="not_available",
            evidence="headers_only",
            details=["Without the full raw message ARC cannot be cryptographically verified."],
        )
    try:
        import dkim  # type: ignore
    except Exception:
        return ProtocolEvaluation(
            result="not_available",
            evidence="dependency_missing",
            details=["dkimpy with ARC support is not installed; only ARC structure and DNS keys are validated."],
        )
    if not hasattr(dkim, "arc_verify"):
        return ProtocolEvaluation(
            result="not_available",
            evidence="dependency_missing",
            details=["The installed dkimpy version does not expose arc_verify()."],
        )

    dnsfunc = _make_dkim_dnsfunc(resolver)

    try:
        arc_result = dkim.arc_verify(raw_email, dnsfunc=dnsfunc)
        raw_text = repr(arc_result)
        if isinstance(arc_result, tuple):
            verdict = str(arc_result[0]).lower()
            passed = verdict in {"pass", "cv=pass", "b'pass'"} or arc_result[0] is True
        else:
            passed = bool(arc_result)
        return ProtocolEvaluation(
            result="pass" if passed else "fail",
            evidence="arc_cryptographic_verification",
            details=[f"ARC verified with dkimpy: {raw_text}"],
        )
    except Exception as exc:
        return ProtocolEvaluation(
            result="fail",
            evidence="arc_cryptographic_verification",
            details=[f"ARC could not be cryptographically verified: {exc}"],
        )


def check_arc(
    resolver: DnsResolver,
    arc_seal_headers: Sequence[str],
    arc_msg_headers: Sequence[str],
    arc_auth_headers: Sequence[str],
    auth_data: Dict[str, List[Dict[str, str]]],
    raw_email: Optional[bytes] = None,
    include_auth_results: bool = True,
) -> CheckResult:
    check = CheckResult(protocol="ARC", status="PASS")

    total_arc = len(arc_seal_headers) + len(arc_msg_headers) + len(arc_auth_headers)
    if total_arc == 0:
        check.status = "INFO"
        check.evidence = "not_applicable"
        check.details.append("No ARC headers present. ARC is optional except for forwarding/list flows.")
        check.recommendations.append(
            "Enable --expect-arc in audits of forwarding/list flows if you want to treat ARC absence as a finding."
        )
        add_exact_fix(
            check,
            "Enable ARC on the forwarding gateway/MTA (if applicable) to seal ARC-Seal and ARC-Message-Signature.",
        )
        check.implications.append(
            "Legitimate forwarding can lose authentication and enable phishing that mimics mail chains."
        )
        return check

    seals = parse_arc_instances(arc_seal_headers)
    msgs = parse_arc_instances(arc_msg_headers)
    auths = parse_arc_instances(arc_auth_headers)

    # A4: análisis explícito del tag cv= en cada ARC-Seal según RFC 8617 §4.1.3.
    if seals:
        # Ordenar por instance ascending para localizar la última (mayor i=).
        seals_sorted = sorted([(i, t) for i, t in seals if i > 0], key=lambda x: x[0])
        for i_val, tags in seals_sorted:
            cv = tags.get("cv", "").lower().strip()
            if not cv:
                from ..parsing import max_status as _max_status

                check.status = _max_status(check.status, "WARN")
                check.details.append(
                    f"ARC-Seal i={i_val} missing required cv= tag (RFC 8617 §4.1.3)."
                )
                check.recommendations.append(
                    "Ensure the ARC sealer always emits the cv= tag (none/pass/fail) in ARC-Seal."
                )
                continue
            if cv == "fail":
                # cv=fail en cualquier eslabón rompe la cadena; especialmente grave en la última.
                check.status = "FAIL"
                if seals_sorted and i_val == seals_sorted[-1][0]:
                    check.details.append(
                        f"ARC-Seal i={i_val} (last) reports cv=fail; ARC chain broken. "
                        "Typical signal of manipulated forwarding or DMARC bypass attempt."
                    )
                else:
                    check.details.append(
                        f"ARC-Seal i={i_val} reports cv=fail; ARC chain invalid from that point."
                    )
                check.recommendations.append(
                    "Audit the relay that sealed cv=fail: the chain is no longer trustable and receivers must treat the mail as having no ARC."
                )
                add_exact_fix(
                    check,
                    f"Audit the ARC gateway that emitted i={i_val} with cv=fail; broken signature or post-seal modification.",
                )
                check.implications.append(
                    "cv=fail can be used by an attacker to slip in messages that originally failed DMARC."
                )
            elif cv == "none":
                # Sólo válido en i=1; en instancias posteriores debería ser pass o fail.
                if i_val > 1:
                    from ..parsing import max_status as _max_status

                    check.status = _max_status(check.status, "WARN")
                    check.details.append(
                        f"ARC-Seal i={i_val} with cv=none; only expected in the first instance (i=1)."
                    )
            elif cv == "pass":
                pass  # esperado
            else:
                from ..parsing import max_status as _max_status

                check.status = _max_status(check.status, "WARN")
                check.details.append(f"ARC-Seal i={i_val} with unrecognized cv={cv}.")

    if not (len(seals) == len(msgs) == len(auths)):
        check.status = "FAIL"
        check.details.append(
            f"Inconsistent ARC chain: ARC-Seal={len(seals)}, ARC-Message-Signature={len(msgs)}, ARC-Authentication-Results={len(auths)}."
        )
        check.recommendations.append("Each ARC instance must have exactly those 3 headers.")
        add_exact_fix(
            check,
            "Adjust the gateway to generate, per each i=, exactly: ARC-Authentication-Results, ARC-Message-Signature and ARC-Seal.",
        )
        check.implications.append(
            "A broken ARC chain reduces trust in forwarded mail and may help hide fraud."
        )

    all_instances = sorted({i for i, _ in seals + msgs + auths if i > 0})
    if all_instances:
        expected = list(range(1, max(all_instances) + 1))
        if all_instances != expected:
            check.status = "FAIL"
            check.details.append(f"ARC instances are not consecutive: {all_instances}")
            check.recommendations.append("Ensure consecutive i= values starting at 1.")
            add_exact_fix(check, "Fix i= values so they are consecutive (1,2,3...).")
            check.implications.append(
                "Gaps in the ARC chain hinder history validation and open manipulation opportunities."
            )

    # Validar claves DNS para cada ARC-Seal (d/s)
    for i, tags in seals:
        d = tags.get("d", "").lower()
        s = tags.get("s", "")
        if i < 1 or not d or not s:
            check.status = "FAIL"
            check.details.append(f"ARC-Seal with invalid i/d/s (i={i}, d={d or '-'}, s={s or '-'})")
            check.recommendations.append("Every ARC-Seal must include valid i=, d= and s=.")
            add_exact_fix(check, "Ensure ARC-Seal contains valid i=<instance>, d=<domain>, s=<selector>.")
            check.implications.append(
                "An invalid ARC-Seal prevents chain verification and reduces anti-abuse effectiveness in forwarding."
            )
            continue

        host, txt, cnames = resolve_dkim_key(resolver, s, d)
        dkim_records = select_dkim_record(txt)
        if not txt:
            check.status = "FAIL"
            alias_note = f" (CNAME detected: {', '.join(cnames)})" if cnames else ""
            check.details.append(f"No ARC/DKIM key found at {host}{alias_note}.")
            check.recommendations.append(
                f"Publish the ARC sealing key at {host} with v=DKIM1; p=..."
            )
            add_exact_fix(
                check,
                f"DNS TXT -> host: {host} | value: v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64> for ARC signing.",
            )
            check.implications.append(
                "Without a sealing key, third parties cannot validate the ARC chain and trust in forwarded mail drops."
            )
            continue

        if not dkim_records:
            check.status = "FAIL"
            check.details.append(f"Key found at {host}, but it does not have v=DKIM1.")
            check.recommendations.append(f"Fix the TXT at {host} for ARC (v=DKIM1; p=...).")
            add_exact_fix(check, f"DNS TXT -> edit {host}: use v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64>.")
            check.implications.append(
                "A malformed ARC key invalidates verification and enables abuse in forwarding chains."
            )

    arc_eval = verify_arc_message(raw_email, resolver)
    check.details.extend(arc_eval.details)
    if arc_eval.result == "pass":
        check.evidence = arc_eval.evidence
    elif arc_eval.result == "fail":
        check.status = "FAIL"
        check.evidence = arc_eval.evidence
        check.recommendations.append("Review the full ARC signature; structure and DNS keys are not enough if the chain does not verify cryptographically.")
    elif arc_eval.result == "not_available" and check.status == "PASS":
        check.status = "WARN"
        check.evidence = "arc_structure_only"

    if include_auth_results:
        all_arc_auth = auth_data.get("arc", [])
        arc_auth = trusted_auth_items(all_arc_auth)
        if arc_auth:
            results = [x.get("result", "") for x in arc_auth]
            if any(r in {"fail", "permerror", "temperror"} for r in results):
                check.status = "FAIL"
                check.details.append(f"Authentication-Results reports invalid ARC: {', '.join(results)}.")
                check.recommendations.append("Review the full ARC chain and signatures between forwarding hops.")
                add_exact_fix(
                    check,
                    "Review ARC configuration on the forwarding relay and signature continuity across all hops.",
                )
                check.implications.append(
                    "Failing ARC can cause legitimate forwarded mail to be mistaken for phishing."
                )
            elif any(r in {"none"} for r in results) and check.status == "PASS":
                check.status = "WARN"
                check.details.append("Authentication-Results shows ARC=none.")
                add_exact_fix(check, "If using forwarding/lists, enable ARC at the first hop that forwards messages.")
                check.implications.append(
                    "Without ARC in forwarding flows, authentication traceability between hops decreases."
                )
        elif all_arc_auth:
            check.details.append(
                "Authentication-Results ARC present, but not used as evidence because it does not match a trusted authserv-id."
            )

    return check


def check_arc_domain_only() -> CheckResult:
    check = CheckResult(protocol="ARC", status="INFO", evidence="not_applicable")
    check.details.append("With only an address/domain the ARC chain cannot be validated.")
    check.recommendations.append(
        "To validate ARC you need a real .eml with ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results."
    )
    add_exact_fix(
        check,
        "Export a real .eml from a forwarding flow and run it with --file to validate ARC end-to-end.",
    )
    check.implications.append(
        "You will not detect whether a malicious forwarding chain is altering or hiding authentication."
    )
    return check
