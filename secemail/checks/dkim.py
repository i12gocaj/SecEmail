"""Comprobaciones DKIM: DNS de clave + verificación criptográfica con dkimpy."""

from __future__ import annotations

import base64
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ..dns import DnsResolver
from ..models import CheckResult, ProtocolEvaluation
from ..parsing import (
    add_exact_fix,
    parse_semicolon_tags,
    select_dkim_record,
    trusted_auth_items,
)


def _dkim_key_bits(p_value: str) -> Optional[int]:
    """Devuelve el tamaño en bits de una clave pública DKIM ``p=<base64>``.

    Estrategia: 1) cryptography (preferido), 2) dkim.bitsize+parse_public_key,
    3) None si no se puede determinar. Nunca eleva excepciones al caller.
    """
    if not p_value:
        return None
    raw = p_value.strip().replace(" ", "").replace("\t", "")
    try:
        der = base64.b64decode(raw, validate=False)
    except Exception:
        return None
    if not der:
        return None
    # Intento 1: cryptography
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key  # type: ignore

        key = load_der_public_key(der)
        size = getattr(key, "key_size", None)
        if isinstance(size, int) and size > 0:
            return size
    except Exception:
        pass
    # Intento 2: dkimpy
    try:
        import dkim  # type: ignore

        pk = dkim.parse_public_key(der)
        n = None
        if isinstance(pk, dict):
            n = pk.get("modulus") or pk.get("publicExponent")
        else:
            n = getattr(pk, "n", None) or getattr(pk, "modulus", None)
        if n:
            return int(dkim.bitsize(n))
    except Exception:
        pass
    return None


def _analyze_dkim_signature(check: CheckResult, idx: int, raw_sig: str, tags: Dict[str, str]) -> None:
    """A3: detecta atributos peligrosos en el header DKIM-Signature.

    - l= → FAIL (length tag, permite append abuse).
    - a=rsa-sha1 → FAIL (RFC 8301).
    - a= con algoritmo desconocido → WARN.
    """
    a = tags.get("a", "").lower().strip()
    if a.startswith("rsa-sha1"):
        check.status = "FAIL"
        check.details.append(
            f"DKIM-Signature #{idx}: a={a} uses rsa-sha1, deprecated by RFC 8301."
        )
        check.recommendations.append(
            "Reconfigure the signer to use a=rsa-sha256 or a=ed25519-sha256."
        )
        add_exact_fix(check, f"DKIM signing -> replace a={a} with a=rsa-sha256 (minimum) in the signer.")
        check.implications.append(
            "rsa-sha1 is cryptographically broken; modern receivers may mark the signature as invalid."
        )
    elif a and not (a.startswith("rsa-sha256") or a.startswith("ed25519-sha256") or a.startswith("rsa-sha384") or a.startswith("rsa-sha512")):
        from ..parsing import max_status

        check.status = max_status(check.status, "WARN")
        check.details.append(f"DKIM-Signature #{idx}: non-standard algorithm a={a}.")

    if "l" in tags:
        check.status = "FAIL"
        l_val = tags.get("l", "")
        check.details.append(
            f"DKIM-Signature #{idx}: l={l_val} (length) tag present. Enables append abuse."
        )
        check.recommendations.append(
            "Remove the l= tag from the signer configuration: it only covers N body bytes and lets attackers append content without invalidating the signature."
        )
        add_exact_fix(check, "DKIM signing -> drop the l= tag from the signer (cover the full body).")
        check.implications.append(
            "An attacker can append content (HTML/attachments) after the N signed bytes while keeping a valid DKIM signature."
        )


def _analyze_dkim_key_record(check: CheckResult, host: str, tags_key: Dict[str, str]) -> None:
    """A3: detecta problemas en el TXT de la clave DKIM (RFC 6376 §3.6.1).

    - t=y → WARN (testing mode).
    - p= con tamaño < 1024 bits → WARN.
    - k= distinto de rsa o ed25519 → WARN.
    """
    from ..parsing import max_status

    t_flags = tags_key.get("t", "").lower().strip()
    if t_flags and "y" in [flag.strip() for flag in t_flags.split(":")]:
        check.status = max_status(check.status, "WARN")
        check.details.append(
            f"DKIM key {host}: t=y (testing mode); receivers must ignore the signature per RFC 6376 §3.6.1."
        )
        check.recommendations.append(
            f"Remove t=y from the TXT at {host} once the deployment is in production."
        )
        add_exact_fix(check, f"DNS TXT -> at {host}, drop `t=y` to enable the signature in production.")

    k = tags_key.get("k", "rsa").lower().strip()
    if k and k not in {"rsa", "ed25519"}:
        check.status = max_status(check.status, "WARN")
        check.details.append(f"DKIM key {host}: k={k} is neither rsa nor ed25519.")
        check.recommendations.append(
            "Use k=rsa with a >=2048-bit key or k=ed25519 (RFC 8463)."
        )

    p = tags_key.get("p", "")
    if p and k == "rsa":
        bits = _dkim_key_bits(p)
        if bits is None:
            check.details.append(
                f"DKIM key {host}: could not compute key size (install `cryptography` for precise analysis)."
            )
        elif bits < 1024:
            check.status = max_status(check.status, "WARN")
            check.details.append(
                f"DKIM key {host}: weak RSA key ({bits} bits)."
            )
            check.recommendations.append(
                f"Rotate the DKIM key at {host} to at least 2048 bits (recommended 2048-4096)."
            )
            add_exact_fix(check, f"DNS TXT -> regenerate p= at {host} with RSA-2048 and rotate the private key.")
            check.implications.append(
                "Keys below 1024 bits can be factored; an attacker with the private key signs as you."
            )
        elif bits < 2048:
            check.status = max_status(check.status, "WARN")
            check.details.append(
                f"DKIM key {host}: RSA key of {bits} bits; minimum recommended is 2048 bits."
            )


def resolve_dkim_key(resolver: DnsResolver, selector: str, domain: str) -> Tuple[str, List[str], List[str]]:
    name = f"{selector}._domainkey.{domain}".lower()
    txt = resolver.txt(name)
    cnames: List[str] = []

    if not txt:
        cnames = resolver.cname(name)
        for alias in cnames:
            txt = resolver.txt(alias)
            if txt:
                break

    return name, txt, cnames


def _make_dkim_dnsfunc(resolver: DnsResolver):
    """Devuelve callback dnsfunc(name, timeout) -> bytes|None que filtra TXTs por v=DKIM1.

    Si hay varios TXT en el mismo nombre (comentarios + clave, rotación, etc.),
    selecciona el que parezca una clave DKIM real para evitar que dkimpy reciba basura.
    """
    def dnsfunc(name: bytes, timeout: int = 5) -> Optional[bytes]:
        raw_name = name.decode("ascii", errors="ignore") if isinstance(name, bytes) else str(name)
        query = raw_name.rstrip(".").lower()
        records = resolver.txt(query)
        if not records:
            return None
        # Prioridad 1: TXT con v=DKIM1 explícito (RFC 6376 §3.6.1).
        for r in records:
            if re.match(r"^\s*v\s*=\s*dkim1\b", r, re.IGNORECASE):
                return r.encode("utf-8")
        # Prioridad 2: TXT sin tag v= pero con p= (válido por RFC, v= es opcional).
        for r in records:
            if "p=" in r.lower() and not re.match(r"^\s*v\s*=", r, re.IGNORECASE):
                return r.encode("utf-8")
        # Fallback: primer registro tal cual (compat con setups no estándar).
        return records[0].encode("utf-8")
    return dnsfunc


def verify_dkim_message(
    raw_email: Optional[bytes],
    resolver: DnsResolver,
    dkim_headers: Sequence[str],
) -> ProtocolEvaluation:
    if not raw_email:
        return ProtocolEvaluation(
            result="not_available",
            evidence="headers_only",
            details=["Without the full raw message DKIM cannot be cryptographically verified."],
        )
    signature_count = len(dkim_headers)
    if signature_count < 1:
        return ProtocolEvaluation(result="none", evidence="raw_email", details=[])
    try:
        import dkim  # type: ignore
    except Exception:
        return ProtocolEvaluation(
            result="not_available",
            evidence="dependency_missing",
            details=["dkimpy is not installed; only DNS selector/key presence is validated."],
        )

    dnsfunc = _make_dkim_dnsfunc(resolver)

    verified_domains: List[str] = []
    errors: List[str] = []
    try:
        dkim_obj = dkim.DKIM(raw_email)
        for idx in range(signature_count):
            try:
                if dkim_obj.verify(idx=idx, dnsfunc=dnsfunc):
                    sig_d = parse_semicolon_tags(str(dkim_headers[idx])).get("d", "").lower().strip()
                    # Dedup: si el mismo `d=` aparece en varias firmas verificadas
                    # (rotación de selector durante migración), no duplicar.
                    if sig_d and sig_d not in verified_domains:
                        verified_domains.append(sig_d)
            except TypeError:
                # dkimpy antigua sin idx=: solo permite verificar la primera firma.
                # NO aceptamos "alguna firma vale" — abortar y reportar honestamente.
                errors.append(
                    "Installed dkimpy version does not support per-index verification; "
                    "cannot bind verified signature to its d= in multi-signature messages."
                )
                break
            except Exception as exc:
                errors.append(f"signature #{idx + 1}: {exc}")
    except Exception as exc:
        errors.append(str(exc))

    if verified_domains:
        details = [
            f"DKIM cryptographically verified with dkimpy. "
            f"Verified signing domains: {', '.join(verified_domains)}."
        ]
        if errors:
            details.append("Some signatures did not verify: " + "; ".join(errors[:3]))
        return ProtocolEvaluation(
            result="pass",
            evidence="cryptographic_verification",
            details=details,
            verified_domains=verified_domains,
        )

    details = ["No DKIM signature could be cryptographically verified."]
    if errors:
        details.append("DKIM errors: " + "; ".join(errors[:3]))
    return ProtocolEvaluation(result="fail", evidence="cryptographic_verification", details=details)


def check_dkim(
    resolver: DnsResolver,
    dkim_headers: Sequence[str],
    auth_data: Dict[str, List[Dict[str, str]]],
    raw_email: Optional[bytes] = None,
    include_auth_results: bool = True,
) -> CheckResult:
    check = CheckResult(protocol="DKIM", status="PASS")
    if not dkim_headers:
        check.status = "FAIL"
        check.details.append("No DKIM-Signature header found in the message.")
        check.missing.append("Outbound DKIM signature")
        check.recommendations.append("Configure your server/provider to sign outbound mail with DKIM.")
        add_exact_fix(
            check,
            "Enable DKIM signing in your mail provider and publish the DNS selector provided by the vendor.",
        )
        check.implications.append(
            "Without DKIM it is easier to impersonate or tamper with messages appearing to come from your domain."
        )

        dkim_auth = trusted_auth_items(auth_data.get("dkim", []))
        if dkim_auth and any(x.get("result") in {"none", "fail"} for x in dkim_auth):
            check.details.append("Authentication-Results confirms DKIM is absent or failing.")
        return check

    for idx, raw_sig in enumerate(dkim_headers, start=1):
        tags = parse_semicolon_tags(raw_sig)
        d = tags.get("d", "").lower().strip()
        s = tags.get("s", "").strip()
        if not d or not s:
            check.status = "FAIL"
            check.details.append(f"DKIM-Signature #{idx} is missing d= or s=.")
            check.missing.append("d= and s= tags in DKIM-Signature")
            add_exact_fix(check, "Fix the DKIM signer to include d=<domain> and s=<selector>.")
            check.implications.append(
                "An incomplete DKIM signature invalidates authentication and enables email fraud."
            )
            continue

        # A3: análisis de atributos peligrosos de la firma.
        _analyze_dkim_signature(check, idx, str(raw_sig), tags)

        host, txt, cnames = resolve_dkim_key(resolver, s, d)
        dkim_records = select_dkim_record(txt)

        if not txt:
            check.status = "FAIL"
            alias_note = f" (CNAME detected: {', '.join(cnames)})" if cnames else ""
            check.details.append(f"No TXT record found for the DKIM key at {host}{alias_note}.")
            check.missing.append(f"DKIM TXT at {host}")
            check.recommendations.append(
                f"Publish the DKIM public key at {host} (or a correct CNAME) in the form v=DKIM1; p=..."
            )
            add_exact_fix(
                check,
                f"DNS TXT -> host: {host} | value: v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64> | suggested TTL: 3600",
            )
            check.implications.append(
                "Without a valid public key, receivers cannot verify message integrity/authenticity."
            )
            continue

        if not dkim_records:
            check.status = "FAIL"
            check.details.append(f"TXT found at {host}, but it does not contain v=DKIM1.")
            check.recommendations.append(f"Fix the TXT at {host} to include v=DKIM1; p=<public key>.")
            add_exact_fix(check, f"DNS TXT -> edit {host}: use 'v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64>'.")
            check.implications.append(
                "A malformed DKIM record is ignored and leaves the door open for impersonation."
            )
            continue

        key_rec = dkim_records[0]
        tags_key = parse_semicolon_tags(key_rec)
        p = tags_key.get("p", "")
        check.details.append(f"DKIM key located for {d} (selector={s}).")

        # A3: análisis de la clave DNS (t=y, k=, bits).
        _analyze_dkim_key_record(check, host, tags_key)

        if not p:
            check.status = "FAIL"
            check.details.append(f"The DKIM key at {host} has no valid p=.")
            check.missing.append(f"p=<public key> at {host}")
            check.recommendations.append(f"Publish a non-empty public key at {host}.")
            add_exact_fix(check, f"DNS TXT -> at {host}, set a non-empty p=<PUBLIC_KEY_BASE64>.")
            check.implications.append(
                "Without a usable DKIM key there is no cryptographic verification of messages."
            )

    dkim_eval = verify_dkim_message(raw_email, resolver, dkim_headers)
    check.details.extend(dkim_eval.details)
    check.verified_domains = list(dkim_eval.verified_domains)
    if dkim_eval.result == "pass":
        check.evidence = dkim_eval.evidence
    elif dkim_eval.result == "fail":
        check.status = "FAIL"
        check.evidence = dkim_eval.evidence
        check.recommendations.append("Verify that the DKIM signature covers the received message and that the DNS key matches the active private key.")
        add_exact_fix(check, "Regenerate/fix DKIM: correct DNS selector, matching private key, and a message unmodified after signing.")
        check.implications.append(
            "An existing DNS key does not prove authenticity; without actual DKIM verification the message may be forged or altered."
        )
    elif dkim_eval.result == "not_available" and check.status == "PASS":
        check.status = "WARN"
        check.evidence = "dns_key_found_only"
        check.details.append("The DNS key exists, but that does not equate to a valid DKIM signature.")

    if include_auth_results:
        all_dkim_auth = auth_data.get("dkim", [])
        dkim_auth = trusted_auth_items(all_dkim_auth)
        if dkim_auth:
            check.evidence = "trusted_authentication_results" if check.evidence == "dns_only" else check.evidence
            results = [x.get("result", "") for x in dkim_auth]
            if any(r in {"fail", "permerror", "temperror"} for r in results):
                check.status = "FAIL"
                check.details.append(f"Authentication-Results reports invalid DKIM: {', '.join(results)}.")
                check.recommendations.append(
                    "Review key rotation, active selector, canonicalization and consistency between private/public keys."
                )
                add_exact_fix(
                    check,
                    "Validate that the active selector in the signature exists in DNS and matches the private key in use.",
                )
                check.implications.append(
                    "Messages may arrive without cryptographic trust and be more vulnerable to tampering."
                )
            elif any(r in {"none"} for r in results) and check.status == "PASS":
                check.status = "WARN"
                check.details.append("Authentication-Results shows DKIM=none.")
                add_exact_fix(
                    check,
                    "Enable DKIM signing across every outbound flow (applications, relays and external providers).",
                )
                check.implications.append(
                    "Without effective DKIM, DMARC relies more on SPF and impersonation risk increases."
                )
        elif all_dkim_auth:
            check.details.append(
                "Authentication-Results DKIM present, but not used as evidence because it does not match a trusted authserv-id."
            )

    return check


def check_dkim_domain(
    resolver: DnsResolver,
    domain: str,
    selectors: Sequence[str],
) -> CheckResult:
    check = CheckResult(protocol="DKIM", status="WARN")
    clean_selectors = [s.strip().lower() for s in selectors if s and s.strip()]

    if not clean_selectors:
        check.details.append("Without headers, a real DKIM signature (d=/s=) cannot be validated.")
        check.missing.append("DKIM selector")
        check.recommendations.append(
            "Pass one or more --dkim-selector values to validate key DNS, or use a real .eml to validate the signature."
        )
        add_exact_fix(
            check,
            "Run: --dkim-selector <real_selector> for each active selector (e.g.: default, s1, google, selector1).",
        )
        check.implications.append(
            "Without validating DKIM you cannot know whether an attacker could forge legitimate-looking email."
        )
        return check

    check.status = "PASS"
    for selector in clean_selectors:
        host, txt, cnames = resolve_dkim_key(resolver, selector, domain)
        dkim_records = select_dkim_record(txt)
        if not txt:
            check.status = "FAIL"
            alias_note = f" (CNAME detected: {', '.join(cnames)})" if cnames else ""
            check.details.append(f"No DKIM TXT found for selector '{selector}' at {host}{alias_note}.")
            check.missing.append(f"DKIM TXT at {host}")
            check.recommendations.append(
                f"Publish the DKIM key for '{selector}' at {host} in the form v=DKIM1; p=<public key>."
            )
            add_exact_fix(
                check,
                f"DNS TXT -> host: {host} | value: v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64>.",
            )
            check.implications.append(
                "An attacker can exploit the absence of effective DKIM to impersonate domain communications."
            )
            continue

        if not dkim_records:
            check.status = "FAIL"
            check.details.append(f"TXT exists at {host}, but it does not contain v=DKIM1.")
            check.recommendations.append(f"Fix the TXT at {host} for DKIM (v=DKIM1; p=<public key>).")
            add_exact_fix(check, f"DNS TXT -> edit {host}: use v=DKIM1; k=rsa; p=<PUBLIC_KEY_BASE64>.")
            check.implications.append(
                "A malformed DKIM record leaves messages without reliable cryptographic validation."
            )
            continue

        tags = parse_semicolon_tags(dkim_records[0])
        if not tags.get("p", ""):
            check.status = "FAIL"
            check.details.append(f"The DKIM key at {host} has no valid p=.")
            check.missing.append(f"p=<public key> at {host}")
            check.recommendations.append(f"Publish a non-empty public key at {host}.")
            add_exact_fix(check, f"DNS TXT -> at {host}, set a non-empty p=<PUBLIC_KEY_BASE64>.")
            check.implications.append(
                "Without a valid public key, the DKIM signature provides no protection against tampering or spoofing."
            )
            continue

        check.details.append(f"Valid DKIM key found for selector '{selector}' at {host}.")

    return check


# B5: enumeración de selectores comunes ----------------------------------------

COMMON_DKIM_SELECTORS: Tuple[str, ...] = (
    "selector1", "selector2", "google", "k1", "k2", "mxvault", "smtpapi",
    "mandrill", "mailchimp", "mailgun", "mail", "m1", "dkim", "default",
    "s1", "s2", "fd", "sm", "scph0921", "hubspot", "marketo", "sendgrid",
    "sparkpost", "postmark", "klaviyo", "intercom", "zendesk",
)


def enumerate_dkim_selectors(
    resolver: DnsResolver,
    domain: str,
    selectors_list: Optional[Sequence[str]] = None,
) -> List[Dict[str, object]]:
    """Enumera selectores DKIM comunes y devuelve los que existen.

    Cada entrada: {selector, host, record, k, t, bits, p_truncated}.
    """
    selectors = list(selectors_list) if selectors_list else list(COMMON_DKIM_SELECTORS)
    found: List[Dict[str, object]] = []
    for selector in selectors:
        try:
            host, txt, _cnames = resolve_dkim_key(resolver, selector, domain)
        except Exception:
            continue
        records = select_dkim_record(txt)
        if not records and txt:
            # Permite formatos sin v= tag (legacy)
            records = [r for r in txt if "p=" in r.lower()]
        if not records:
            continue
        tags_key = parse_semicolon_tags(records[0])
        p = tags_key.get("p", "")
        bits = _dkim_key_bits(p) if p else None
        found.append({
            "selector": selector,
            "host": host,
            "record": records[0],
            "k": tags_key.get("k", "rsa"),
            "t": tags_key.get("t", ""),
            "bits": bits,
            "p_truncated": (p[:32] + "...") if len(p) > 32 else p,
        })
    return found
