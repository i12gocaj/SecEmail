"""Checks modernos: MTA-STS, TLS-RPT, DANE, BIMI y lookalike/homograph.

Estos checks complementan SPF/DKIM/DMARC y son útiles en auditorías Red Team
para evaluar la exposición real de un dominio a downgrade de TLS, spoofing
visual o suplantación basada en homógrafos IDN.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from ..dns import DnsResolver
from ..models import CheckResult
from ..parsing import (
    add_exact_fix,
    max_status,
    organizational_domain,
    parse_semicolon_tags,
)


# ---------------------------------------------------------------------------
# B1: MTA-STS (RFC 8461)
# ---------------------------------------------------------------------------

_MTA_STS_TXT_RE = re.compile(r"v\s*=\s*STSv1\b", re.IGNORECASE)


def _fetch_mta_sts_policy(domain: str, timeout: float = 5.0) -> Optional[str]:
    """Descarga la policy HTTPS de MTA-STS. None si no es accesible."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:  # nosec
            if resp.status != 200:
                return None
            ctype = resp.headers.get("Content-Type", "")
            if "text" not in ctype and "octet" not in ctype:
                # No bloqueamos por content-type laxo, solo seguimos.
                pass
            data = resp.read(64 * 1024)
            return data.decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ssl.SSLError, OSError):
        return None
    except Exception:
        return None


def _parse_mta_sts_policy(text: str) -> Dict[str, object]:
    """Parsea la policy de MTA-STS: claves version/mode/mx/max_age."""
    out: Dict[str, object] = {"mx": []}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if key == "mx":
            out.setdefault("mx", []).append(val.lower())  # type: ignore[union-attr]
        elif key in {"version", "mode", "max_age"}:
            out[key] = val.lower() if key in {"version", "mode"} else val
    return out


def check_mta_sts(resolver: DnsResolver, domain: str) -> CheckResult:
    check = CheckResult(protocol="MTA-STS", status="INFO")
    if not domain:
        check.details.append("Cannot check MTA-STS without a domain.")
        return check

    txt_host = f"_mta-sts.{domain}".lower()
    txts = resolver.txt(txt_host)
    sts_records = [t for t in txts if _MTA_STS_TXT_RE.search(t)]

    if not sts_records:
        check.status = "INFO"
        check.evidence = "dns_only"
        check.details.append(f"No MTA-STS TXT at {txt_host}.")
        check.recommendations.append(
            f"Publish TXT at {txt_host} with `v=STSv1; id=<timestamp>` and an HTTPS policy at mta-sts.{domain}."
        )
        add_exact_fix(
            check,
            f"DNS TXT -> host: {txt_host} | value: v=STSv1; id=<YYYYMMDDHHMMSS>",
        )
        check.implications.append(
            "Without MTA-STS, a MITM can downgrade to cleartext SMTP for traffic to/from the domain."
        )
        return check

    if len(sts_records) > 1:
        check.status = "WARN"
        check.details.append(f"Multiple MTA-STS TXT records at {txt_host} ({len(sts_records)}).")
        check.recommendations.append("Consolidate MTA-STS TXT records into a single one.")

    tags = parse_semicolon_tags(sts_records[0])
    if not tags.get("id"):
        check.status = max_status(check.status, "WARN")
        check.details.append("MTA-STS TXT without `id=` tag (required to invalidate caches).")

    policy_text = _fetch_mta_sts_policy(domain)
    if policy_text is None:
        check.status = max_status(check.status, "WARN")
        check.evidence = "dns_only"
        check.details.append(
            f"MTA-STS TXT present but HTTPS policy https://mta-sts.{domain}/.well-known/mta-sts.txt is unreachable."
        )
        check.recommendations.append(
            f"Publish the policy at https://mta-sts.{domain}/.well-known/mta-sts.txt with a valid certificate."
        )
        check.implications.append(
            "STS advertised without a reachable policy is equivalent to no STS at many receivers."
        )
        return check

    policy = _parse_mta_sts_policy(policy_text)
    mode = str(policy.get("mode", "")).lower()
    mx_list = policy.get("mx", [])  # type: ignore[assignment]
    check.evidence = "mta_sts_policy_fetched"
    check.details.append(
        f"MTA-STS policy found: mode={mode or '?'}, mx={mx_list}, max_age={policy.get('max_age', '?')}"
    )

    if mode == "enforce":
        check.status = "PASS"
        check.evidence = "mta_sts_enforce"
        check.details.append("MTA-STS in enforce mode; downgrade-resistant.")
    elif mode == "testing":
        check.status = "WARN"
        check.details.append("MTA-STS in testing mode; receivers will not enforce the policy, only report.")
        check.recommendations.append("Once traffic is verified, switch to `mode: enforce`.")
        add_exact_fix(check, f"Edit https://mta-sts.{domain}/.well-known/mta-sts.txt -> `mode: enforce`.")
    elif mode == "none":
        check.status = "WARN"
        check.details.append("MTA-STS with mode=none (no active protection).")
    else:
        check.status = "WARN"
        check.details.append(f"MTA-STS with unknown mode: {mode}.")

    return check


# ---------------------------------------------------------------------------
# B2: TLS-RPT (RFC 8460)
# ---------------------------------------------------------------------------

_TLSRPT_RE = re.compile(r"v\s*=\s*TLSRPTv1\b", re.IGNORECASE)


def check_tls_rpt(resolver: DnsResolver, domain: str) -> CheckResult:
    check = CheckResult(protocol="TLS-RPT", status="INFO")
    if not domain:
        check.details.append("Cannot check TLS-RPT without a domain.")
        return check

    host = f"_smtp._tls.{domain}".lower()
    txts = resolver.txt(host)
    rpt_recs = [t for t in txts if _TLSRPT_RE.search(t)]

    if not rpt_recs:
        check.status = "INFO"
        check.details.append(f"No TLS-RPT TXT at {host}.")
        check.recommendations.append(
            f"Publish `v=TLSRPTv1; rua=mailto:tlsrpt@{domain}` at {host} for visibility into TLS failures."
        )
        add_exact_fix(
            check,
            f"DNS TXT -> host: {host} | value: v=TLSRPTv1; rua=mailto:tlsrpt@{domain}",
        )
        check.implications.append(
            "Without TLS-RPT you will not receive reports of delivery failures or downgrades between your MTA and others."
        )
        return check

    tags = parse_semicolon_tags(rpt_recs[0])
    rua = tags.get("rua")
    if not rua:
        check.status = "WARN"
        check.details.append("TLS-RPT present without `rua=` tag (required).")
        check.recommendations.append("Add `rua=mailto:tlsrpt@your-domain` or `rua=https://...` to the TLS-RPT TXT.")
        return check

    check.status = "PASS"
    check.evidence = "dns_only"
    check.details.append(f"TLS-RPT properly published: rua={rua}")
    return check


# ---------------------------------------------------------------------------
# B3: DANE / TLSA por MX (RFC 7672)
# ---------------------------------------------------------------------------


def check_dane(resolver: DnsResolver, domain: str) -> CheckResult:
    check = CheckResult(protocol="DANE", status="INFO")
    if not domain:
        check.details.append("Cannot check DANE without a domain.")
        return check

    try:
        mx_list = resolver.mx(domain)
    except Exception as exc:
        check.details.append(f"Could not resolve MX for {domain}: {exc}")
        return check

    if not mx_list:
        check.details.append(f"{domain} has no MX; DANE/SMTP does not apply.")
        return check

    with_tlsa: List[Tuple[str, List[Tuple[int, int, int, str]]]] = []
    without_tlsa: List[str] = []

    for pref, mx_host in mx_list:
        name = f"_25._tcp.{mx_host}".lower().rstrip(".")
        try:
            tlsa_records = resolver.tlsa(name)
        except Exception:
            tlsa_records = []
        if tlsa_records:
            with_tlsa.append((mx_host, tlsa_records))
        else:
            without_tlsa.append(mx_host)

    if not with_tlsa:
        check.status = "INFO"
        check.details.append(
            f"DANE not deployed: none of the MX hosts ({', '.join(h for _, h in mx_list)}) has TLSA."
        )
        check.recommendations.append(
            "Consider publishing TLSA `_25._tcp.<mx>` with DNSSEC to authenticate the MX certificate."
        )
        check.implications.append(
            "Without DANE the SMTP client cannot pin the certificate; downgrade to opportunistic TLS."
        )
        return check

    if without_tlsa:
        check.status = "WARN"
        check.evidence = "dns_only"
        labels = [
            f"{h}: " + ", ".join(f"{u}/{s}/{m}" for u, s, m, _ in records)
            for h, records in with_tlsa
        ]
        check.details.append(
            f"DANE deployed partially. With TLSA: {labels}. Without TLSA: {without_tlsa}."
        )
        check.recommendations.append(
            f"Publish TLSA for the MX hosts without DANE ({without_tlsa}) or remove the uncovered MX entries."
        )
        check.implications.append(
            "An attacker may prefer the MX without TLSA to force a downgrade; partial coverage equals successful downgrade."
        )
        return check

    check.status = "PASS"
    check.evidence = "dns_only"
    labels = [
        f"{h}: " + ", ".join(f"{u}/{s}/{m}" for u, s, m, _ in records)
        for h, records in with_tlsa
    ]
    check.details.append(f"DANE deployed on every MX. {labels}")
    return check


# ---------------------------------------------------------------------------
# B4: BIMI (draft-brand-indicators-for-message-identification)
# ---------------------------------------------------------------------------

_BIMI_RE = re.compile(r"v\s*=\s*BIMI1\b", re.IGNORECASE)


def check_bimi(resolver: DnsResolver, domain: str) -> CheckResult:
    check = CheckResult(protocol="BIMI", status="INFO")
    if not domain:
        check.details.append("Cannot check BIMI without a domain.")
        return check

    host = f"default._bimi.{domain}".lower()
    txts = resolver.txt(host)
    recs = [t for t in txts if _BIMI_RE.search(t)]

    if not recs:
        check.status = "INFO"
        check.details.append(f"No BIMI TXT at {host}.")
        check.recommendations.append(
            f"BIMI is optional. To improve brand recognition, publish `v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem` at {host}."
        )
        return check

    tags = parse_semicolon_tags(recs[0])
    l_val = tags.get("l", "")
    a_val = tags.get("a", "")

    check.details.append(f"BIMI found at {host}: l={l_val}, a={a_val or 'no VMC'}.")

    if l_val and not l_val.lower().startswith("https://"):
        check.status = "FAIL"
        check.details.append("BIMI with `l=` not using HTTPS.")
        check.recommendations.append("BIMI requires HTTPS in `l=` to distribute the logo.")
        add_exact_fix(check, f"DNS TXT -> at {host}, change l= to an https:// URL")
        check.implications.append("A logo served over HTTP can be tampered with and receivers will discard it.")
        return check

    if not a_val:
        check.status = "WARN"
        check.details.append("BIMI without `a=` tag (VMC). Many receivers (Gmail, Apple) will not show the logo without a VMC.")
        check.recommendations.append(
            "Obtain a Verified Mark Certificate (VMC) and publish it at an HTTPS URL via the `a=` tag."
        )
        return check

    check.status = "PASS"
    check.details.append("BIMI configured with VMC.")
    return check


# ---------------------------------------------------------------------------
# B6: Lookalike / IDN homograph
# ---------------------------------------------------------------------------

# Substituciones confusables ASCII de alto riesgo (multi-carácter).
_CONFUSABLE_PAIRS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
]

# Sustitución de carácter "fuerte" — sólo dispara findings cuando el carácter
# aparece dentro de un label de marca conocida o presenta forma claramente
# anómala (mayúsculas en medio de minúsculas, dígitos donde no esperarías).
_DIGIT_AS_LETTER = {
    "0": "o",
    "1": "l",
    "5": "s",
}


def _label_has_mixed_case_anomaly(label: str) -> List[str]:
    """Detecta mayúsculas en posiciones sospechosas (paypaI, GitHuB, IBM→lBM).

    Reglas:
    - 'I' como primera o última letra cuando el resto del label es minúsculo
      (paypaI, Ibm, GoogIe).
    - 'I' rodeado de minúsculas (paypaI con otra letra detrás).
    """
    hits: List[str] = []
    if len(label) < 3:
        return hits
    # Localizar 'I' mayúscula y comprobar contexto de minúsculas alrededor.
    for i, ch in enumerate(label):
        if ch != "I":
            continue
        # Resto del label sin la I en cuestión debe ser dominantemente minúscula.
        others = label[:i] + label[i + 1:]
        if not others:
            continue
        # >70% minúsculas alfabéticas
        alphas = [c for c in others if c.isalpha()]
        if not alphas:
            continue
        lower_ratio = sum(1 for c in alphas if c.islower()) / len(alphas)
        if lower_ratio >= 0.7:
            hits.append(
                f"`I` (uppercase) inside `{label}` surrounded by lowercase letters — visually identical to lowercase `l`."
            )
            break
    return hits


def _label_has_digit_as_letter(label: str) -> List[str]:
    """Detecta dígitos en posiciones intermedias parecidos a letras (0→o, 1→l, 5→s)."""
    hits: List[str] = []
    if len(label) < 3:
        return hits
    for i, ch in enumerate(label):
        if ch in _DIGIT_AS_LETTER and 0 < i < len(label) - 1:
            prev_alpha = label[i - 1].isalpha()
            next_alpha = label[i + 1].isalpha()
            if prev_alpha and next_alpha:
                hits.append(
                    f"`{ch}` between letters in `{label}` — visually similar to `{_DIGIT_AS_LETTER[ch]}`."
                )
    return hits


def _confusable_score(label: str) -> List[str]:
    """Heurística pragmática: substituciones sospechosas en un label."""
    hits: List[str] = []
    lower = label.lower()
    # 1) Bigramas ASCII confusables (rn→m, vv→w, cl→d, nn→m).
    for src, target in _CONFUSABLE_PAIRS:
        if src in lower:
            hits.append(f"`{src}` in `{label}` can be confused with `{target}`")
    # 2) Mayúscula 'I' entre minúsculas (paypaI).
    hits.extend(_label_has_mixed_case_anomaly(label))
    # 3) Dígitos entre letras (g00gle, paypa1, c1tibank).
    hits.extend(_label_has_digit_as_letter(label))
    return hits


def _idn_decode(domain: str) -> Tuple[Optional[str], bool]:
    """Devuelve (unicode_form, was_punycode)."""
    if "xn--" not in domain.lower():
        return None, False
    try:
        # Codecs idna intenta IDN A→U.
        unicode_form = domain.encode("ascii").decode("idna")
        return unicode_form, True
    except Exception:
        try:
            import codecs

            unicode_form = codecs.decode(domain.encode("ascii"), "idna")
            return unicode_form, True
        except Exception:
            return None, True


def check_lookalike(domain: str, raw_domain: Optional[str] = None) -> CheckResult:
    """Analiza un dominio en busca de patrones lookalike / IDN-homograph.

    Args:
        domain: Forma normalizada (lowercase) del dominio, usada para chequeos case-insensitive.
        raw_domain: Dominio tal como lo escribió el usuario/cabecera, preservando el case
            original. Esencial para detectar mayúsculas anómalas (`paypaI` con I mayúscula
            que se confunde con `l` minúscula). Si es None, se usa `domain` (sin detección
            de case-mix).
    """
    check = CheckResult(protocol="LOOKALIKE", status="INFO")
    if not domain:
        check.details.append("Cannot analyze lookalike without a domain.")
        return check

    findings: List[str] = []

    unicode_form, was_punycode = _idn_decode(domain)
    if was_punycode and unicode_form:
        findings.append(
            f"Punycode-encoded domain `{domain}` decodes to `{unicode_form}` — check whether it impersonates a legitimate brand."
        )

    # Caracteres Unicode no-ASCII en labels que parecen ASCII (cirílico/griego homograph).
    if raw_domain:
        for label in raw_domain.split("."):
            non_ascii = [c for c in label if ord(c) > 127]
            ascii_alphas = [c for c in label if c.isascii() and c.isalpha()]
            if non_ascii and ascii_alphas:
                # Label mezcla caracteres ASCII con no-ASCII: vector clásico de homograph
                # (а cirílica + resto ASCII).
                findings.append(
                    f"label `{label}` mixes ASCII and non-ASCII characters "
                    f"(possible Cyrillic/Greek homograph): {', '.join(f'U+{ord(c):04X}' for c in non_ascii[:3])}"
                )

    # Aplicar heurísticas a cada label. Usamos raw_domain (preserva case) si está disponible,
    # para que `_label_has_mixed_case_anomaly` pueda detectar I-mayúscula confundible con l.
    domain_for_labels = raw_domain or domain
    for label in domain_for_labels.split("."):
        hits = _confusable_score(label)
        for hit in hits:
            findings.append(f"label `{label}`: {hit}")

    if not findings:
        check.details.append(f"`{domain}` does not contain obvious lookalike / IDN-homograph patterns.")
        return check

    check.status = "WARN"
    check.details.extend(findings)
    check.recommendations.append(
        f"If `{domain}` is not your primary domain, consider defensively registering confusable variants and/or "
        "marking legitimate campaigns with DKIM to distinguish them."
    )
    check.implications.append(
        "Domains visually similar to your brand are the basis for targeted phishing campaigns."
    )
    return check
