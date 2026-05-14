"""Header parsing, DNS record parsing, and domain helpers."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Dict, List, Optional, Sequence, Tuple

from .models import STATUS_ORDER, CheckResult


SPF_RE = re.compile(r"^v=spf1\b", re.IGNORECASE)
DMARC_RE = re.compile(r"^v=dmarc1\b", re.IGNORECASE)
DKIM_RE = re.compile(r"^v=dkim1\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")
SPF_DNS_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def unique_preserve_order(values: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def get_domain_from_address(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    _, addr = parseaddr(value)
    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return domain or None


def get_email_address(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    _, addr = parseaddr(value)
    addr = addr.strip().lower()
    if not EMAIL_RE.match(addr):
        return None
    return addr


def normalize_domain_or_email(value: str) -> str:
    candidate = (value or "").strip().lower().rstrip(".")
    if not candidate:
        raise ValueError("--email option is empty.")

    if "@" in candidate:
        domain = get_domain_from_address(candidate)
        if not domain:
            raise ValueError(f"Invalid email address: {value}")
        return domain

    if DOMAIN_RE.match(candidate):
        return candidate

    raise ValueError(f"Invalid format for --email/--domain: {value}")


def validate_email(value: str, field_name: str) -> str:
    addr = get_email_address(value)
    if not addr:
        raise ValueError(f"{field_name} must be a valid email address: {value}")
    return addr


def is_valid_domain(value: Optional[str]) -> bool:
    return bool(value and DOMAIN_RE.match(value))


def organizational_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    clean = domain.lower().strip().rstrip(".")
    if not is_valid_domain(clean):
        return clean
    try:
        from publicsuffix2 import get_sld  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "publicsuffix2 is a required dependency to compute the organizational domain "
            "used for DMARC fallback and alignment. Install with: "
            "pip install -r requirements.txt"
        ) from exc

    org = get_sld(clean)
    if org:
        return org.lower().rstrip(".")
    return clean


def domains_align(child: Optional[str], parent: Optional[str], mode: str = "r") -> bool:
    if not child or not parent:
        return False
    child = child.lower().strip().rstrip(".")
    parent = parent.lower().strip().rstrip(".")
    if mode == "s":
        return child == parent
    return organizational_domain(child) == organizational_domain(parent)


def max_status(current: str, candidate: str) -> str:
    return candidate if STATUS_ORDER.get(candidate, 0) > STATUS_ORDER.get(current, 0) else current


def parse_semicolon_tags(value: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    duplicates: List[str] = []
    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        clean_key = key.strip().lower()
        if clean_key in tags:
            duplicates.append(clean_key)
        tags[clean_key] = val.strip()
    if duplicates:
        tags["__duplicates__"] = ",".join(unique_preserve_order(duplicates))
    return tags


def add_exact_fix(check: CheckResult, value: str) -> None:
    if value and value not in check.exact_fixes:
        check.exact_fixes.append(value)


def _strip_rfc5322_comments(text: str) -> str:
    """Elimina comentarios entre paréntesis (con anidamiento) según RFC 5322 §3.2.2.

    Necesario para que `Authentication-Results: (verified by foo) mx.google.com;`
    no produzca `(verified` como authserv-id.
    """
    out: List[str] = []
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            # Quoted-pair: si estamos fuera de comentario, conservar ambos.
            if depth == 0:
                out.append(ch)
                out.append(text[i + 1])
            i += 2
            continue
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            i += 1
            continue
        if depth == 0:
            out.append(ch)
        i += 1
    return "".join(out)


def parse_authserv_id(header_text: str) -> str:
    """Extrae el authserv-id de un header Authentication-Results.

    Ignora comentarios RFC 5322 entre paréntesis y se queda con el primer
    token significativo antes del primer `;`.
    """
    cleaned = _strip_rfc5322_comments(header_text)
    first = cleaned.split(";", 1)[0].strip()
    if not first:
        return ""
    token = first.split()[0]
    return token.lower().rstrip(";")


def _authserv_matches(authserv_id: str, trusted_entry: str) -> bool:
    """Match exacto o por sufijo de dominio (RFC 8601 §2).

    `google.com` matchea `mx.google.com` y `mx1.google.com`, pero NUNCA
    `evil-google.com` (debe haber un `.` separador).
    """
    if not authserv_id or not trusted_entry:
        return False
    if authserv_id == trusted_entry:
        return True
    suffix = "." + trusted_entry
    return authserv_id.endswith(suffix)


def parse_authentication_results(
    headers: Sequence[str],
    trusted_authserv_ids: Sequence[str] = (),
    trust_all: bool = False,
    warnings_out: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, str]]]:
    """Parsea cabeceras Authentication-Results, marcando trust por authserv-id.

    Aplica RFC 8601 §4.1 / §5: cuando varios AR comparten un mismo ``authserv_id``,
    el PRIMERO en el header chain (más alto en la cabecera RFC 5322) es el que añadió
    el MTA receptor; los duplicados subsiguientes son sospechosos de inyección y se
    degradan a ``trusted="false"`` aunque el authserv-id coincida con la allowlist.

    Si ``warnings_out`` se pasa, se añaden mensajes describiendo los duplicados
    detectados (para que el caller los meta en ``report.metadata["warnings"]``).
    """
    out: Dict[str, List[Dict[str, str]]] = {
        "spf": [],
        "dkim": [],
        "dmarc": [],
        "arc": [],
    }
    trusted = {x.lower().strip().rstrip(";") for x in trusted_authserv_ids if x and x.strip()}

    # Conjunto de (authserv_id, proto) ya vistos para un mismo AR confiable.
    # Si un segundo header con el mismo authserv_id intenta añadir otro item del
    # mismo proto, lo degradamos a untrusted y registramos warning.
    seen_trusted_pairs: set = set()

    for header_idx, header in enumerate(headers):
        header_text = str(header)
        authserv_id = parse_authserv_id(header_text)
        if trust_all:
            authserv_trusted = True
        elif trusted:
            authserv_trusted = any(_authserv_matches(authserv_id, t) for t in trusted)
        else:
            authserv_trusted = False
        for proto in ("spf", "dkim", "dmarc", "arc"):
            for m in re.finditer(rf"\b{proto}=([a-z_]+)", header_text, flags=re.IGNORECASE):
                # Aplicar RFC 8601 §5: si ya hay un item trusted con este
                # (authserv_id, proto), el actual es sospechoso de inyección.
                is_trusted = authserv_trusted
                if authserv_trusted:
                    key = (authserv_id, proto)
                    if key in seen_trusted_pairs:
                        is_trusted = False
                        if warnings_out is not None:
                            warnings_out.append(
                                f"Authentication-Results duplicated with authserv_id={authserv_id!r} "
                                f"and proto={proto!r} (header #{header_idx + 1}): downgraded to untrusted "
                                "to defend against post-MTA injection (RFC 8601 §5)."
                            )
                    else:
                        seen_trusted_pairs.add(key)

                item: Dict[str, str] = {
                    "result": m.group(1).lower(),
                    "authserv_id": authserv_id,
                    "trusted": "true" if is_trusted else "false",
                }

                if proto == "spf":
                    mf = re.search(r"\bsmtp\.mailfrom=([^\s;]+)", header_text, flags=re.IGNORECASE)
                    if mf:
                        item["smtp.mailfrom"] = mf.group(1)
                elif proto == "dkim":
                    hd = re.search(r"\bheader\.d=([^\s;]+)", header_text, flags=re.IGNORECASE)
                    if hd:
                        item["header.d"] = hd.group(1)
                elif proto == "dmarc":
                    hf = re.search(r"\bheader\.from=([^\s;]+)", header_text, flags=re.IGNORECASE)
                    if hf:
                        item["header.from"] = hf.group(1)

                out[proto].append(item)
    return out


def trusted_auth_items(items: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    return [item for item in items if item.get("trusted") == "true"]


def parse_arc_instances(values: Sequence[str]) -> List[Tuple[int, Dict[str, str]]]:
    parsed: List[Tuple[int, Dict[str, str]]] = []
    for value in values:
        tags = parse_semicolon_tags(value)
        raw_i = tags.get("i")
        try:
            i = int(raw_i) if raw_i else -1
        except ValueError:
            i = -1
        parsed.append((i, tags))
    return parsed


def select_spf_record(txt_records: Sequence[str]) -> List[str]:
    return [v for v in txt_records if SPF_RE.match(v)]


def select_dmarc_record(txt_records: Sequence[str]) -> List[str]:
    return [v for v in txt_records if DMARC_RE.match(v)]


def select_dkim_record(txt_records: Sequence[str]) -> List[str]:
    return [v for v in txt_records if DKIM_RE.match(v)]


def spf_tokens(record: str) -> List[str]:
    return [token.strip().lower() for token in record.split() if token.strip()]


def spf_has_terminal_policy(tokens: Sequence[str]) -> bool:
    return any(token in {"all", "+all", "-all", "~all", "?all"} for token in tokens) or any(
        token.startswith("redirect=") for token in tokens
    )


def spf_lookup_count(tokens: Sequence[str]) -> int:
    count = 0
    for token in tokens:
        if token.startswith(("include:", "exists:", "redirect=")):
            count += 1
        elif token in {"a", "mx", "ptr"} or token.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            count += 1
    return count


# --- A1: walker recursivo para conteo SPF cross-include (RFC 7208 §4.6.4) ----

SPF_MACRO_RE = re.compile(r"%\{[ilpvhsdcrt][^}]*\}", re.IGNORECASE)
SPF_DANGEROUS_MACROS = ("%{i}", "%{l}", "%{p}", "%{v}", "%{s}", "%{h}")


def _spf_extract_target(token: str) -> Optional[str]:
    """Devuelve el dominio objetivo de un mecanismo SPF que dispara DNS lookup.

    Soporta ``include:dom``, ``redirect=dom``, ``a:dom``, ``a:dom/24``,
    ``mx:dom``, ``mx:dom/24``, ``exists:dom``, ``ptr:dom``. Para los
    mecanismos sin ``:`` (``a``, ``mx``, ``ptr``) devuelve None — el caller
    sabe que aplica al dominio actual del walker.
    """
    if not token:
        return None
    if token.startswith("include:"):
        return token[len("include:"):].split("/", 1)[0].lower() or None
    if token.startswith("redirect="):
        return token[len("redirect="):].split("/", 1)[0].lower() or None
    for prefix in ("a:", "mx:", "exists:", "ptr:"):
        if token.startswith(prefix):
            return token[len(prefix):].split("/", 1)[0].lower() or None
    return None


def spf_lookup_count_recursive(
    resolver,  # type: ignore[no-untyped-def]
    domain: str,
    *,
    max_lookups: int = 10,
    max_void: int = 2,
) -> Dict[str, object]:
    """Camina recursivamente el SPF de ``domain`` siguiendo include/redirect/a/mx/exists/ptr.

    Devuelve un dict con:
      - lookups: int (cuenta acumulada de mecanismos que disparan DNS, incluido el record raíz)
      - void_lookups: int (mecanismos cuyo destino devolvió NXDOMAIN o no tuvo SPF aplicable)
      - exceeded: bool (si la cuenta supera ``max_lookups``)
      - void_exceeded: bool (si void_lookups > ``max_void``, RFC 7208 §4.6.4)
      - visited: list[str] (dominios atravesados, para diagnóstico)
      - chain: list[str] (mensaje resumido por dominio)
      - macros: list[(domain, token, macro)] de macros peligrosas detectadas
      - errors: list[str] (problemas encontrados)
    """
    visited: List[str] = []
    seen: set = set()
    macros: List[Tuple[str, str, str]] = []
    errors: List[str] = []
    chain: List[str] = []

    state = {"lookups": 0, "void": 0}

    def _walk(name: str, depth: int) -> None:
        clean = name.lower().rstrip(".")
        if not clean or clean in seen:
            return
        seen.add(clean)
        visited.append(clean)
        if state["lookups"] >= max_lookups + 5:
            # Cortafuegos defensivo: ya excedimos mucho, no sigas
            return

        try:
            txt_records = resolver.txt(clean)
        except Exception as exc:  # pragma: no cover - defensivo
            errors.append(f"DNS error resolviendo SPF de {clean}: {exc}")
            return

        spf_recs = select_spf_record(txt_records)
        if not spf_recs:
            state["void"] += 1
            chain.append(f"{clean}: no SPF (void lookup)")
            return
        if len(spf_recs) > 1:
            errors.append(f"{clean} has multiple SPF records ({len(spf_recs)})")
            return
        record = spf_recs[0]
        tokens = spf_tokens(record)
        chain.append(f"{clean}: {record}")

        for token in tokens:
            # Detección de macros peligrosas (A2)
            if "%{" in token:
                for match in SPF_MACRO_RE.findall(token):
                    macros.append((clean, token, match.lower()))

            # Mecanismos sin DNS lookup
            if not token.startswith(SPF_DNS_LOOKUP_MECHANISMS) and token not in {"a", "mx", "ptr"}:
                continue

            target = _spf_extract_target(token) or clean
            state["lookups"] += 1
            if state["lookups"] > max_lookups:
                # Seguimos consumiendo include si es include/redirect para reportar bien,
                # pero rompemos para evitar trabajo desbocado.
                pass

            if token.startswith("include:") or token.startswith("redirect="):
                _walk(target, depth + 1)
            elif token.startswith(("a:", "mx:", "exists:", "ptr:")) or token in {"a", "mx", "ptr"}:
                # These trigger DNS but do not expand SPF recursively. We still
                # count one lookup per RFC 7208 §4.6.4. For `exists:`/`a:`/`mx:`
                # with an external target, we probe if the resolution is void
                # (NXDOMAIN-like): no TXT/MX/CNAME data at all.
                #
                # Probe is gated by the same defensive cap as the main walker:
                # once we are past the limit we stop issuing fresh DNS probes
                # to avoid amplifying adversarial SPF with N×3 unbounded calls.
                if (
                    target != clean
                    and target
                    and "%{" not in target  # skip unexpanded macros (e.g. %{i}.tld)
                    and state["lookups"] < max_lookups + 5
                ):
                    try:
                        sub_txt = resolver.txt(target)
                    except Exception:
                        sub_txt = []
                    try:
                        sub_mx = resolver.mx(target)
                    except Exception:
                        sub_mx = []
                    try:
                        sub_cname = resolver.cname(target)
                    except Exception:
                        sub_cname = []
                    if not sub_txt and not sub_mx and not sub_cname:
                        state["void"] += 1

    _walk(domain, depth=0)

    return {
        "lookups": state["lookups"],
        "void_lookups": state["void"],
        "exceeded": state["lookups"] > max_lookups,
        "void_exceeded": state["void"] > max_void,
        "visited": visited,
        "chain": chain,
        "macros": macros,
        "errors": errors,
    }
