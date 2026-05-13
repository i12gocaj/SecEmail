"""Controlled SMTP sending for authorized Red Team engagements.

The tool assumes the operator has contractual authorization to spoof the
From domain and send to the destination domain. Scope authorization is the
operator's responsibility, not the tool's.

Operational guardrails (against typos and mistakes, not legal):
- Optional defensive allowlist (``--authorize-domain DOMAIN``): when set,
  validated against the Public Suffix List (rejects bare TLDs, single
  labels, public suffixes) and warns if target/from fall outside. Does NOT
  block sending — it only appends a notice to ``reasons``.
- Every attempt (success or failure) is appended to a JSONL log at
  ``~/.secemail/audit.jsonl`` (override with ``SECEMAIL_AUDIT_LOG``) with
  UTC timestamp, operator, MX, SMTP code, and SHA-256 of the ``.eml``.
- The ``X-SecEmail-*`` header is opt-in (``--add-forensic-headers``): off by
  default, so we don't contaminate the measurement of real defenses.

The ``send_spoof=False`` (dry-run) branch is still available for programmatic
tests but is NOT the default CLI path.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import asdict
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from .dns import DnsResolver
from .models import CampaignResult, SpoofAttempt, SpoofTestResult
from .parsing import (
    get_domain_from_address,
    get_email_address,
    is_valid_domain,
    validate_email,
)
from .ui import UIStyle


# ---------------------------------------------------------------------------
# Constantes públicas
# ---------------------------------------------------------------------------

DEFAULT_AUDIT_PATH = Path.home() / ".secemail" / "audit.jsonl"

DEFAULT_MAX_RECIPIENTS = 50
DEFAULT_RATE_PER_MINUTE = 30

CONFIRM_PHRASE = "SI ENVIAR"


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------


def _now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _audit_log_path() -> Path:
    override = os.environ.get("SECEMAIL_AUDIT_LOG")
    if override:
        return Path(override)
    return DEFAULT_AUDIT_PATH


def _operator_id() -> str:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    host = socket.gethostname() or "unknown-host"
    return f"{user}@{host}"


def _append_jsonl(path: Path, entry: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Validación de allowlist (OPSEC duro)
# ---------------------------------------------------------------------------


def validate_authorized_domains(authorized_domains: Sequence[str]) -> List[str]:
    """Validate each allowlist entry and return the normalized list.

    Rules:
    - Each entry must pass ``is_valid_domain`` (DOMAIN_RE).
    - Minimum 2 labels (``example.com``, not ``example`` nor ``com``).
    - Cannot be a public suffix on its own (PSL):
      ``com``, ``co.uk``, ``com.br`` → ValueError.
    """

    if not authorized_domains:
        return []

    try:
        from publicsuffix2 import get_tld  # type: ignore
    except ImportError as exc:  # pragma: no cover - requirements installs it
        raise RuntimeError(
            "publicsuffix2 is a required dependency to validate --authorize-domain."
        ) from exc

    normalized: List[str] = []
    for raw in authorized_domains:
        if not raw or not isinstance(raw, str):
            raise ValueError(
                "Empty entry in --authorize-domain/--authorized-domain."
            )
        candidate = raw.strip().lower().rstrip(".")
        if not candidate:
            raise ValueError(
                "Empty entry in --authorize-domain/--authorized-domain."
            )

        if "." not in candidate:
            raise ValueError(
                f"Invalid authorized domain (needs at least 2 labels): {raw!r}. "
                "Example: example.com."
            )

        if not is_valid_domain(candidate):
            raise ValueError(
                f"Invalid authorized domain (syntax): {raw!r}."
            )

        public_suffix = get_tld(candidate)
        if public_suffix and public_suffix == candidate:
            raise ValueError(
                f"Invalid authorized domain: {raw!r} is a public suffix "
                "(composite TLD, e.g. 'com', 'co.uk'). Authorize a real registrable "
                "domain like example.com, not its TLD."
            )

        normalized.append(candidate)

    # De-duplicate while preserving order.
    seen = set()
    out: List[str] = []
    for d in normalized:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def domain_allowed(domain: str, authorized_domains: Sequence[str]) -> bool:
    """Check whether ``domain`` falls inside any authorized domain.

    Assumes ``authorized_domains`` already passed through ``validate_authorized_domains``.
    """

    clean = domain.lower().rstrip(".")
    for allowed in authorized_domains:
        allowed_clean = allowed.lower().strip().rstrip(".")
        if clean == allowed_clean or clean.endswith(f".{allowed_clean}"):
            return True
    return False


# ---------------------------------------------------------------------------
# Rendering CLI
# ---------------------------------------------------------------------------


def render_spoof_result(result: SpoofTestResult, style: UIStyle) -> None:
    from .explain import explain_spoof_outcome

    print(style.title("🎭 SMTP SEND"))
    print(f"  {style.color('➤ Mode', 'dim')}           : {result.mode}")
    print(f"  {style.color('➤ Status', 'dim')}         : {result.status}")
    print(f"  {style.color('➤ Envelope From', 'dim')}  : {result.envelope_from}")
    print(f"  {style.color('➤ Header From', 'dim')}    : {result.header_from}")
    print(f"  {style.color('➤ Header To', 'dim')}      : {result.header_to}")
    if result.session_id:
        print(f"  {style.color('➤ Session-Id', 'dim')}     : {result.session_id}")
    if result.mx_hosts:
        print(f"  {style.color('➤ MX detected', 'dim')}    : {', '.join(result.mx_hosts)}")
    for reason in result.reasons:
        print(f"  {style.color('➤ Note', 'yellow')}         : {reason}")
    for attempt in result.attempts:
        label = "accepted_by_mx" if attempt.accepted else "rejected_or_failed"
        tls = " STARTTLS" if attempt.used_starttls else ""
        relay = " (relay)" if attempt.via_relay else ""
        print(
            f"  {style.color('[*]', 'cyan')} {attempt.mx_host} pri={attempt.preference} -> "
            f"{label}{tls}{relay} {attempt.message}"
        )

    # ─── Human explanation ────────────────────────────────────────────
    human = explain_spoof_outcome(result)
    if human:
        print()
        print(f"  {style.color('💡', 'bold')} {style.color(human, 'cyan')}")


# ---------------------------------------------------------------------------
# Construcción del mensaje
# ---------------------------------------------------------------------------


def _build_message(
    *,
    spoof_subject: str,
    header_from: str,
    header_to: str,
    env_from: str,
    from_domain: str,
    text_content: str,
    html_content: Optional[str],
    attach_path: Optional[str],
    max_attachment_bytes: int,
    add_forensic_headers: bool,
    session_id: str,
    operator_id: str,
    reasons: List[str],
) -> Optional[EmailMessage]:
    """Build the ``EmailMessage`` ready to send.

    Returns None if the attachment exceeds the maximum size (the caller
    propagates the error to ``reasons`` before reaching here, but we repeat
    defensively).
    """

    msg = EmailMessage()
    msg["Subject"] = spoof_subject
    msg["From"] = header_from
    msg["To"] = header_to
    # OPSEC: usamos UTC (-0000) en lugar de localtime para no filtrar la
    # timezone del operador en la cabecera Date que ve el MX/SOC del cliente.
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=from_domain)
    msg["Reply-To"] = env_from

    if add_forensic_headers:
        msg["X-SecEmail-Test"] = "authorized-red-team-simulation"
        msg["X-SecEmail-Session-Id"] = session_id
        msg["X-SecEmail-Operator"] = operator_id

    if html_content is None:
        msg.set_content(text_content)
    else:
        msg.set_content(text_content)
        msg.add_alternative(html_content, subtype="html")

    if attach_path:
        import mimetypes

        if not os.path.isfile(attach_path):
            reasons.append(
                f"Attachment not found: {attach_path}. Message prepared without attachment."
            )
        else:
            size = os.path.getsize(attach_path)
            if size > max_attachment_bytes:
                reasons.append(
                    f"Attachment too large ({size} bytes > {max_attachment_bytes})."
                )
                return None
            ctype, encoding = mimetypes.guess_type(attach_path)
            if ctype is None or encoding is not None:
                ctype = "application/octet-stream"
            maintype, subtype = ctype.split("/", 1)
            with open(attach_path, "rb") as f:
                msg.add_attachment(
                    f.read(),
                    maintype=maintype,
                    subtype=subtype,
                    filename=os.path.basename(attach_path),
                )

    return msg


# ---------------------------------------------------------------------------
# Envío SMTP (relay autenticado o directo a MX)
# ---------------------------------------------------------------------------


def _attempt_relay(
    *,
    msg: EmailMessage,
    env_from: str,
    target_addr: str,
    relay_host: str,
    relay_port: int,
    relay_user: Optional[str],
    relay_pass: Optional[str],
    smtp_timeout: float,
) -> SpoofAttempt:
    import smtplib

    attempt = SpoofAttempt(mx_host=f"{relay_host}:{relay_port}", preference=0, via_relay=True)
    try:
        with smtplib.SMTP(relay_host, relay_port, timeout=smtp_timeout) as server:
            server.ehlo("security-audit.local")
            if not server.has_extn("starttls"):
                attempt.message = (
                    "Relay does not advertise STARTTLS; aborting send to avoid exposing credentials in cleartext."
                )
                return attempt
            server.starttls()
            attempt.used_starttls = True
            server.ehlo("security-audit.local")
            if relay_user and relay_pass:
                server.login(relay_user, relay_pass)
            server.send_message(msg, from_addr=env_from, to_addrs=[target_addr])
            attempt.accepted = True
            attempt.message = "Relay accepted the message (authenticated, STARTTLS)."
    except smtplib.SMTPResponseException as exc:
        attempt.smtp_code = exc.smtp_code
        attempt.message = (
            exc.smtp_error.decode("utf-8", errors="replace")
            if isinstance(exc.smtp_error, bytes)
            else str(exc.smtp_error)
        )
    except (smtplib.SMTPException, OSError, socket.timeout) as exc:
        attempt.message = str(exc)
    return attempt


def _attempt_direct_mx(
    *,
    msg: EmailMessage,
    env_from: str,
    target_addr: str,
    mxs: Sequence,
    smtp_timeout: float,
) -> List[SpoofAttempt]:
    import smtplib

    attempts: List[SpoofAttempt] = []
    for pref, mx_host in mxs:
        attempt = SpoofAttempt(mx_host=mx_host, preference=pref)
        try:
            with smtplib.SMTP(mx_host, 25, timeout=smtp_timeout) as server:
                server.ehlo("security-audit.local")
                if server.has_extn("starttls"):
                    server.starttls()
                    attempt.used_starttls = True
                    server.ehlo("security-audit.local")
                server.send_message(msg, from_addr=env_from, to_addrs=[target_addr])
                attempt.accepted = True
                attempt.message = (
                    "The MX accepted the SMTP message. This does not prove inbox delivery nor reading."
                )
                attempts.append(attempt)
                return attempts
        except smtplib.SMTPResponseException as exc:
            attempt.smtp_code = exc.smtp_code
            attempt.message = (
                exc.smtp_error.decode("utf-8", errors="replace")
                if isinstance(exc.smtp_error, bytes)
                else str(exc.smtp_error)
            )
        except (smtplib.SMTPException, OSError, socket.timeout) as exc:
            attempt.message = str(exc)
        attempts.append(attempt)
    return attempts


# ---------------------------------------------------------------------------
# Entry point principal
# ---------------------------------------------------------------------------


def run_spoof_test(
    target_email: str,
    spoof_domain: str,
    resolver: DnsResolver,
    style: UIStyle,
    spoof_from: Optional[str] = None,
    spoof_name: Optional[str] = None,
    spoof_to: Optional[str] = None,
    attach_path: Optional[str] = None,
    html_path: Optional[str] = None,
    send_spoof: bool = True,
    i_have_authorization: bool = True,
    authorized_domains: Sequence[str] = (),
    spoof_subject: str = "Authorized test message",
    smtp_timeout: float = 10.0,
    max_attachment_bytes: int = 10 * 1024 * 1024,
    quiet: bool = False,
    # OPSEC / capacidad ofensiva nuevos
    add_forensic_headers: bool = False,
    no_interactive: bool = False,
    relay_host: Optional[str] = None,
    relay_port: int = 587,
    relay_user: Optional[str] = None,
    relay_pass: Optional[str] = None,
    track_capture_url: Optional[str] = None,
    tracker=None,
    session_id: Optional[str] = None,
    skip_allowlist_validation: bool = False,
    audit_path: Optional[Path] = None,
    confirm_callback: Optional[Callable[[str], str]] = None,
    isatty_fn: Optional[Callable[[], bool]] = None,
) -> SpoofTestResult:
    reasons: List[str] = []
    session_id = session_id or uuid.uuid4().hex
    operator_id = _operator_id()
    audit_path = audit_path or _audit_log_path()

    # ---- 1. Validar allowlist antes de cualquier envío --------------------
    try:
        if skip_allowlist_validation:
            validated_allowlist = list(authorized_domains)
        else:
            validated_allowlist = validate_authorized_domains(authorized_domains)
    except ValueError:
        raise

    target_addr = validate_email(target_email, "--spoof-test")
    env_from = get_email_address(spoof_from) if spoof_from else None
    if not env_from:
        env_from = validate_email(f"audit@{spoof_domain}", "generated --spoof-from")
    from_domain = env_from.rsplit("@", 1)[1]
    target_domain = target_addr.rsplit("@", 1)[1]

    if spoof_name:
        if "\r" in spoof_name or "\n" in spoof_name:
            raise ValueError("--spoof-name contains disallowed line breaks.")
        header_from = f"{spoof_name} <{env_from}>"
    elif spoof_from and parseaddr(spoof_from)[0]:
        display = parseaddr(spoof_from)[0].replace("\r", "").replace("\n", "")
        header_from = f"{display} <{env_from}>"
    else:
        header_from = env_from

    header_to = spoof_to if spoof_to else target_addr
    if "\r" in header_to or "\n" in header_to:
        raise ValueError("--spoof-to contains disallowed line breaks.")

    # ---- 2. Aviso si spoof_to apunta fuera de allowlist -------------------
    if spoof_to:
        spoof_to_domain = get_domain_from_address(spoof_to)
        if (
            spoof_to_domain
            and validated_allowlist
            and not domain_allowed(spoof_to_domain, validated_allowlist)
        ):
            reasons.append(
                f"WARN: --spoof-to points to {spoof_to_domain}, outside the allowlist. "
                "SOCs with phishing-report best practices may flag this as a header "
                "inconsistent with the real recipient."
            )

    # ---- 3. Resolver MX (solo si no hay relay) ---------------------------
    using_relay = bool(relay_host)
    if using_relay:
        mxs: List = []
        mx_hosts_for_result = [f"{relay_host}:{relay_port}"]
    else:
        mxs = resolver.mx(target_domain)
        mxs.sort(key=lambda x: x[0])
        mx_hosts_for_result = [host for _, host in mxs]

    result = SpoofTestResult(
        mode="send" if send_spoof else "dry-run",
        target_email=target_addr,
        envelope_from=env_from,
        header_from=header_from,
        header_to=header_to,
        authorized=False,
        dry_run=not send_spoof,
        status="prepared",
        mx_hosts=mx_hosts_for_result,
        reasons=reasons,
        session_id=session_id,
    )

    if not using_relay and not mxs:
        result.status = "failed_no_mx"
        reasons.append(f"No MX records for {target_domain}.")
        _audit_attempt(
            audit_path=audit_path,
            operation="spoof_dry_run" if not send_spoof else "spoof_send",
            session_id=session_id,
            operator_id=operator_id,
            target_email=target_addr,
            header_from=header_from,
            env_from=env_from,
            mx_host=None,
            smtp_code=None,
            starttls=False,
            eml_sha256=None,
            via_relay=False,
            authorized_domains=list(validated_allowlist),
            status=result.status,
        )
        if not quiet:
            render_spoof_result(result, style)
        return result

    # Autorización asumida: el operador es responsable de tener permiso contractual.
    # Si se pasa allowlist, se valida defensivamente (typos); si no, se acepta el envío.
    if validated_allowlist:
        target_in_allow = domain_allowed(target_domain, validated_allowlist)
        from_in_allow = domain_allowed(from_domain, validated_allowlist)
        if not target_in_allow or not from_in_allow:
            missing = []
            if not target_in_allow:
                missing.append(f"target {target_domain}")
            if not from_in_allow:
                missing.append(f"from {from_domain}")
            reasons.append(
                f"NOTICE: allowlist does not cover: {', '.join(missing)}. Send proceeds anyway "
                "(authorization assumed); the allowlist is defensive, not blocking."
            )
    result.authorized = True

    # ---- 4. Build content (with optional tokenization) -------------------
    text_content = (
        "This message is part of an authorized email security simulation.\n"
        "If you received it outside an approved testing window, report it to the "
        "security team.\n"
    )
    html_content: Optional[str] = (
        "<html><body><p>Authorized email security simulation.</p></body></html>"
    )

    if html_path:
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read().replace("{{TARGET_EMAIL}}", target_addr)
            text_content = "This email contains an authorized simulation HTML template."
        except Exception as exc:
            result.status = "failed_template_read"
            reasons.append(f"Could not read HTML template: {exc}")
            if not quiet:
                render_spoof_result(result, style)
            return result

    # Tracking: tokenize HTML placeholders if we have tracker + base URL.
    if tracker is not None and track_capture_url and html_content:
        try:
            token = tracker.tokenize_for(
                target_addr,
                capture_base_url=track_capture_url,
                notes={"session_id": session_id},
            )
            result.tracking_token = token
            html_content = tracker.tokenize_html(
                html_content,
                target_email=target_addr,
                capture_base_url=track_capture_url,
                token=token,
            )
        except Exception as exc:
            reasons.append(f"Tracking disabled due to error: {exc}")

    msg = _build_message(
        spoof_subject=spoof_subject,
        header_from=header_from,
        header_to=header_to,
        env_from=env_from,
        from_domain=from_domain,
        text_content=text_content,
        html_content=html_content,
        attach_path=attach_path,
        max_attachment_bytes=max_attachment_bytes,
        add_forensic_headers=add_forensic_headers,
        session_id=session_id,
        operator_id=operator_id,
        reasons=reasons,
    )

    if msg is None:
        result.status = "failed_attachment_too_large"
        if not quiet:
            render_spoof_result(result, style)
        return result

    eml_bytes = msg.as_bytes()
    result.message_size_bytes = len(eml_bytes)
    result.eml_sha256 = hashlib.sha256(eml_bytes).hexdigest()

    # ---- 5. Dry-run: log + return ----------------------------------------
    if not send_spoof:
        result.status = "dry_run_ready"
        reasons.append("Dry-run: no SMTP connection opened and no mail sent.")
        _audit_attempt(
            audit_path=audit_path,
            operation="spoof_dry_run",
            session_id=session_id,
            operator_id=operator_id,
            target_email=target_addr,
            header_from=header_from,
            env_from=env_from,
            mx_host=mx_hosts_for_result[0] if mx_hosts_for_result else None,
            smtp_code=None,
            starttls=False,
            eml_sha256=result.eml_sha256,
            via_relay=using_relay,
            authorized_domains=list(validated_allowlist),
            status=result.status,
        )
        if not quiet:
            render_spoof_result(result, style)
        return result

    # ---- 6. Real SMTP send (no TTY confirmation; authorization assumed) --
    if using_relay:
        attempt = _attempt_relay(
            msg=msg,
            env_from=env_from,
            target_addr=target_addr,
            relay_host=relay_host,
            relay_port=relay_port,
            relay_user=relay_user,
            relay_pass=relay_pass,
            smtp_timeout=smtp_timeout,
        )
        result.attempts.append(attempt)
        result.status = "accepted_by_mx" if attempt.accepted else "rejected_by_relay"
        _audit_attempt(
            audit_path=audit_path,
            operation="spoof_send",
            session_id=session_id,
            operator_id=operator_id,
            target_email=target_addr,
            header_from=header_from,
            env_from=env_from,
            mx_host=attempt.mx_host,
            smtp_code=attempt.smtp_code,
            starttls=attempt.used_starttls,
            eml_sha256=result.eml_sha256,
            via_relay=True,
            authorized_domains=list(validated_allowlist),
            status=result.status,
        )
    else:
        attempts = _attempt_direct_mx(
            msg=msg,
            env_from=env_from,
            target_addr=target_addr,
            mxs=mxs,
            smtp_timeout=smtp_timeout,
        )
        result.attempts.extend(attempts)
        accepted = any(a.accepted for a in attempts)
        result.status = "accepted_by_mx" if accepted else "rejected_by_all_mx"
        last = attempts[-1] if attempts else None
        _audit_attempt(
            audit_path=audit_path,
            operation="spoof_send",
            session_id=session_id,
            operator_id=operator_id,
            target_email=target_addr,
            header_from=header_from,
            env_from=env_from,
            mx_host=last.mx_host if last else None,
            smtp_code=last.smtp_code if last else None,
            starttls=last.used_starttls if last else False,
            eml_sha256=result.eml_sha256,
            via_relay=False,
            authorized_domains=list(validated_allowlist),
            status=result.status,
        )

    if not quiet:
        render_spoof_result(result, style)
    return result


def _audit_attempt(
    *,
    audit_path: Path,
    operation: str,
    session_id: str,
    operator_id: str,
    target_email: str,
    header_from: str,
    env_from: str,
    mx_host: Optional[str],
    smtp_code: Optional[int],
    starttls: bool,
    eml_sha256: Optional[str],
    via_relay: bool,
    authorized_domains: List[str],
    status: str,
) -> None:
    entry = {
        "ts_utc": _now_utc_iso(),
        "operator": operator_id,
        "operation": operation,
        "session_id": session_id,
        "target_email": target_email,
        "from_header": header_from,
        "envelope_from": env_from,
        "mx_host": mx_host,
        "smtp_code": smtp_code,
        "starttls": starttls,
        "eml_sha256": eml_sha256,
        "via_relay": via_relay,
        "authorized_domains": authorized_domains,
        "status": status,
    }
    try:
        _append_jsonl(audit_path, entry)
    except OSError:
        # No queremos romper el envío por un fallo de logging.
        pass


# ---------------------------------------------------------------------------
# Campaña: wrap de N targets con rate-limit
# ---------------------------------------------------------------------------


def run_spoof_campaign(
    targets: Iterable[str],
    *,
    spoof_domain: str,
    resolver: DnsResolver,
    style: UIStyle,
    max_recipients: int = DEFAULT_MAX_RECIPIENTS,
    rate_per_minute: int = DEFAULT_RATE_PER_MINUTE,
    sleep_fn: Optional[Callable[[float], None]] = None,
    monotonic_fn: Optional[Callable[[], float]] = None,
    **per_target_kwargs,
) -> CampaignResult:
    """Run ``run_spoof_test`` over multiple targets with rate-limiting.

    Shares the same ``session_id`` and validated allowlist across sends.
    The first call validates the allowlist; subsequent sends are passed
    ``skip_allowlist_validation=True`` to avoid re-validating N times.
    """

    sleep_fn = sleep_fn or time.sleep
    monotonic_fn = monotonic_fn or time.monotonic

    targets_list = list(targets)
    session_id = per_target_kwargs.pop("session_id", None) or uuid.uuid4().hex

    campaign = CampaignResult(
        session_id=session_id,
        started_utc=_now_utc_iso(),
        targets_total=len(targets_list),
        rate_per_minute=rate_per_minute,
        max_recipients=max_recipients,
    )

    if len(targets_list) > max_recipients:
        campaign.aborted_reason = (
            f"Too many recipients: {len(targets_list)} > --max-recipients={max_recipients}."
        )
        campaign.finished_utc = _now_utc_iso()
        return campaign

    # Validar allowlist una sola vez.
    authorized = per_target_kwargs.pop("authorized_domains", ())
    try:
        validated = validate_authorized_domains(authorized)
    except ValueError:
        raise

    # Calcular delay en segundos entre envíos para encajar el rate.
    if rate_per_minute <= 0:
        delay = 0.0
    else:
        delay = 60.0 / float(rate_per_minute)

    last_send_time: Optional[float] = None
    for idx, target in enumerate(targets_list):
        if last_send_time is not None and delay > 0:
            elapsed = monotonic_fn() - last_send_time
            remaining = delay - elapsed
            if remaining > 0:
                sleep_fn(remaining)

        last_send_time = monotonic_fn()
        try:
            res = run_spoof_test(
                target_email=target,
                spoof_domain=spoof_domain,
                resolver=resolver,
                style=style,
                authorized_domains=validated,
                skip_allowlist_validation=True,
                session_id=session_id,
                **per_target_kwargs,
            )
        except ValueError as exc:
            # Email mal-formado: registramos y seguimos.
            res = SpoofTestResult(
                mode="send" if per_target_kwargs.get("send_spoof") else "dry-run",
                target_email=target,
                envelope_from="",
                header_from="",
                header_to="",
                authorized=False,
                dry_run=not per_target_kwargs.get("send_spoof"),
                status="failed_validation",
                reasons=[str(exc)],
                session_id=session_id,
            )
        campaign.results.append(res)
        campaign.targets_processed += 1

    campaign.finished_utc = _now_utc_iso()
    return campaign


__all__ = [
    "run_spoof_test",
    "run_spoof_campaign",
    "render_spoof_result",
    "domain_allowed",
    "validate_authorized_domains",
    "DEFAULT_AUDIT_PATH",
    "DEFAULT_MAX_RECIPIENTS",
    "DEFAULT_RATE_PER_MINUTE",
]
