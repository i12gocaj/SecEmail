"""Translation of technical jargon into short human-readable explanations.

Goal: when the auditor reports a FAIL/WARN or an SMTP send is rejected with
a cryptic code, produce ONE clear sentence that explains:
- What happened (in plain language).
- Why it happened.
- What to do about it.

Designed to keep output compact: each explanation is at most 1-3 lines and
only appears when it adds value (we do not duplicate what the technical
detail already conveys).
"""

from __future__ import annotations

import re
from typing import List, Optional


# ---------------------------------------------------------------------------
# Explanations for SMTP rejection codes / messages
# ---------------------------------------------------------------------------


def explain_smtp_attempt(
    accepted: bool,
    smtp_code: Optional[int],
    message: str,
    via_relay: bool = False,
) -> Optional[str]:
    """Return a human sentence explaining the SMTP attempt outcome.

    Returns None if there is nothing useful to add (the technical detail is enough).
    """
    msg_lower = (message or "").lower()
    code = smtp_code or 0

    # --- Accepted: important nuance about actual inbox delivery -----------
    if accepted:
        if via_relay:
            return (
                "The relay accepted the message and will deliver it. "
                "Inbox placement depends on the relay's reputation and the sending domain."
            )
        return (
            "The MX accepted the SMTP connection. That does NOT mean it lands in Inbox: "
            "it will most likely go to Junk/Spam unless you use a lookalike domain with "
            "its own SPF/DKIM/DMARC and a reputable relay."
        )

    # --- Rejections: by message patterns (ordered by specificity) ---------
    if "spamhaus" in msg_lower or "pbl" in msg_lower:
        return (
            "Your IP is on an anti-spam blocklist (Spamhaus PBL): residential/dynamic "
            "IPs cannot send SMTP directly. "
            "Fix: use an authenticated relay (Mailgun, SendGrid, SES, Postmark)."
        )

    if "sorbs" in msg_lower or "spamcop" in msg_lower or "barracuda" in msg_lower:
        return (
            "Your IP is on an anti-spam blocklist (SORBS/SpamCop/Barracuda). "
            "Fix: use an authenticated relay or send from a clean IP with good reputation."
        )

    if "blocked using" in msg_lower or "blacklist" in msg_lower or "rbl" in msg_lower:
        return (
            "The receiver checked a blocklist and your IP/domain is flagged. "
            "Fix: authenticated relay with a reputable domain."
        )

    if "spf" in msg_lower and ("fail" in msg_lower or "softfail" in msg_lower):
        return (
            "The receiver evaluated SPF and it failed: your IP is not authorized to send "
            "as that domain. Fix: sign from a domain you do have in SPF, or use a relay "
            "for that domain."
        )

    if "dmarc" in msg_lower and ("reject" in msg_lower or "fail" in msg_lower):
        return (
            "The spoofed domain has DMARC at reject/quarantine and there is no SPF/DKIM "
            "alignment with your send. The receiver rejected it per the domain policy."
        )

    if "dkim" in msg_lower and ("fail" in msg_lower or "missing" in msg_lower):
        return (
            "The receiver required a valid DKIM signature and either none was present or "
            "verification failed. Some receivers enforce this when senders are well configured."
        )

    if "greylisted" in msg_lower or "greylisting" in msg_lower or code == 421:
        return (
            "The receiver applied greylisting (temporary rejection): retry in a few minutes. "
            "Normal on first contact from a new IP."
        )

    if "reverse dns" in msg_lower or "ptr" in msg_lower or "fcrdns" in msg_lower:
        return (
            "Your IP has no PTR (reverse DNS) or it does not match your HELO. "
            "Strict receivers require this. Fix: configure PTR with your ISP or use a relay."
        )

    if "rate" in msg_lower and "limit" in msg_lower:
        return (
            "The receiver applied a rate limit. Slow down or use a relay with good reputation."
        )

    if "policy" in msg_lower and ("rejected" in msg_lower or "violation" in msg_lower):
        return (
            "The receiver rejected by internal policy (anti-spam, anti-phishing). "
            "The content or sender matches one of their block heuristics."
        )

    if code == 550:
        return (
            "Permanent rejection (550): the receiver will not accept this message. "
            "Read the SMTP message for the exact cause and adjust domain/IP/content."
        )
    if 400 <= code < 500:
        return (
            "Temporary rejection (4xx): could be greylisting, congestion, or rate limit. "
            "Retry in a few minutes."
        )
    if code >= 500:
        return (
            "Permanent rejection (5xx). Read the SMTP message for the exact cause."
        )

    return None


# ---------------------------------------------------------------------------
# Explanations for CheckResult from the auditor
# ---------------------------------------------------------------------------


def explain_check(check) -> Optional[str]:
    """Return one human sentence to append to the check, or None if nothing to add.

    The check already carries `recommendations`/`exact_fixes`/`implications`;
    here we add a single "what this means" sentence in plain language.
    """
    proto = check.protocol
    status = check.status
    details = " ".join(check.details).lower() if check.details else ""
    missing = " ".join(check.missing).lower() if check.missing else ""

    if status == "PASS":
        return _explain_pass(proto)

    if proto == "SPF":
        if "does not exist" in details or "not found" in details or "no spf" in details or "no existe" in details or "no se encontró" in details:
            return (
                "The domain does NOT declare which servers may send on its behalf. "
                "Anyone can send mail as you with no restriction."
            )
        if "+all" in details:
            return (
                "Your domain's server list ends in `+all`, which means "
                "'every server on the internet is allowed to send as me'. "
                "That is identical to publishing no list at all. Replace "
                "the last term with `-all` (reject everyone else) or `~all` "
                "(soft-fail while you validate)."
            )
        if "duplic" in details:
            return (
                "Multiple SPF records found; receivers will treat it as invalid. "
                "Consolidate into a single TXT."
            )
        if "lookups" in details and ("limit" in details or "10" in details or "límite" in details):
            return (
                "Your SPF exceeds the 10 DNS-lookup limit from RFC 7208. "
                "Receivers will mark as permerror. Flatten includes or use SPF flattening."
            )

    if proto == "DKIM":
        if "does not exist" in details or "not found" in details or "selector" in missing or "no existe" in details or "no se encontró" in details:
            return (
                "Your domain does not put a cryptographic seal on its outbound mail, "
                "or we don't know which DNS subdomain (the 'selector', for example "
                "`s1._domainkey.your-domain.com`) holds the public key. Without that seal, "
                "anyone relaying the message can change its body and the recipient gets no signal. "
                "Configure DKIM at your mail provider; they hand you a DNS record to publish."
            )
        if "rsa-sha1" in details:
            return (
                "You are signing with rsa-sha1, deprecated since RFC 8301. "
                "Migrate to rsa-sha256 or ed25519."
            )
        if "l=" in details:
            return (
                "Your DKIM uses the `l=` (length) tag, which enables append abuse: an attacker "
                "can append content to the message without invalidating the signature. Remove it."
            )
        if "t=y" in details:
            return (
                "Your DKIM key is in testing mode (`t=y`). Receivers ignore it. "
                "Remove `t=y` once you have validated the flow."
            )

    if proto == "DMARC":
        if "does not exist" in details or "monitor" in details or "p=none" in details or "no existe" in details:
            return (
                "Your domain has no published rule telling Gmail or Outlook how to react "
                "when somebody fakes mail from you. With the rule missing, a phishing email "
                "pretending to be from your CEO gets delivered as if it were real. "
                "Publish a DMARC record in monitor mode (`p=none` with a reporting address) "
                "to start collecting evidence without blocking anything yet."
            )
        if "pct" in details and ("<" in details or "less" in details or "menos" in details):
            return (
                "Your DMARC applies the policy only to a percentage of messages (`pct<100`). "
                "The rest passes unfiltered. Raise to 100 once you trust the setup."
            )
        if ("align" in details or "alineac" in details) and ("fail" in details or "no" in details):
            return (
                "The mail does not align SPF or DKIM with the header-From domain. "
                "Receivers treat it as spoofing."
            )
        if "duplicate" in details or "multiple" in details or "duplicad" in details or "múltiples" in details:
            return (
                "Multiple DMARC records found: receivers treat it as ambiguous and many will ignore it. "
                "Consolidate into one."
            )

    if proto == "ARC":
        if "cv=fail" in details:
            return (
                "The ARC chain is broken (cv=fail). A signal the mail went through a forwarder "
                "that should NOT be trusted: possible DMARC bypass via forwarding."
            )
        if "not applicable" in details or "not_applicable" in details or "no aplica" in details or status == "INFO":
            return None  # ARC INFO without .eml has nothing useful to add

    if proto == "MTA-STS":
        if "does not exist" in details or "not published" in details or "no existe" in details or "no publicado" in details:
            return (
                "The domain does not publish MTA-STS. An attacker on the network can downgrade "
                "the SMTP connection to plaintext and read mail in transit. Recommended for serious domains."
            )
        if "testing" in details:
            return (
                "MTA-STS is in `testing` mode: it detects failures but does not enforce them. "
                "Switch to `enforce` once you trust the setup."
            )

    if proto == "TLS-RPT":
        if "does not exist" in details or "no existe" in details:
            return (
                "Without TLS-RPT you will not receive reports of encryption failures between your MTA "
                "and others. Optional but useful for detecting downgrade attacks."
            )

    if proto == "DANE":
        if "not deployed" in details or "none" in details or "no desplegado" in details or "ninguno" in details:
            return (
                "DANE not deployed: your MX cannot authenticate their certificate via DNSSEC. "
                "Optional. Used by .gov, European banking, and secure email providers."
            )
        if "partial" in details or "parcial" in details:
            return (
                "DANE deployed on only some MX. Receivers can fall back to the MX without DANE "
                "and degrade security. Apply to all or to none."
            )

    if proto == "BIMI":
        if "no vmc" in details or "sin vmc" in details or "without tag a=" in details.lower() or "sin tag a=" in details.lower():
            return (
                "BIMI without VMC: many receivers (Gmail, Yahoo, Apple Mail) will not display your logo "
                "without a verified VMC certificate. BIMI is purely cosmetic without it."
            )

    if proto == "LOOKALIKE":
        if status == "WARN":
            return (
                "The domain visually resembles another well-known one. If it is NOT yours, "
                "it may be a spoofing attempt against you or your customers."
            )

    return None


def _explain_pass(proto: str) -> Optional[str]:
    """Short sentence when a check passes, so panels are not left without context."""
    if proto == "SPF":
        return "The domain declares which servers may send mail on its behalf."
    if proto == "DKIM":
        return "DKIM signatures verify cryptographically; the message was not altered."
    if proto == "DMARC":
        return "The domain has an effective DMARC policy and receivers will enforce it."
    if proto == "ARC":
        return "ARC chain intact: the mail passed through trusted forwarders without tampering."
    if proto == "MTA-STS":
        return "MTA-STS in `enforce`: SMTP connections to this domain are forced over TLS."
    if proto == "TLS-RPT":
        return "TLS-RPT published: the domain will receive reports if an MTA fails TLS when talking to it."
    if proto == "DANE":
        return "DANE deployed: the MX certificates are authenticated via DNSSEC."
    if proto == "BIMI":
        return "BIMI with VMC: compatible receivers will display the brand logo."
    if proto == "LOOKALIKE":
        return "Domain name has no obvious lookalike or homograph patterns."
    return None


# ---------------------------------------------------------------------------
# Executive summary of the whole report
# ---------------------------------------------------------------------------


def explain_summary(report) -> str:
    """Generate 1-3 sentences summarizing the global state of the report."""
    by_proto = {c.protocol: c for c in report.checks}
    fails = [c for c in report.checks if c.status == "FAIL"]
    warns = [c for c in report.checks if c.status == "WARN"]

    has_spf_fail = "SPF" in by_proto and by_proto["SPF"].status == "FAIL"
    has_dkim_issue = "DKIM" in by_proto and by_proto["DKIM"].status in ("FAIL", "WARN")
    has_dmarc_fail = "DMARC" in by_proto and by_proto["DMARC"].status == "FAIL"

    if has_dmarc_fail and (has_spf_fail or has_dkim_issue):
        return (
            "The domain is exposed to spoofing. It has no effective DMARC and "
            "SPF/DKIM are weak or absent: an attacker can send mail as if it were "
            "yours and receivers will accept it."
        )

    if has_dmarc_fail:
        return (
            "The domain has SPF and/or DKIM, but without DMARC receivers do not enforce "
            "any policy against spoofing. Publish DMARC in monitor mode (`p=none` with `rua`) "
            "to start seeing abuse attempts."
        )

    if fails:
        protos = ", ".join(c.protocol for c in fails)
        return (
            f"There are {len(fails)} critical failure(s) ({protos}). Review the priority "
            "actions above — they are concrete DNS records to publish."
        )

    if warns:
        return (
            f"Acceptable configuration with {len(warns)} warning(s). The domain is not "
            "trivially spoofable, but there is room for improvement."
        )

    return (
        "Solid configuration across the verified checks. The domain is aligned "
        "with current email authentication best practices."
    )


# ---------------------------------------------------------------------------
# Explanations for the full result of a spoof
# ---------------------------------------------------------------------------


def explain_spoof_outcome(spoof_result) -> str:
    """1-3 sentences summarizing WHAT happened with the send and WHAT to do if it was not what you expected."""
    status = spoof_result.status
    attempts = spoof_result.attempts or []
    accepted = any(a.accepted for a in attempts)

    if status == "dry_run_ready":
        return (
            "Dry-run mode: the message was built but NOT sent. "
            "For a real send, call without send_spoof=False."
        )

    if status == "failed_no_mx":
        return (
            f"No MX servers for {spoof_result.target_email.split('@')[-1]}. "
            "The destination domain does not accept mail. Check that the email is correct."
        )

    if status == "failed_template_read":
        return "Could not read the HTML template. Check the file path."

    if status == "failed_attachment_too_large":
        return (
            "Attachment exceeds the maximum size. Raise `--max-attachment-bytes` "
            "or use a smaller attachment."
        )

    if accepted:
        via_relay = any(getattr(a, "via_relay", False) for a in attempts)
        if via_relay:
            return (
                "Mail handed off to the relay. Inbox delivery depends on the relay, "
                "the sending domain's reputation, and the recipient's filters."
            )
        return (
            "The recipient MX accepted the SMTP connection. Watch out: acceptance "
            "is NOT the same as Inbox delivery. Without a lookalike domain + own "
            "SPF/DKIM/DMARC + a reputable relay, the mail likely lands in Junk/Spam."
        )

    if status == "rejected_by_all_mx":
        # If we have information about the first rejection, try to explain it.
        if attempts:
            first = attempts[0]
            human = explain_smtp_attempt(
                accepted=False,
                smtp_code=first.smtp_code,
                message=first.message,
                via_relay=getattr(first, "via_relay", False),
            )
            if human:
                return human
        return (
            "All MX servers rejected the mail. Read the SMTP message from the attempt "
            "for the exact cause."
        )

    return ""


# ---------------------------------------------------------------------------
# Human explanation of a campaign (dashboard)
# ---------------------------------------------------------------------------


def explain_campaign(report: dict) -> List[str]:
    """Return 2-4 human sentences summarizing the campaign state.

    Independent lines, intended to be shown as bullets in the dashboard
    summary panel.
    """
    totals = report.get("totals") or {}
    recipients = int(totals.get("recipients", 0) or 0)
    opens = int(totals.get("opens", 0) or 0)
    clicks = int(totals.get("clicks", 0) or 0)
    submits = int(totals.get("submits", 0) or 0)
    creds = int(totals.get("submits_with_credentials", 0) or 0)

    notes: List[str] = []

    if recipients == 0:
        notes.append(
            "No data yet: no recipients recorded in tracking.jsonl. "
            "Launch a campaign with `secemail spoof ... --track --capture-url ...` to start seeing them."
        )
        return notes

    # ── Click rate vs typical simulated-phishing benchmarks ─────────────
    click_pct = (clicks / recipients) * 100 if recipients else 0
    if click_pct >= 40:
        notes.append(
            f"VERY HIGH click rate ({click_pct:.0f}%). Real simulated campaigns "
            "typically land around 5-15%; this suggests either an exceptionally effective "
            "pretext or recipients with no prior anti-phishing training."
        )
    elif click_pct >= 15:
        notes.append(
            f"High click rate ({click_pct:.0f}%). Above the typical benchmark (5-15%) "
            "for simulated phishing in organizations with awareness training."
        )
    elif click_pct > 0:
        notes.append(
            f"Moderate click rate ({click_pct:.0f}%). Within the usual range for "
            "simulated campaigns (5-15%)."
        )
    else:
        notes.append(
            "No recipient has clicked yet. "
            "If the campaign has been running >24h, review delivery (junk folder), pretext, or subject."
        )

    # ── Submit rate (the most critical signal) ──────────────────────────
    if submits > 0:
        submit_pct = (submits / recipients) * 100
        notes.append(
            f"{submits} recipient(s) submitted credentials ({submit_pct:.0f}% of total). "
            "This is the most serious indicator: the attack would have succeeded against them."
        )
        if creds > 0:
            notes.append(
                f"{creds} capture(s) contain credential fields. "
                "Stored in ~/.secemail/captures.jsonl."
            )
    elif clicks > 0:
        notes.append(
            "Clicks but NO submits: the victim reached the landing page but did NOT enter "
            "credentials. Good sign: cautious users, or the landing raised suspicion."
        )

    # ── Funnel: clicks vs opens ─────────────────────────────────────────
    if opens > 0 and clicks == 0:
        notes.append(
            f"{opens} opens but 0 clicks. The email CTA is not convincing (copy, "
            "visual, urgency) or victims spotted something off."
        )

    return notes
