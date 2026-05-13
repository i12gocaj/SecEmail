"""Dataclasses and status constants for audit results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


STATUS_ORDER = {"INFO": 0, "PASS": 1, "WARN": 2, "FAIL": 3}

# Schema version of the output JSON. SINGLE source of truth.
SCHEMA_VERSION = "2.0"


@dataclass
class ProtocolEvaluation:
    result: str
    evidence: str
    details: List[str] = field(default_factory=list)
    verified_domains: List[str] = field(default_factory=list)


@dataclass
class DmarcPolicy:
    host: str
    domain: str
    org_domain: str
    record: str
    tags: Dict[str, str]
    inherited: bool
    effective_policy: Optional[str]


@dataclass
class SpoofAttempt:
    mx_host: str
    preference: int
    accepted: bool = False
    smtp_code: Optional[int] = None
    message: str = ""
    used_starttls: bool = False
    via_relay: bool = False


@dataclass
class SpoofTestResult:
    mode: str
    target_email: str
    envelope_from: str
    header_from: str
    header_to: str
    authorized: bool
    dry_run: bool
    status: str
    reasons: List[str] = field(default_factory=list)
    mx_hosts: List[str] = field(default_factory=list)
    attempts: List[SpoofAttempt] = field(default_factory=list)
    message_size_bytes: int = 0
    session_id: Optional[str] = None
    eml_sha256: Optional[str] = None
    tracking_token: Optional[str] = None


@dataclass
class CampaignResult:
    """Aggregated result of a bulk send (``run_spoof_campaign``)."""

    session_id: str
    started_utc: str
    finished_utc: Optional[str] = None
    targets_total: int = 0
    targets_processed: int = 0
    rate_per_minute: int = 30
    max_recipients: int = 50
    results: List[SpoofTestResult] = field(default_factory=list)
    aborted_reason: Optional[str] = None


@dataclass
class CheckResult:
    protocol: str
    status: str  # PASS, WARN, FAIL
    evidence: str = "dns_only"
    details: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    exact_fixes: List[str] = field(default_factory=list)
    implications: List[str] = field(default_factory=list)
    verified_domains: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    from_domain: Optional[str]
    return_path_domain: Optional[str]
    envelope_from_domain: Optional[str]
    input_mode: str = "eml"
    target: Optional[str] = None
    dns_backend: Optional[str] = None
    dns_errors: List[str] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    spoof_test: Optional[SpoofTestResult] = None

    @property
    def summary(self) -> Dict[str, int]:
        out = {"INFO": 0, "PASS": 0, "WARN": 0, "FAIL": 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out
