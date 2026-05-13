"""SecEmail: auditor SPF/DKIM/DMARC/ARC + simulación SMTP controlada.

Uso programático (API pública):

    from secemail import audit_email, audit_domain, run_spoof_test

    report = audit_domain("dominio.com", dkim_selectors=["default"])
    print(report.summary)
"""

from .checks import audit_domain, audit_email
from .models import (
    AuditReport,
    CampaignResult,
    CheckResult,
    SpoofAttempt,
    SpoofTestResult,
)
from .spoof import (
    run_spoof_campaign,
    run_spoof_test,
    validate_authorized_domains,
)
from .tracking import Tracker, build_campaign_report

__all__ = [
    "audit_email",
    "audit_domain",
    "run_spoof_test",
    "run_spoof_campaign",
    "validate_authorized_domains",
    "AuditReport",
    "CheckResult",
    "SpoofAttempt",
    "SpoofTestResult",
    "CampaignResult",
    "Tracker",
    "build_campaign_report",
]

__version__ = "0.3.0"

# Re-export para uso programático: from secemail import SCHEMA_VERSION
from .models import SCHEMA_VERSION  # noqa: F401,E402

__all__ = __all__ + ["SCHEMA_VERSION", "__version__"]
