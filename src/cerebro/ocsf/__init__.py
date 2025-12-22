"""
OCSF (Open Cybersecurity Schema Framework) Support

Cerebro OCSF implementation providing standardized security event format for
interoperability with SIEM, data lakes, and security analytics platforms.

OCSF Version: 1.4.0+
Schema: https://schema.ocsf.io/

Key Features:
- Transform Cerebro findings to OCSF Finding class (category 2)
- Transform IAM events to OCSF IAM category (category 3)
- Transform security configuration data to OCSF compliance findings
- Export capabilities for AWS Security Lake, Splunk, and other OCSF consumers
"""

from .mapper import OCSFMapper
from .models import (
    OCSFEvent,
    OCSFFinding,
    OCSFComplianceFinding,
    OCSFIdentityActivity,
    OCSFSeverity,
    OCSFStatus,
    OCSFActivityID,
)
from .exporter import OCSFExporter, OCSFFormat

__all__ = [
    "OCSFMapper",
    "OCSFEvent",
    "OCSFFinding",
    "OCSFComplianceFinding",
    "OCSFIdentityActivity",
    "OCSFSeverity",
    "OCSFStatus",
    "OCSFActivityID",
    "OCSFExporter",
    "OCSFFormat",
]

__version__ = "1.0.0"
__ocsf_version__ = "1.4.0"
