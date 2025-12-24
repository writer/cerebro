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

from .exporter import OCSFExporter, OCSFFormat
from .mapper import OCSFMapper
from .models import (
    OCSFActivityID,
    OCSFComplianceFinding,
    OCSFEvent,
    OCSFFinding,
    OCSFIdentityActivity,
    OCSFSeverity,
    OCSFStatus,
)

__all__ = [
    "OCSFActivityID",
    "OCSFComplianceFinding",
    "OCSFEvent",
    "OCSFExporter",
    "OCSFFinding",
    "OCSFFormat",
    "OCSFIdentityActivity",
    "OCSFMapper",
    "OCSFSeverity",
    "OCSFStatus",
]

__version__ = "1.0.0"
__ocsf_version__ = "1.4.0"
