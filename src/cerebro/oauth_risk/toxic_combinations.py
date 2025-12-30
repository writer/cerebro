"""
Toxic combination detection for OAuth applications.

Detects dangerous combinations of OAuth scopes and settings that
create security risks (e.g., Slack app with files:read + public links).
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import structlog

from .registry import AppRiskLevel, OAuthApp

logger = structlog.get_logger(__name__)


class ToxicityLevel(Enum):
    """Severity levels for toxic combinations."""

    INFO = "info"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


@dataclass
class ToxicPattern:
    """Definition of a toxic OAuth pattern."""

    pattern_id: str
    name: str
    description: str
    toxicity_level: ToxicityLevel
    conditions: list[str]  # Human-readable conditions
    detection_function: str  # Name of detection function
    remediation_steps: list[str]
    examples: list[str]


@dataclass
class ToxicCombinationResult:
    """Result of toxic combination detection."""

    app_id: str
    app_name: str
    provider: str
    toxic_patterns: list[ToxicPattern]
    toxicity_score: float
    detected_at: datetime
    recommended_actions: list[str]
    auto_quarantine_eligible: bool


class ToxicCombinationDetector:
    """
    Detects toxic combinations of OAuth scopes and app configurations.

    Identifies dangerous patterns that increase breach risk across
    Google Workspace, M365, Slack, and GitHub applications.
    """

    def __init__(self):
        self.toxic_patterns = self._define_toxic_patterns()

    def _define_toxic_patterns(self) -> dict[str, ToxicPattern]:
        """Define known toxic OAuth patterns."""
        patterns = {}

        # Pattern 1: Slack app with file access + public link capabilities
        patterns["slack_file_public"] = ToxicPattern(
            pattern_id="slack_file_public",
            name="Slack File Access + Public Links",
            description="Slack app with file access that can create public links to external domains",
            toxicity_level=ToxicityLevel.CRITICAL,
            conditions=[
                "Slack application with files:read scope",
                "Public link sharing enabled",
                "External domain recipients allowed",
            ],
            detection_function="detect_slack_file_public",
            remediation_steps=[
                "Disable public link sharing for the app",
                "Restrict to internal domains only",
                "Review app necessity and permissions",
                "Implement app-specific policies",
            ],
            examples=[
                "Slack bot that can read files and share public links with competitors",
                "Marketing automation that exposes confidential documents",
            ],
        )

        # Pattern 2: GitHub app with repository write + external network access
        patterns["github_write_external"] = ToxicPattern(
            pattern_id="github_write_external",
            name="GitHub Write Access + External Network",
            description="GitHub app with repository write access that can communicate externally",
            toxicity_level=ToxicityLevel.DANGEROUS,
            conditions=[
                "GitHub app with contents:write permission",
                "Network access to external domains",
                "No IP restrictions configured",
            ],
            detection_function="detect_github_write_external",
            remediation_steps=[
                "Review app network access requirements",
                "Implement IP allow-lists",
                "Audit code modification capabilities",
                "Consider read-only alternatives",
            ],
            examples=[
                "CI/CD tool that could exfiltrate source code",
                "Third-party security scanner with broad write access",
            ],
        )

        # Pattern 3: Google Workspace admin + external app
        patterns["google_admin_external"] = ToxicPattern(
            pattern_id="google_admin_external",
            name="Google Admin Access + External Publisher",
            description="External app with Google Workspace admin permissions",
            toxicity_level=ToxicityLevel.CRITICAL,
            conditions=[
                "Google Workspace admin scope",
                "External publisher domain",
                "Unverified application",
            ],
            detection_function="detect_google_admin_external",
            remediation_steps=[
                "Remove admin permissions immediately",
                "Verify app publisher identity",
                "Review admin action audit logs",
                "Implement admin app allow-list",
            ],
            examples=[
                "Third-party HR tool with user management access",
                "Marketing automation with domain admin rights",
            ],
        )

        # Pattern 4: M365 Mail + Calendar + External recipient
        patterns["m365_mail_calendar_external"] = ToxicPattern(
            pattern_id="m365_mail_calendar_external",
            name="M365 Mail/Calendar + External Recipients",
            description="M365 app with mail and calendar access that can send to external recipients",
            toxicity_level=ToxicityLevel.DANGEROUS,
            conditions=[
                "Microsoft Graph Mail.ReadWrite permission",
                "Calendar access permissions",
                "External recipient access enabled",
            ],
            detection_function="detect_m365_mail_calendar_external",
            remediation_steps=[
                "Restrict to internal recipients only",
                "Review mail forwarding rules",
                "Audit calendar sharing permissions",
                "Implement data loss prevention rules",
            ],
            examples=[
                "CRM integration that forwards emails externally",
                "Calendar sync that exposes meeting details",
            ],
        )

        # Pattern 5: High-scope app without recent usage
        patterns["high_scope_unused"] = ToxicPattern(
            pattern_id="high_scope_unused",
            name="High-Scope Unused Application",
            description="OAuth app with extensive permissions but no recent usage",
            toxicity_level=ToxicityLevel.WARNING,
            conditions=[
                "High-risk scope permissions",
                "No usage in 90+ days",
                "No designated owner",
            ],
            detection_function="detect_high_scope_unused",
            remediation_steps=[
                "Review app necessity",
                "Revoke unused applications",
                "Assign app ownership",
                "Implement usage monitoring",
            ],
            examples=[
                "Abandoned integration with extensive file access",
                "Trial app left with admin permissions",
            ],
        )

        return patterns

    async def detect_toxic_combinations(
        self, apps: list[OAuthApp]
    ) -> list[ToxicCombinationResult]:
        """
        Detect toxic combinations across all OAuth apps.

        Args:
            apps: List of OAuth applications to analyze

        Returns:
            List of detected toxic combinations
        """
        toxic_results = []

        for app in apps:
            detected_patterns = []

            # Run each detection pattern
            for _pattern_id, pattern in self.toxic_patterns.items():
                detection_method = getattr(self, pattern.detection_function, None)
                if detection_method and await detection_method(app):
                    detected_patterns.append(pattern)

            # Create result if toxic patterns found
            if detected_patterns:
                toxicity_score = self._calculate_toxicity_score(detected_patterns)

                result = ToxicCombinationResult(
                    app_id=app.app_id,
                    app_name=app.app_name,
                    provider=app.provider,
                    toxic_patterns=detected_patterns,
                    toxicity_score=toxicity_score,
                    detected_at=datetime.now(),
                    recommended_actions=self._aggregate_remediation_steps(
                        detected_patterns
                    ),
                    auto_quarantine_eligible=toxicity_score >= 0.8,
                )

                toxic_results.append(result)

        # Sort by toxicity score
        toxic_results.sort(key=lambda x: x.toxicity_score, reverse=True)

        logger.info(f"Detected {len(toxic_results)} toxic combinations")

        return toxic_results

    async def detect_slack_file_public(self, app: OAuthApp) -> bool:
        """Detect Slack app with file access + public link risk."""
        if app.provider != "slack":
            return False

        # Check for file access scopes
        has_file_access = any("files" in scope.scope.lower() for scope in app.scopes)

        # Check for public link capabilities (simplified)
        has_public_links = any(
            factor in ["public_link_sharing", "external_recipients"]
            for factor in app.risk_factors
        )

        return has_file_access and has_public_links

    async def detect_github_write_external(self, app: OAuthApp) -> bool:
        """Detect GitHub app with write access + external network risk."""
        if app.provider != "github":
            return False

        # Check for write permissions
        has_write_access = any(scope.write_permissions for scope in app.scopes)

        # Check for external network access (simplified check)
        has_external_access = (
            not app.is_internal or "external_network" in app.risk_factors
        )

        return has_write_access and has_external_access

    async def detect_google_admin_external(self, app: OAuthApp) -> bool:
        """Detect Google Workspace admin access by external app."""
        if app.provider != "google_workspace":
            return False

        # Check for admin scopes
        has_admin_access = any("admin" in scope.scope.lower() for scope in app.scopes)

        # Check if external app
        is_external = not app.is_internal and not app.is_verified

        return has_admin_access and is_external

    async def detect_m365_mail_calendar_external(self, app: OAuthApp) -> bool:
        """Detect M365 app with mail/calendar + external recipient risk."""
        if app.provider != "m365":
            return False

        # Check for mail/calendar access
        has_mail_access = any("Mail" in scope.scope for scope in app.scopes)
        has_calendar_access = any("Calendar" in scope.scope for scope in app.scopes)

        # Check for external recipient capability
        has_external_recipients = "external_recipients" in app.risk_factors

        return (has_mail_access or has_calendar_access) and has_external_recipients

    async def detect_high_scope_unused(self, app: OAuthApp) -> bool:
        """Detect high-scope app without recent usage."""
        # Check for high-risk scopes
        has_high_scopes = app.risk_level in [AppRiskLevel.HIGH, AppRiskLevel.CRITICAL]

        # Check for recent usage
        if app.last_used:
            days_since_use = (datetime.now() - app.last_used).days
            recently_unused = days_since_use > 90
        else:
            recently_unused = True  # Never used

        # Check for ownership
        no_owner = not app.owner

        return has_high_scopes and recently_unused and no_owner

    def _calculate_toxicity_score(self, patterns: list[ToxicPattern]) -> float:
        """Calculate overall toxicity score from detected patterns."""
        if not patterns:
            return 0.0

        # Weight by toxicity level
        level_weights = {
            ToxicityLevel.CRITICAL: 1.0,
            ToxicityLevel.DANGEROUS: 0.8,
            ToxicityLevel.WARNING: 0.5,
            ToxicityLevel.INFO: 0.2,
        }

        total_score = sum(
            level_weights.get(pattern.toxicity_level, 0.5) for pattern in patterns
        )

        # Normalize to 0-1 range (max score of 3 patterns = 1.0)
        return min(total_score / 3.0, 1.0)

    def _aggregate_remediation_steps(self, patterns: list[ToxicPattern]) -> list[str]:
        """Aggregate remediation steps from all detected patterns."""
        all_steps = []
        for pattern in patterns:
            all_steps.extend(pattern.remediation_steps)

        # Deduplicate while preserving order
        seen = set()
        unique_steps = []
        for step in all_steps:
            if step not in seen:
                seen.add(step)
                unique_steps.append(step)

        return unique_steps[:10]  # Top 10 recommendations


# SQL queries for toxic combination detection
TOXIC_COMBINATION_SQL_QUERIES = {
    "high_scope_apps_no_owner": """
        SELECT app_name, scopes, last_used_at, owner
        FROM oauth_app
        WHERE scopes ILIKE '%files:read%'
          AND owner IS NULL
          AND last_used_at > now() - interval '30 days'
    """,
    "slack_apps_file_access": """
        SELECT app_name, scopes, publisher_domain, last_used_at
        FROM oauth_app
        WHERE provider = 'slack'
          AND (scopes ILIKE '%files%' OR scopes ILIKE '%drive%')
          AND publisher_domain NOT LIKE '%.company.com'
    """,
    "github_apps_write_external": """
        SELECT app_name, permissions, redirect_uris, is_verified
        FROM oauth_app
        WHERE provider = 'github'
          AND permissions ILIKE '%write%'
          AND is_verified = false
          AND redirect_uris NOT LIKE '%github.com%'
    """,
    "m365_admin_external": """
        SELECT app_name, scopes, publisher_domain, is_verified
        FROM oauth_app
        WHERE provider = 'm365'
          AND scopes ILIKE '%admin%'
          AND publisher_domain NOT LIKE '%.microsoft.com'
          AND is_verified = false
    """,
}


# Global toxic combination detector
_toxic_detector = ToxicCombinationDetector()


def get_toxic_detector() -> ToxicCombinationDetector:
    """Get global toxic combination detector."""
    return _toxic_detector
