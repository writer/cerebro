"""
GitHub provider table implementations.

Exposes GitHub security resources as SQL tables.
"""

from typing import AsyncGenerator, Dict, Any, Optional
from datetime import datetime
import logging

from ...query.table import ProviderSecurityTable, QueryContext
from ...collectors.normalization import normalize_severity
from ...query.registry import register_table
from ...query.schema import SecurityColumn, ColumnType


# Real GitHub API client implementation
class GitHubClient:
    def __init__(self, org_name: Optional[str] = None, token: Optional[str] = None):
        self.org_name = org_name
        self.token = token
        self._github = None
        self._org = None

    async def authenticate(self):
        """Authenticate with GitHub API."""
        try:
            import asyncio
            from github import Github
            from cerebro.core.config import settings

            # Use provided credentials or fall back to settings
            org_name = self.org_name or getattr(settings, "github_org", "demo-org")
            token = self.token or getattr(settings, "github_token", None)

            if not token:
                logger.error("GitHub token not configured")
                return False

            # Run sync GitHub operations in executor
            loop = asyncio.get_event_loop()

            def _auth():
                self._github = Github(token)
                # Test authentication by getting user info
                user = self._github.get_user()
                user.name  # This will raise if token is invalid

                # Get organization
                self._org = self._github.get_organization(org_name)
                self._org.name  # Test org access
                return True

            return await loop.run_in_executor(None, _auth)

        except ImportError:
            logger.error("PyGithub not installed. Run: pip install PyGithub")
            return False
        except Exception as e:
            logger.error(f"GitHub authentication failed: {e}")
            return False

    async def list_repositories(self):
        """List all repositories from GitHub API."""
        try:
            if not self._org:
                if not await self.authenticate():
                    return

            import asyncio

            def _get_repos():
                return list(self._org.get_repos())

            loop = asyncio.get_event_loop()
            repos = await loop.run_in_executor(None, _get_repos)

            for repo in repos:
                # Convert PyGithub objects to dict format
                repo_dict = {
                    "id": repo.id,
                    "name": repo.name,
                    "full_name": repo.full_name,
                    "owner": {"login": repo.owner.login},
                    "private": repo.private,
                    "archived": repo.archived,
                    "disabled": repo.disabled,
                    "default_branch": repo.default_branch,
                    "visibility": "private" if repo.private else "public",
                    "created_at": (
                        repo.created_at.isoformat() if repo.created_at else None
                    ),
                    "updated_at": (
                        repo.updated_at.isoformat() if repo.updated_at else None
                    ),
                    "pushed_at": repo.pushed_at.isoformat() if repo.pushed_at else None,
                    "language": repo.language,
                    "topics": (
                        list(repo.get_topics()) if hasattr(repo, "get_topics") else []
                    ),
                    "size": repo.size,
                    "stargazers_count": repo.stargazers_count,
                    "forks_count": repo.forks_count,
                    "description": repo.description,
                    "homepage": repo.homepage,
                    "has_issues": repo.has_issues,
                    "has_projects": repo.has_projects,
                    "has_wiki": repo.has_wiki,
                }
                yield repo_dict

        except Exception as e:
            logger.error(f"Error listing GitHub repositories: {e}")
            return

    async def list_vulnerability_alerts(self):
        """List vulnerability alerts from GitHub API."""
        try:
            if not self._org:
                if not await self.authenticate():
                    return

            import asyncio

            def _get_vulns():
                alerts = []
                for repo in self._org.get_repos():
                    try:
                        # Note: This requires special permissions and may not work for all repos
                        for alert in repo.get_vulnerability_alerts():
                            alert_dict = {
                                "number": getattr(alert, "number", 0),
                                "repository": {
                                    "full_name": repo.full_name,
                                    "owner": {"login": repo.owner.login},
                                },
                                "state": getattr(alert, "state", "unknown"),
                                "created_at": (
                                    alert.created_at.isoformat()
                                    if hasattr(alert, "created_at") and alert.created_at
                                    else None
                                ),
                                "updated_at": (
                                    alert.updated_at.isoformat()
                                    if hasattr(alert, "updated_at") and alert.updated_at
                                    else None
                                ),
                                "security_advisory": {
                                    "severity": getattr(alert, "severity", "unknown")
                                },
                                "dependency": {
                                    "package": {
                                        "name": getattr(
                                            alert, "package_name", "unknown"
                                        )
                                    }
                                },
                            }
                            alerts.append(alert_dict)
                    except Exception as e:
                        logger.warning(
                            f"Could not fetch vulnerability alerts for {repo.full_name}: {e}"
                        )
                        continue
                return alerts

            loop = asyncio.get_event_loop()
            alerts = await loop.run_in_executor(None, _get_vulns)

            for alert in alerts:
                yield alert

        except Exception as e:
            logger.error(f"Error listing GitHub vulnerability alerts: {e}")
            return

    async def list_secret_scanning_alerts(self):
        """List secret scanning alerts from GitHub API."""
        try:
            if not self._org:
                if not await self.authenticate():
                    return

            import asyncio

            def _get_secrets():
                alerts = []
                for repo in self._org.get_repos():
                    try:
                        # Note: This requires special permissions and may not work for all repos
                        for alert in repo.get_secret_scanning_alerts():
                            alert_dict = {
                                "number": getattr(alert, "number", 0),
                                "repository": {
                                    "full_name": repo.full_name,
                                    "owner": {"login": repo.owner.login},
                                },
                                "state": getattr(alert, "state", "unknown"),
                                "created_at": (
                                    alert.created_at.isoformat()
                                    if hasattr(alert, "created_at") and alert.created_at
                                    else None
                                ),
                                "updated_at": (
                                    alert.updated_at.isoformat()
                                    if hasattr(alert, "updated_at") and alert.updated_at
                                    else None
                                ),
                                "secret_type": getattr(alert, "secret_type", "unknown"),
                                "secret_type_display_name": getattr(
                                    alert, "secret_type_display_name", "Unknown"
                                ),
                                "secret": "***",  # Never expose actual secret
                            }
                            alerts.append(alert_dict)
                    except Exception as e:
                        logger.warning(
                            f"Could not fetch secret scanning alerts for {repo.full_name}: {e}"
                        )
                        continue
                return alerts

            loop = asyncio.get_event_loop()
            alerts = await loop.run_in_executor(None, _get_secrets)

            for alert in alerts:
                yield alert

        except Exception as e:
            logger.error(f"Error listing GitHub secret scanning alerts: {e}")
            return


logger = logging.getLogger(__name__)


class GitHubRepositoryTable(ProviderSecurityTable):
    """GitHub repositories as a security table."""

    def __init__(self):
        repo_columns = [
            SecurityColumn(
                "repo_id",
                ColumnType.INTEGER,
                "Repository ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "repo_name", ColumnType.TEXT, "Repository name", source_field="name"
            ),
            SecurityColumn(
                "full_name",
                ColumnType.TEXT,
                "Full repository name",
                source_field="full_name",
            ),
            SecurityColumn(
                "owner", ColumnType.TEXT, "Repository owner", source_field="owner.login"
            ),
            SecurityColumn(
                "private",
                ColumnType.BOOLEAN,
                "Private repository",
                source_field="private",
            ),
            SecurityColumn(
                "archived",
                ColumnType.BOOLEAN,
                "Archived repository",
                source_field="archived",
            ),
            SecurityColumn(
                "disabled",
                ColumnType.BOOLEAN,
                "Disabled repository",
                source_field="disabled",
            ),
            SecurityColumn(
                "default_branch",
                ColumnType.TEXT,
                "Default branch",
                source_field="default_branch",
            ),
            SecurityColumn(
                "visibility",
                ColumnType.TEXT,
                "Repository visibility",
                source_field="visibility",
            ),
            SecurityColumn(
                "security_and_analysis",
                ColumnType.JSON,
                "Security settings",
                source_field="security_and_analysis",
            ),
            SecurityColumn(
                "permissions",
                ColumnType.JSON,
                "User permissions",
                source_field="permissions",
            ),
            SecurityColumn(
                "topics", ColumnType.JSON, "Repository topics", source_field="topics"
            ),
            SecurityColumn(
                "license",
                ColumnType.JSON,
                "License information",
                source_field="license",
            ),
            SecurityColumn(
                "language", ColumnType.TEXT, "Primary language", source_field="language"
            ),
            SecurityColumn(
                "size", ColumnType.INTEGER, "Repository size in KB", source_field="size"
            ),
            SecurityColumn(
                "open_issues_count",
                ColumnType.INTEGER,
                "Open issues count",
                source_field="open_issues_count",
            ),
            SecurityColumn(
                "forks_count",
                ColumnType.INTEGER,
                "Forks count",
                source_field="forks_count",
            ),
            SecurityColumn(
                "stargazers_count",
                ColumnType.INTEGER,
                "Stars count",
                source_field="stargazers_count",
            ),
            SecurityColumn(
                "pushed_at",
                ColumnType.TIMESTAMP,
                "Last push date",
                source_field="pushed_at",
            ),
        ]

        super().__init__(
            name="github_repository",
            description="GitHub repositories with security and configuration data",
            provider_name="github",
            columns=repo_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch repositories from GitHub API."""
        client = GitHubClient(
            org_name=ctx.config.get("github_org"), token=ctx.config.get("github_token")
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            # Get organization or user repositories
            async for repo in client.list_repositories():
                # Add provider metadata
                repo["provider"] = "github"
                repo["account_id"] = repo["owner"]["login"]  # Use owner as account
                repo["region"] = "global"
                repo["created_at"] = self._parse_github_timestamp(
                    repo.get("created_at")
                )
                repo["updated_at"] = self._parse_github_timestamp(
                    repo.get("updated_at")
                )

                # Transform topics to tags
                topics = repo.get("topics", [])
                repo["tags"] = {f"topic-{i}": topic for i, topic in enumerate(topics)}

                repo["metadata"] = {"github_repo_data": repo}

                yield repo

        except Exception as e:
            logger.error(f"Error fetching GitHub repositories: {e}")
            return

    def _parse_github_timestamp(
        self, timestamp_str: Optional[str]
    ) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class GitHubVulnerabilityAlertTable(ProviderSecurityTable):
    """GitHub Dependabot vulnerability alerts as a security table."""

    def __init__(self):
        alert_columns = [
            SecurityColumn(
                "alert_id",
                ColumnType.INTEGER,
                "Alert ID",
                required=True,
                source_field="number",
            ),
            SecurityColumn(
                "repository",
                ColumnType.TEXT,
                "Repository full name",
                transform="get_repo_name",
            ),
            SecurityColumn(
                "state", ColumnType.STATUS, "Alert state", source_field="state"
            ),
            SecurityColumn(
                "dependency",
                ColumnType.JSON,
                "Vulnerable dependency",
                source_field="dependency",
            ),
            SecurityColumn(
                "security_advisory",
                ColumnType.JSON,
                "Security advisory",
                source_field="security_advisory",
            ),
            SecurityColumn(
                "security_vulnerability",
                ColumnType.JSON,
                "Vulnerability details",
                source_field="security_vulnerability",
            ),
            SecurityColumn("url", ColumnType.TEXT, "Alert URL", source_field="url"),
            SecurityColumn(
                "html_url", ColumnType.TEXT, "Web URL", source_field="html_url"
            ),
            SecurityColumn(
                "dismissed_at",
                ColumnType.TIMESTAMP,
                "Dismissal timestamp",
                source_field="dismissed_at",
            ),
            SecurityColumn(
                "dismissed_by",
                ColumnType.JSON,
                "Dismissed by user",
                source_field="dismissed_by",
            ),
            SecurityColumn(
                "dismissed_reason",
                ColumnType.TEXT,
                "Dismissal reason",
                source_field="dismissed_reason",
            ),
            SecurityColumn(
                "dismissed_comment",
                ColumnType.TEXT,
                "Dismissal comment",
                source_field="dismissed_comment",
            ),
            SecurityColumn(
                "fixed_at",
                ColumnType.TIMESTAMP,
                "Fix timestamp",
                source_field="fixed_at",
            ),
        ]

        super().__init__(
            name="github_vulnerability_alert",
            description="GitHub Dependabot vulnerability alerts",
            provider_name="github",
            columns=alert_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch vulnerability alerts from GitHub API."""
        client = GitHubClient(
            org_name=ctx.config.get("github_org"), token=ctx.config.get("github_token")
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            # Get alerts for all accessible repositories
            async for alert in client.list_vulnerability_alerts():
                # Add provider metadata
                alert["provider"] = "github"
                alert["account_id"] = (
                    alert.get("repository", {}).get("owner", {}).get("login", "")
                )
                alert["region"] = "global"
                alert["created_at"] = self._parse_github_timestamp(
                    alert.get("created_at")
                )
                alert["updated_at"] = self._parse_github_timestamp(
                    alert.get("updated_at")
                )
                alert["tags"] = {}
                alert["metadata"] = {"github_alert_data": alert}

                # Extract severity from advisory
                advisory = alert.get("security_advisory", {})
                alert["severity"] = normalize_severity(
                    advisory.get("severity"), provider="github"
                )

                yield alert

        except Exception as e:
            logger.error(f"Error fetching GitHub vulnerability alerts: {e}")
            return

    def get_repo_name(self, alert_data: Dict[str, Any]) -> str:
        """Extract repository name from alert data."""
        repo = alert_data.get("repository", {})
        return repo.get("full_name", "")

    def _parse_github_timestamp(
        self, timestamp_str: Optional[str]
    ) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class GitHubSecretScanningAlertTable(ProviderSecurityTable):
    """GitHub secret scanning alerts as a security table."""

    def __init__(self):
        alert_columns = [
            SecurityColumn(
                "alert_id",
                ColumnType.INTEGER,
                "Alert ID",
                required=True,
                source_field="number",
            ),
            SecurityColumn(
                "repository",
                ColumnType.TEXT,
                "Repository full name",
                transform="get_repo_name",
            ),
            SecurityColumn(
                "state", ColumnType.STATUS, "Alert state", source_field="state"
            ),
            SecurityColumn(
                "secret_type",
                ColumnType.TEXT,
                "Secret type",
                source_field="secret_type",
            ),
            SecurityColumn(
                "secret_type_display_name",
                ColumnType.TEXT,
                "Secret type display",
                source_field="secret_type_display_name",
            ),
            SecurityColumn(
                "secret", ColumnType.TEXT, "Masked secret", source_field="secret"
            ),
            SecurityColumn(
                "resolution",
                ColumnType.TEXT,
                "Resolution method",
                source_field="resolution",
            ),
            SecurityColumn(
                "resolved_by",
                ColumnType.JSON,
                "Resolved by user",
                source_field="resolved_by",
            ),
            SecurityColumn(
                "resolved_at",
                ColumnType.TIMESTAMP,
                "Resolution timestamp",
                source_field="resolved_at",
            ),
            SecurityColumn(
                "push_protection_bypassed",
                ColumnType.BOOLEAN,
                "Push protection bypassed",
                source_field="push_protection_bypassed",
            ),
            SecurityColumn(
                "push_protection_bypassed_by",
                ColumnType.JSON,
                "Bypass user",
                source_field="push_protection_bypassed_by",
            ),
            SecurityColumn(
                "push_protection_bypassed_at",
                ColumnType.TIMESTAMP,
                "Bypass timestamp",
                source_field="push_protection_bypassed_at",
            ),
            SecurityColumn(
                "locations",
                ColumnType.JSON,
                "Secret locations",
                source_field="locations",
            ),
        ]

        super().__init__(
            name="github_secret_scanning_alert",
            description="GitHub secret scanning alerts",
            provider_name="github",
            columns=alert_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch secret scanning alerts from GitHub API."""
        client = GitHubClient(
            org_name=ctx.config.get("github_org"), token=ctx.config.get("github_token")
        )

        try:
            # Authenticate if needed
            await client.authenticate()

            async for alert in client.list_secret_scanning_alerts():
                # Add provider metadata
                alert["provider"] = "github"
                alert["account_id"] = (
                    alert.get("repository", {}).get("owner", {}).get("login", "")
                )
                alert["region"] = "global"
                alert["created_at"] = self._parse_github_timestamp(
                    alert.get("created_at")
                )
                alert["updated_at"] = self._parse_github_timestamp(
                    alert.get("updated_at")
                )
                alert["tags"] = {"secret_type": alert.get("secret_type", "")}
                alert["metadata"] = {"github_secret_alert_data": alert}

                alert["severity"] = normalize_severity("high", provider="github")

                yield alert

        except Exception as e:
            logger.error(f"Error fetching GitHub secret scanning alerts: {e}")
            return

    def get_repo_name(self, alert_data: Dict[str, Any]) -> str:
        """Extract repository name from alert data."""
        repo = alert_data.get("repository", {})
        return repo.get("full_name", "")

    def _parse_github_timestamp(
        self, timestamp_str: Optional[str]
    ) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


def register_github_tables():
    """Register all GitHub tables with the query engine."""
    register_table(GitHubRepositoryTable(), aliases=["github_repos", "repositories"])
    register_table(
        GitHubVulnerabilityAlertTable(),
        aliases=["github_vuln_alerts", "dependabot_alerts"],
    )
    register_table(
        GitHubSecretScanningAlertTable(),
        aliases=["github_secret_alerts", "secret_alerts"],
    )
