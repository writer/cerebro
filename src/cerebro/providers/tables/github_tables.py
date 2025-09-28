"""
GitHub provider table implementations.

Exposes GitHub security resources as SQL tables.
"""

import asyncio
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime
import logging

from ...query.table import ProviderSecurityTable, QueryContext
from ...query.registry import register_table  
from ...query.schema import SecurityColumn, ColumnType

# Mock GitHub client for demonstration
class GitHubClient:
    async def list_repositories(self):
        repos = [{
            "id": 1234567,
            "name": "example-repo",
            "full_name": "example-org/example-repo",
            "owner": {"login": "example-org"},
            "private": False,
            "archived": False,
            "disabled": False,
            "default_branch": "main",
            "visibility": "public",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "pushed_at": "2024-01-01T12:00:00Z",
            "language": "Python",
            "topics": ["python", "security"],
            "size": 1024
        }]
        for repo in repos:
            yield repo
    
    async def list_vulnerability_alerts(self):
        alerts = [{
            "number": 1,
            "repository": {"full_name": "example-org/example-repo", "owner": {"login": "example-org"}},
            "state": "open",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "security_advisory": {"severity": "high"},
            "dependency": {"package": {"name": "requests"}}
        }]
        for alert in alerts:
            yield alert
    
    async def list_secret_scanning_alerts(self):
        alerts = [{
            "number": 1,
            "repository": {"full_name": "example-org/example-repo", "owner": {"login": "example-org"}},
            "state": "open",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token",
            "secret": "ghp_****"
        }]
        for alert in alerts:
            yield alert

logger = logging.getLogger(__name__)


class GitHubRepositoryTable(ProviderSecurityTable):
    """GitHub repositories as a security table."""
    
    def __init__(self):
        repo_columns = [
            SecurityColumn("repo_id", ColumnType.INTEGER, "Repository ID", required=True, source_field="id"),
            SecurityColumn("repo_name", ColumnType.TEXT, "Repository name", source_field="name"),
            SecurityColumn("full_name", ColumnType.TEXT, "Full repository name", source_field="full_name"),
            SecurityColumn("owner", ColumnType.TEXT, "Repository owner", source_field="owner.login"),
            SecurityColumn("private", ColumnType.BOOLEAN, "Private repository", source_field="private"),
            SecurityColumn("archived", ColumnType.BOOLEAN, "Archived repository", source_field="archived"),
            SecurityColumn("disabled", ColumnType.BOOLEAN, "Disabled repository", source_field="disabled"),
            SecurityColumn("default_branch", ColumnType.TEXT, "Default branch", source_field="default_branch"),
            SecurityColumn("visibility", ColumnType.TEXT, "Repository visibility", source_field="visibility"),
            SecurityColumn("security_and_analysis", ColumnType.JSON, "Security settings", source_field="security_and_analysis"),
            SecurityColumn("permissions", ColumnType.JSON, "User permissions", source_field="permissions"),
            SecurityColumn("topics", ColumnType.JSON, "Repository topics", source_field="topics"),
            SecurityColumn("license", ColumnType.JSON, "License information", source_field="license"),
            SecurityColumn("language", ColumnType.TEXT, "Primary language", source_field="language"),
            SecurityColumn("size", ColumnType.INTEGER, "Repository size in KB", source_field="size"),
            SecurityColumn("open_issues_count", ColumnType.INTEGER, "Open issues count", source_field="open_issues_count"),
            SecurityColumn("forks_count", ColumnType.INTEGER, "Forks count", source_field="forks_count"),
            SecurityColumn("stargazers_count", ColumnType.INTEGER, "Stars count", source_field="stargazers_count"),
            SecurityColumn("pushed_at", ColumnType.TIMESTAMP, "Last push date", source_field="pushed_at"),
        ]
        
        super().__init__(
            name="github_repository",
            description="GitHub repositories with security and configuration data",
            provider_name="github",
            columns=repo_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch repositories from GitHub API."""
        client = GitHubClient()
        
        try:
            # Get organization or user repositories
            async for repo in client.list_repositories():
                # Add provider metadata
                repo["provider"] = "github"
                repo["account_id"] = repo["owner"]["login"]  # Use owner as account
                repo["region"] = "global"
                repo["created_at"] = self._parse_github_timestamp(repo.get("created_at"))
                repo["updated_at"] = self._parse_github_timestamp(repo.get("updated_at"))
                
                # Transform topics to tags
                topics = repo.get("topics", [])
                repo["tags"] = {f"topic-{i}": topic for i, topic in enumerate(topics)}
                
                repo["metadata"] = {"github_repo_data": repo}
                
                yield repo
                
        except Exception as e:
            logger.error(f"Error fetching GitHub repositories: {e}")
            raise
    
    def _parse_github_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class GitHubVulnerabilityAlertTable(ProviderSecurityTable):
    """GitHub Dependabot vulnerability alerts as a security table."""
    
    def __init__(self):
        alert_columns = [
            SecurityColumn("alert_id", ColumnType.INTEGER, "Alert ID", required=True, source_field="number"),
            SecurityColumn("repository", ColumnType.TEXT, "Repository full name", transform="get_repo_name"),
            SecurityColumn("state", ColumnType.STATUS, "Alert state", source_field="state"),
            SecurityColumn("dependency", ColumnType.JSON, "Vulnerable dependency", source_field="dependency"),
            SecurityColumn("security_advisory", ColumnType.JSON, "Security advisory", source_field="security_advisory"),
            SecurityColumn("security_vulnerability", ColumnType.JSON, "Vulnerability details", source_field="security_vulnerability"),
            SecurityColumn("url", ColumnType.TEXT, "Alert URL", source_field="url"),
            SecurityColumn("html_url", ColumnType.TEXT, "Web URL", source_field="html_url"),
            SecurityColumn("dismissed_at", ColumnType.TIMESTAMP, "Dismissal timestamp", source_field="dismissed_at"),
            SecurityColumn("dismissed_by", ColumnType.JSON, "Dismissed by user", source_field="dismissed_by"),
            SecurityColumn("dismissed_reason", ColumnType.TEXT, "Dismissal reason", source_field="dismissed_reason"),
            SecurityColumn("dismissed_comment", ColumnType.TEXT, "Dismissal comment", source_field="dismissed_comment"),
            SecurityColumn("fixed_at", ColumnType.TIMESTAMP, "Fix timestamp", source_field="fixed_at"),
        ]
        
        super().__init__(
            name="github_vulnerability_alert",
            description="GitHub Dependabot vulnerability alerts",
            provider_name="github", 
            columns=alert_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch vulnerability alerts from GitHub API."""
        client = GitHubClient()
        
        try:
            # Get alerts for all accessible repositories
            async for alert in client.list_vulnerability_alerts():
                # Add provider metadata
                alert["provider"] = "github"
                alert["account_id"] = alert.get("repository", {}).get("owner", {}).get("login", "")
                alert["region"] = "global"
                alert["created_at"] = self._parse_github_timestamp(alert.get("created_at"))
                alert["updated_at"] = self._parse_github_timestamp(alert.get("updated_at"))
                alert["tags"] = {}
                alert["metadata"] = {"github_alert_data": alert}
                
                # Extract severity from advisory
                advisory = alert.get("security_advisory", {})
                alert["severity"] = advisory.get("severity", "unknown").lower()
                
                yield alert
                
        except Exception as e:
            logger.error(f"Error fetching GitHub vulnerability alerts: {e}")
            raise
    
    def get_repo_name(self, alert_data: Dict[str, Any]) -> str:
        """Extract repository name from alert data."""
        repo = alert_data.get("repository", {})
        return repo.get("full_name", "")
    
    def _parse_github_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class GitHubSecretScanningAlertTable(ProviderSecurityTable):
    """GitHub secret scanning alerts as a security table."""
    
    def __init__(self):
        alert_columns = [
            SecurityColumn("alert_id", ColumnType.INTEGER, "Alert ID", required=True, source_field="number"),
            SecurityColumn("repository", ColumnType.TEXT, "Repository full name", transform="get_repo_name"),
            SecurityColumn("state", ColumnType.STATUS, "Alert state", source_field="state"),
            SecurityColumn("secret_type", ColumnType.TEXT, "Secret type", source_field="secret_type"),
            SecurityColumn("secret_type_display_name", ColumnType.TEXT, "Secret type display", source_field="secret_type_display_name"),
            SecurityColumn("secret", ColumnType.TEXT, "Masked secret", source_field="secret"),
            SecurityColumn("resolution", ColumnType.TEXT, "Resolution method", source_field="resolution"),
            SecurityColumn("resolved_by", ColumnType.JSON, "Resolved by user", source_field="resolved_by"),
            SecurityColumn("resolved_at", ColumnType.TIMESTAMP, "Resolution timestamp", source_field="resolved_at"),
            SecurityColumn("push_protection_bypassed", ColumnType.BOOLEAN, "Push protection bypassed", source_field="push_protection_bypassed"),
            SecurityColumn("push_protection_bypassed_by", ColumnType.JSON, "Bypass user", source_field="push_protection_bypassed_by"),
            SecurityColumn("push_protection_bypassed_at", ColumnType.TIMESTAMP, "Bypass timestamp", source_field="push_protection_bypassed_at"),
            SecurityColumn("locations", ColumnType.JSON, "Secret locations", source_field="locations"),
        ]
        
        super().__init__(
            name="github_secret_scanning_alert",
            description="GitHub secret scanning alerts",
            provider_name="github",
            columns=alert_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch secret scanning alerts from GitHub API."""
        client = GitHubClient()
        
        try:
            async for alert in client.list_secret_scanning_alerts():
                # Add provider metadata
                alert["provider"] = "github"
                alert["account_id"] = alert.get("repository", {}).get("owner", {}).get("login", "")
                alert["region"] = "global"
                alert["created_at"] = self._parse_github_timestamp(alert.get("created_at"))
                alert["updated_at"] = self._parse_github_timestamp(alert.get("updated_at"))
                alert["tags"] = {"secret_type": alert.get("secret_type", "")}
                alert["metadata"] = {"github_secret_alert_data": alert}
                
                # Set severity based on secret type
                alert["severity"] = "high"  # Secrets are generally high severity
                
                yield alert
                
        except Exception as e:
            logger.error(f"Error fetching GitHub secret scanning alerts: {e}")
            raise
    
    def get_repo_name(self, alert_data: Dict[str, Any]) -> str:
        """Extract repository name from alert data."""
        repo = alert_data.get("repository", {})
        return repo.get("full_name", "")
    
    def _parse_github_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GitHub timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


def register_github_tables():
    """Register all GitHub tables with the query engine."""
    register_table(GitHubRepositoryTable(), aliases=['github_repos', 'repositories'])
    register_table(GitHubVulnerabilityAlertTable(), aliases=['github_vuln_alerts', 'dependabot_alerts'])
    register_table(GitHubSecretScanningAlertTable(), aliases=['github_secret_alerts', 'secret_alerts'])
