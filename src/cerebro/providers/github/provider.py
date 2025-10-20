"""GitHub provider implementation.

The :class:`GitHubProvider` adapts the `PyGithub`_ library to the
``BaseProvider`` contract, allowing the collector to ingest repositories,
members, teams, and associated configuration data from GitHub organisations.

.. _PyGithub: https://pygithub.readthedocs.io/
"""

from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
import logging
import asyncio

from github import Github, GithubException
from github.Repository import Repository
from github.Organization import Organization
from github.Team import Team
from github.NamedUser import NamedUser

from cerebro.core.config import settings
from ..base import (
    BaseProvider, ResourceInfo, PrincipalInfo, 
    ConfigurationSnapshot, IamPermission, ProviderError
)

logger = logging.getLogger(__name__)


class GitHubProvider(BaseProvider):
    """Collect repositories, principals, and IAM edges from GitHub."""
    
    def __init__(self, account_id, org_name: str, **kwargs):
        """Instantiate a provider for a specific GitHub organisation."""
        super().__init__(account_id, **kwargs)
        self.org_name = org_name
        self._github: Optional[Github] = None
        self._org: Optional[Organization] = None
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "github"
    
    async def authenticate(self) -> bool:
        """Authenticate with GitHub and prime org context."""
        try:
            if not settings.github_token:
                raise ProviderError("GitHub token not configured")
            
            # Run sync GitHub operations in executor
            loop = asyncio.get_event_loop()
            
            def _auth():
                self._github = Github(settings.github_token)
                # Test authentication by getting user info
                user = self._github.get_user()
                user.name  # This will raise if token is invalid
                
                # Get organization
                self._org = self._github.get_organization(self.org_name)
                self._org.name  # Test org access
                return True
            
            return await loop.run_in_executor(None, _auth)
            
        except GithubException as e:
            logger.error(f"GitHub authentication failed: {e}")
            raise ProviderError(f"GitHub authentication failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during GitHub auth: {e}")
            return False
    
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GitHub resources (repositories, teams)."""
        if not self._org:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        # Discover repositories
        if not resource_types or "github.repo" in resource_types:
            def _get_repos():
                return list(self._org.get_repos())
            
            repos = await loop.run_in_executor(None, _get_repos)
            
            for repo in repos:
                yield ResourceInfo(
                    external_id=repo.full_name,
                    name=repo.name,
                    resource_type="github.repo",
                    metadata={
                        "private": repo.private,
                        "archived": repo.archived,
                        "disabled": repo.disabled,
                        "fork": repo.fork,
                        "default_branch": repo.default_branch,
                    }
                )
        
        # Discover teams
        if not resource_types or "github.team" in resource_types:
            def _get_teams():
                return list(self._org.get_teams())
            
            teams = await loop.run_in_executor(None, _get_teams)
            
            for team in teams:
                yield ResourceInfo(
                    external_id=str(team.id),
                    name=team.name,
                    resource_type="github.team",
                    metadata={
                        "slug": team.slug,
                        "description": team.description,
                        "privacy": team.privacy,
                        "permission": team.permission,
                    }
                )
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover GitHub users and teams."""
        if not self._org:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        # Discover organization members
        def _get_members():
            return list(self._org.get_members())
        
        members = await loop.run_in_executor(None, _get_members)
        
        for member in members:
            yield PrincipalInfo(
                external_id=member.login,
                principal_type="user",
                display_name=member.name,
                is_human=True,
                metadata={
                    "type": member.type,
                    "site_admin": member.site_admin,
                    "company": member.company,
                    "location": member.location,
                }
            )
        
        # Discover teams (as group principals)
        def _get_teams():
            return list(self._org.get_teams())
        
        teams = await loop.run_in_executor(None, _get_teams)
        
        for team in teams:
            yield PrincipalInfo(
                external_id=team.slug,
                principal_type="group",
                display_name=team.name,
                is_human=False,
                metadata={
                    "id": team.id,
                    "description": team.description,
                    "privacy": team.privacy,
                    "members_count": team.members_count,
                }
            )
    
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get GitHub resource configuration."""
        if not self._github:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        if resource.resource_type == "github.repo":
            def _get_repo_config():
                repo = self._github.get_repo(resource.external_id)
                
                # Get branch protection for default branch
                branch_protection = None
                try:
                    default_branch = repo.get_branch(repo.default_branch)
                    if default_branch.protected:
                        protection = default_branch.get_protection()
                        branch_protection = {
                            "requirePR": protection.required_pull_request_reviews is not None,
                            "requiredReviewers": protection.required_pull_request_reviews.required_approving_review_count if protection.required_pull_request_reviews else 0,
                            "dismissStaleReviews": protection.required_pull_request_reviews.dismiss_stale_reviews if protection.required_pull_request_reviews else False,
                            "requireCodeOwnerReviews": protection.required_pull_request_reviews.require_code_owner_reviews if protection.required_pull_request_reviews else False,
                            "enforceAdmins": protection.enforce_admins.enabled if protection.enforce_admins else False,
                        }
                except Exception as e:
                    logger.debug(f"Could not get branch protection for {resource.external_id}: {e}")
                
                return {
                    "name": repo.name,
                    "fullName": repo.full_name,
                    "private": repo.private,
                    "visibility": "private" if repo.private else "public",
                    "archived": repo.archived,
                    "disabled": repo.disabled,
                    "fork": repo.fork,
                    "defaultBranch": repo.default_branch,
                    "hasWiki": repo.has_wiki,
                    "hasIssues": repo.has_issues,
                    "hasProjects": repo.has_projects,
                    "hasDownloads": repo.has_downloads,
                    "allowMergeCommit": repo.allow_merge_commit,
                    "allowSquashMerge": repo.allow_squash_merge,
                    "allowRebaseMerge": repo.allow_rebase_merge,
                    "branchProtection": branch_protection,
                    "webhooks": [{"url": hook.config.get("url", ""), "events": hook.events} for hook in repo.get_hooks()],
                }
            
            config = await loop.run_in_executor(None, _get_repo_config)
            
        elif resource.resource_type == "github.team":
            def _get_team_config():
                team = self._org.get_team(int(resource.external_id))
                return {
                    "name": team.name,
                    "slug": team.slug,
                    "description": team.description,
                    "privacy": team.privacy,
                    "permission": team.permission,
                    "membersCount": team.members_count,
                }
            
            config = await loop.run_in_executor(None, _get_team_config)
        
        else:
            config = {}
        
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config
        )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover GitHub permissions."""
        if not self._org:
            await self.authenticate()
        
        loop = asyncio.get_event_loop()
        
        if resource and resource.resource_type == "github.repo":
            # Repository-specific permissions
            def _get_repo_permissions():
                repo = self._github.get_repo(resource.external_id)
                collaborators = repo.get_collaborators()
                
                permissions = []
                for collab in collaborators:
                    perm = repo.get_collaborator_permission(collab)
                    permissions.append({
                        "principal": collab.login,
                        "permission": perm.permission,
                        "is_admin": perm.permission == "admin"
                    })
                
                return permissions
            
            perms = await loop.run_in_executor(None, _get_repo_permissions)
            
            for perm in perms:
                yield IamPermission(
                    principal_external_id=perm["principal"],
                    resource_external_id=resource.external_id,
                    permission=f"github.repo.{perm['permission']}",
                    effective_at=datetime.utcnow(),
                    is_admin=perm["is_admin"]
                )
        
        # Organization-level permissions
        def _get_org_permissions():
            members = self._org.get_members()
            permissions = []
            
            for member in members:
                membership = self._org.get_membership(member)
                permissions.append({
                    "principal": member.login,
                    "role": membership.role,
                    "is_admin": membership.role == "admin"
                })
            
            return permissions
        
        org_perms = await loop.run_in_executor(None, _get_org_permissions)
        
        for perm in org_perms:
            yield IamPermission(
                principal_external_id=perm["principal"],
                resource_external_id=None,  # Org-level permission
                permission=f"github.org.{perm['role']}",
                effective_at=datetime.utcnow(),
                is_admin=perm["is_admin"]
            )
