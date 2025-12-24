"""GitHub provider implementation.

The :class:`GitHubProvider` adapts the `PyGithub`_ library to the
``BaseProvider`` contract, allowing the collector to ingest repositories,
members, teams, and associated configuration data from GitHub organisations.

.. _PyGithub: https://pygithub.readthedocs.io/
"""

import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

import requests
from github import Github, GithubException
from github.Organization import Organization

from cerebro.core.config import settings

from ..base import (
    BaseProvider,
    ConfigurationSnapshot,
    IamPermission,
    PrincipalInfo,
    ProviderError,
    ResourceInfo,
)
from ..utils.connector import call_sync_with_retries

logger = logging.getLogger(__name__)


class GitHubProvider(BaseProvider):
    """Collect repositories, principals, and IAM edges from GitHub."""

    def __init__(self, account_id, org_name: str, **kwargs):
        """Instantiate a provider for a specific GitHub organisation."""
        super().__init__(account_id, **kwargs)
        self.org_name = org_name
        self._github: Github | None = None
        self._org: Organization | None = None
        self._runner_group_cache: dict[int, dict[str, Any]] = {}
        self._rest_session: requests.Session | None = None

    @property
    def name(self) -> str:
        """Get provider name."""
        return "github"

    @property
    def github(self) -> Github:
        """Get the authenticated GitHub client, raising if not authenticated."""
        if self._github is None:
            raise ProviderError("GitHub provider not authenticated")
        return self._github

    @property
    def org(self) -> Organization:
        """Get the authenticated organization, raising if not authenticated."""
        if self._org is None:
            raise ProviderError("GitHub provider not authenticated")
        return self._org

    async def authenticate(self) -> bool:
        """Authenticate with GitHub and prime org context."""
        try:
            if not settings.github_token:
                raise ProviderError("GitHub token not configured")

            def _auth():
                self._github = Github(settings.github_token)
                # Test authentication by getting user info
                user = self._github.get_user()
                user.name  # This will raise if token is invalid

                # Get organization
                self._org = self._github.get_organization(self.org_name)
                self._org.name  # Test org access
                return True

            return await call_sync_with_retries(
                _auth,
                exceptions=(GithubException,),
                logger=logger,
            )

        except GithubException as e:
            logger.error(f"GitHub authentication failed: {e}")
            raise ProviderError(f"GitHub authentication failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during GitHub auth: {e}")
            return False

    async def discover_resources(
        self, resource_types: list[str] | None = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GitHub resources (repositories, teams)."""
        if not self._org:
            await self.authenticate()

        # Organization resource
        if not resource_types or "github.org" in resource_types:
            org_metadata = {
                "id": getattr(self.org, "id", None),
                "login": self.org.login,
                "description": getattr(self.org, "description", None),
                "html_url": getattr(self.org, "html_url", None),
                "is_verified": getattr(self.org, "is_verified", None),
            }

            yield ResourceInfo(
                external_id=self.org.login,
                name=self.org.name or self.org.login,
                resource_type="github.org",
                metadata=org_metadata,
            )

        # Discover repositories
        if not resource_types or "github.repo" in resource_types:

            def _get_repos():
                return list(self.org.get_repos())

            repos = await call_sync_with_retries(
                _get_repos,
                exceptions=(GithubException,),
                logger=logger,
            )

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
                    },
                )

        # Discover teams
        if not resource_types or "github.team" in resource_types:

            def _get_teams():
                return list(self.org.get_teams())

            teams = await call_sync_with_retries(
                _get_teams,
                exceptions=(GithubException,),
                logger=logger,
            )

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
                    },
                )

        if not resource_types or "github.runner" in resource_types:
            async for runner_resource in self._discover_runners():
                yield runner_resource

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover GitHub users and teams."""
        if not self._org:
            await self.authenticate()

        # Discover organization members
        def _get_members():
            return list(self.org.get_members())

        members = await call_sync_with_retries(
            _get_members,
            exceptions=(GithubException,),
            logger=logger,
        )

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
                },
            )

        # Discover teams (as group principals)
        def _get_teams():
            return list(self.org.get_teams())

        teams = await call_sync_with_retries(
            _get_teams,
            exceptions=(GithubException,),
            logger=logger,
        )

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
                },
            )

    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get GitHub resource configuration."""
        if not self._github:
            await self.authenticate()

        if resource.resource_type == "github.repo":

            def _get_repo_config():
                repo = self.github.get_repo(resource.external_id)

                # Get branch protection for default branch
                branch_protection = None
                try:
                    default_branch = repo.get_branch(repo.default_branch)
                    if default_branch.protected:
                        protection = default_branch.get_protection()
                        branch_protection = {
                            "requirePR": protection.required_pull_request_reviews
                            is not None,
                            "requiredReviewers": (
                                protection.required_pull_request_reviews.required_approving_review_count
                                if protection.required_pull_request_reviews
                                else 0
                            ),
                            "dismissStaleReviews": (
                                protection.required_pull_request_reviews.dismiss_stale_reviews
                                if protection.required_pull_request_reviews
                                else False
                            ),
                            "requireCodeOwnerReviews": (
                                protection.required_pull_request_reviews.require_code_owner_reviews
                                if protection.required_pull_request_reviews
                                else False
                            ),
                            "enforceAdmins": (
                                protection.enforce_admins.enabled  # type: ignore[attr-defined]
                                if protection.enforce_admins and hasattr(protection.enforce_admins, "enabled")
                                else bool(protection.enforce_admins)
                            ),
                        }
                except Exception as e:
                    logger.debug(
                        f"Could not get branch protection for {resource.external_id}: {e}"
                    )

                config = {
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
                    "webhooks": [
                        {"url": hook.config.get("url", ""), "events": hook.events}
                        for hook in repo.get_hooks()
                    ],
                }

                return config

            config = await call_sync_with_retries(
                _get_repo_config,
                exceptions=(GithubException,),
                logger=logger,
            )

            try:
                actions_permissions = await call_sync_with_retries(
                    lambda: self._rest_request(
                        "GET",
                        f"/repos/{resource.external_id}/actions/permissions",
                    ),
                    exceptions=(requests.RequestException,),
                    logger=logger,
                )
            except requests.RequestException as exc:
                logger.debug(
                    f"Unable to fetch actions permissions for {resource.external_id}: {exc}"
                )
                actions_permissions = None

            if actions_permissions:
                config["actionsPermissions"] = actions_permissions

        elif resource.resource_type == "github.team":

            def _get_team_config():
                team = self.org.get_team(int(resource.external_id))
                return {
                    "name": team.name,
                    "slug": team.slug,
                    "description": team.description,
                    "privacy": team.privacy,
                    "permission": team.permission,
                    "membersCount": team.members_count,
                }

            config = await call_sync_with_retries(
                _get_team_config,
                exceptions=(GithubException,),
                logger=logger,
            )

        else:
            if resource.resource_type == "github.runner":
                config = await self._build_runner_configuration(resource)
            elif resource.resource_type == "github.org":
                config = await self._build_org_configuration(resource)
            else:
                config = {}

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config,
        )

    async def discover_iam_edges(
        self, resource: ResourceInfo | None = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover GitHub permissions."""
        if not self._org:
            await self.authenticate()

        if resource and resource.resource_type == "github.repo":
            # Repository-specific permissions
            def _get_repo_permissions():
                repo = self.github.get_repo(resource.external_id)
                collaborators = repo.get_collaborators()

                permissions = []
                for collab in collaborators:
                    perm = repo.get_collaborator_permission(collab)
                    # perm can be a string or an object with permission attribute
                    perm_str = perm.permission if hasattr(perm, "permission") else str(perm)
                    permissions.append(
                        {
                            "principal": collab.login,
                            "permission": perm_str,
                            "is_admin": perm_str == "admin",
                        }
                    )

                return permissions

            perms = await call_sync_with_retries(
                _get_repo_permissions,
                exceptions=(GithubException,),
                logger=logger,
            )

            for perm in perms:
                yield IamPermission(
                    principal_external_id=perm["principal"],
                    resource_external_id=resource.external_id,
                    permission=f"github.repo.{perm['permission']}",
                    effective_at=datetime.utcnow(),
                    is_admin=perm["is_admin"],
                )

        # Organization-level permissions
        def _get_org_permissions():
            members = self.org.get_members()
            permissions = []

            for member in members:
                membership = self.org.get_membership(member)  # type: ignore[attr-defined]
                permissions.append(
                    {
                        "principal": member.login,
                        "role": membership.role,
                        "is_admin": membership.role == "admin",
                    }
                )

            return permissions

        org_perms = await call_sync_with_retries(
            _get_org_permissions,
            exceptions=(GithubException,),
            logger=logger,
        )

        for perm in org_perms:
            yield IamPermission(
                principal_external_id=perm["principal"],
                resource_external_id=None,  # Org-level permission
                permission=f"github.org.{perm['role']}",
                effective_at=datetime.utcnow(),
                is_admin=perm["is_admin"],
            )

    async def _discover_runners(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover self-hosted GitHub Actions runners."""
        try:
            runner_groups = await self._list_runner_groups()
        except Exception as exc:
            logger.error(f"Failed to list runner groups: {exc}")
            runner_groups = {}

        page = 1
        per_page = 100
        while True:
            try:
                runners_payload = await call_sync_with_retries(
                    lambda: self._rest_request(
                        "GET",
                        f"/orgs/{self.org_name}/actions/runners",
                        params={"per_page": per_page, "page": page},
                    ),
                    exceptions=(requests.RequestException,),
                    logger=logger,
                )
            except requests.RequestException as exc:
                logger.debug(
                    f"Skipping GitHub runner discovery due to API error: {exc}"
                )
                break

            runners = runners_payload.get("runners", [])
            if not runners:
                break

            for runner in runners:
                runner_id = runner.get("id")
                group_id = runner.get("runner_group_id")
                group_info = runner_groups.get(group_id)

                metadata = {
                    "runner_id": runner_id,
                    "name": runner.get("name"),
                    "os": runner.get("os"),
                    "status": runner.get("status"),
                    "busy": runner.get("busy"),
                    "ephemeral": runner.get("ephemeral"),
                    "managed": runner.get("managed"),
                    "labels": [label.get("name") for label in runner.get("labels", [])],
                    "runner_group_id": group_id,
                    "runner_group_name": runner.get("runner_group_name")
                    or (group_info or {}).get("name"),
                    "runner_group_visibility": (group_info or {}).get("visibility"),
                    "allows_public_repositories": (group_info or {}).get(
                        "allows_public_repositories"
                    ),
                }

                yield ResourceInfo(
                    external_id=str(runner_id),
                    name=runner.get("name"),
                    resource_type="github.runner",
                    metadata=metadata,
                )

            if len(runners) < per_page:
                break
            page += 1

    async def _list_runner_groups(self) -> dict[int, dict[str, Any]]:
        if self._runner_group_cache:
            return self._runner_group_cache

        page = 1
        per_page = 100
        groups: dict[int, dict[str, Any]] = {}

        while True:
            try:
                payload = await call_sync_with_retries(
                    lambda: self._rest_request(
                        "GET",
                        f"/orgs/{self.org_name}/actions/runner-groups",
                        params={"per_page": per_page, "page": page},
                    ),
                    exceptions=(requests.RequestException,),
                    logger=logger,
                )
            except requests.RequestException as exc:
                logger.debug(f"Unable to enumerate runner groups: {exc}")
                break

            for group in payload.get("runner_groups", []) or []:
                groups[group["id"]] = group

            if len(payload.get("runner_groups", []) or []) < per_page:
                break

            page += 1

        self._runner_group_cache = groups
        return groups

    async def _get_runner_group(
        self, group_id: int | None
    ) -> dict[str, Any] | None:
        if not group_id:
            return None

        if (
            group_id in self._runner_group_cache
            and self._runner_group_cache[group_id].get("allows_public_repositories")
            is not None
        ):
            return self._runner_group_cache[group_id]

        group_payload = await call_sync_with_retries(
            lambda: self._rest_request(
                "GET",
                f"/orgs/{self.org_name}/actions/runner-groups/{group_id}",
            ),
            exceptions=(requests.RequestException,),
            logger=logger,
        )

        self._runner_group_cache[group_id] = group_payload
        return group_payload

    async def _list_runner_group_repositories(
        self, group_id: int | None
    ) -> list[dict[str, Any]]:
        if not group_id:
            return []

        page = 1
        per_page = 100
        repositories: list[dict[str, Any]] = []

        while True:
            payload = await call_sync_with_retries(
                lambda: self._rest_request(
                    "GET",
                    f"/orgs/{self.org_name}/actions/runner-groups/{group_id}/repositories",
                    params={"per_page": per_page, "page": page},
                ),
                exceptions=(requests.RequestException,),
                logger=logger,
            )

            repos = payload.get("repositories", []) or []
            if not repos:
                break

            for repo in repos:
                repositories.append(
                    {
                        "id": repo.get("id"),
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "private": repo.get("private"),
                        "visibility": repo.get("visibility")
                        or ("private" if repo.get("private") else "public"),
                    }
                )

            if len(repos) < per_page:
                break

            page += 1

        return repositories

    async def _build_runner_configuration(
        self, resource: ResourceInfo
    ) -> dict[str, Any]:
        runner_id = resource.metadata.get("runner_id") if resource.metadata else None
        if not runner_id:
            runner_id = resource.external_id

        runner_detail = await call_sync_with_retries(
            lambda: self._rest_request(
                "GET",
                f"/orgs/{self.org_name}/actions/runners/{runner_id}",
            ),
            exceptions=(requests.RequestException,),
            logger=logger,
        )

        group_id = runner_detail.get("runner_group_id")
        runner_group = await self._get_runner_group(group_id)
        repositories = await self._list_runner_group_repositories(group_id)

        runner_info = {
            "id": runner_detail.get("id"),
            "name": runner_detail.get("name"),
            "display_name": runner_detail.get("display_name"),
            "os": runner_detail.get("os"),
            "status": runner_detail.get("status"),
            "busy": runner_detail.get("busy"),
            "labels": [label.get("name") for label in runner_detail.get("labels", [])],
            "architecture": runner_detail.get("architecture"),
            "ephemeral": runner_detail.get("ephemeral"),
            "managed": runner_detail.get("managed"),
            "connected_at": runner_detail.get("connected_at"),
            "last_check_in": runner_detail.get("last_check_in_at"),
            "ip_address": runner_detail.get("ip_address")
            or runner_detail.get("local_ip"),
            "public_ip": runner_detail.get("public_ip"),
            "version": runner_detail.get("version"),
            "runner_group_id": group_id,
        }

        group_info = None
        if runner_group:
            group_info = {
                "id": runner_group.get("id"),
                "name": runner_group.get("name"),
                "visibility": runner_group.get("visibility"),
                "allows_public_repositories": runner_group.get(
                    "allows_public_repositories"
                ),
                "restricted_to_workflows": runner_group.get("restricted_to_workflows"),
                "default": runner_group.get("default"),
                "created_at": runner_group.get("created_at"),
                "updated_at": runner_group.get("updated_at"),
            }

        return {
            "runner": runner_info,
            "runner_group": group_info,
            "repositories": repositories,
        }

    def _rest_request(
        self, method: str, endpoint: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if not settings.github_token:
            raise ProviderError("GitHub token not configured")

        url = f"https://api.github.com{endpoint}"
        headers = {
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cerebro-integrations",
        }

        session = self._rest_session
        if session is None:
            session = requests.Session()
            self._rest_session = session

        response = session.request(
            method, url, params=params, timeout=20, headers=headers
        )

        if response.status_code == 404:
            logger.debug(f"GitHub REST resource not found for {endpoint}")
            raise requests.HTTPError(f"Not found: {endpoint}", response=response)

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            logger.error(f"GitHub REST call failed ({endpoint}): {exc}")
            raise

        return response.json()

    async def _build_org_configuration(self, resource: ResourceInfo) -> dict[str, Any]:
        org_login = resource.external_id or self.org_name

        try:
            org_data = await call_sync_with_retries(
                lambda: self._rest_request("GET", f"/orgs/{org_login}"),
                exceptions=(requests.RequestException,),
                logger=logger,
            )
        except requests.RequestException as exc:
            logger.debug(
                f"Unable to fetch organization metadata for {org_login}: {exc}"
            )
            org_data = {}

        try:
            actions_permissions = await call_sync_with_retries(
                lambda: self._rest_request(
                    "GET", f"/orgs/{org_login}/actions/permissions"
                ),
                exceptions=(requests.RequestException,),
                logger=logger,
            )
        except requests.RequestException as exc:
            logger.debug(
                f"Unable to fetch organization actions permissions for {org_login}: {exc}"
            )
            actions_permissions = None

        if actions_permissions:
            org_data["actionsPermissions"] = actions_permissions

        return org_data
