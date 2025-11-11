"""Unit tests for the :mod:`cerebro.providers.github.provider` adapter."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cerebro.providers.github.provider import GitHubProvider


@pytest.mark.asyncio
async def test_authenticate_requires_token(monkeypatch):
    monkeypatch.setattr("cerebro.providers.github.provider.settings.github_token", None)

    provider = GitHubProvider(account_id="123", org_name="acme")

    assert await provider.authenticate() is False


@pytest.mark.asyncio
async def test_authenticate_success(monkeypatch):
    fake_org = MagicMock()
    fake_user = MagicMock()
    fake_github = MagicMock(
        get_user=MagicMock(return_value=fake_user),
        get_organization=MagicMock(return_value=fake_org),
    )

    monkeypatch.setattr(
        "cerebro.providers.github.provider.settings.github_token",
        "token",
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.Github",
        MagicMock(return_value=fake_github),
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.GitHubProvider._rest_request",
        lambda self, method, endpoint, params=None: {},
    )

    provider = GitHubProvider(account_id="123", org_name="acme")

    assert await provider.authenticate() is True
    fake_github.get_user.assert_called_once()
    fake_github.get_organization.assert_called_once_with("acme")


@pytest.mark.asyncio
async def test_discover_resources_yields_repos(monkeypatch):
    fake_repo = MagicMock(
        full_name="acme/repo",
        name="repo",
        private=False,
        archived=False,
        disabled=False,
        fork=False,
        default_branch="main",
    )
    fake_org = MagicMock(
        get_repos=MagicMock(return_value=[fake_repo]),
        get_teams=MagicMock(return_value=[]),
    )
    fake_github = MagicMock(
        get_user=MagicMock(),
        get_organization=MagicMock(return_value=fake_org),
    )

    monkeypatch.setattr(
        "cerebro.providers.github.provider.settings.github_token",
        "token",
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.Github",
        MagicMock(return_value=fake_github),
    )

    provider = GitHubProvider(account_id="123", org_name="acme")
    await provider.authenticate()

    resources = []
    async for resource in provider.discover_resources():
        resources.append(resource)

    repo_resources = [res for res in resources if res.resource_type == "github.repo"]
    assert repo_resources
    assert repo_resources[0].external_id == "acme/repo"


@pytest.mark.asyncio
async def test_discover_resources_respects_filter(monkeypatch):
    fake_repo = MagicMock(
        full_name="acme/repo",
        name="repo",
        private=False,
        archived=False,
        disabled=False,
        fork=False,
        default_branch="main",
    )
    fake_team = MagicMock(
        id=1,
        name="secops",
        slug="secops",
        description="",
        privacy="closed",
        permission="push",
    )
    fake_org = MagicMock(
        get_repos=MagicMock(return_value=[fake_repo]),
        get_teams=MagicMock(return_value=[fake_team]),
    )
    fake_github = MagicMock(
        get_user=MagicMock(),
        get_organization=MagicMock(return_value=fake_org),
    )

    monkeypatch.setattr(
        "cerebro.providers.github.provider.settings.github_token",
        "token",
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.Github",
        MagicMock(return_value=fake_github),
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.GitHubProvider._rest_request",
        lambda self, method, endpoint, params=None: {},
    )

    provider = GitHubProvider(account_id="123", org_name="acme")
    await provider.authenticate()

    resources = []
    async for resource in provider.discover_resources(["github.team"]):
        resources.append(resource)

    assert len(resources) == 1
    assert resources[0].resource_type == "github.team"


@pytest.mark.asyncio
async def test_discover_iam_edges_for_repo(monkeypatch):
    collaborator = MagicMock(login="octocat")
    repo = MagicMock(
        get_collaborators=MagicMock(return_value=[collaborator]),
        get_collaborator_permission=MagicMock(
            return_value=MagicMock(permission="admin")
        ),
    )
    fake_github = MagicMock(
        get_user=MagicMock(),
        get_repo=MagicMock(return_value=repo),
    )
    membership = MagicMock(role="admin")
    member = MagicMock(login="jane")
    fake_org = MagicMock(
        get_members=MagicMock(return_value=[member]),
        get_membership=MagicMock(return_value=membership),
    )

    monkeypatch.setattr(
        "cerebro.providers.github.provider.settings.github_token",
        "token",
    )
    monkeypatch.setattr(
        "cerebro.providers.github.provider.Github",
        MagicMock(return_value=fake_github),
    )

    provider = GitHubProvider(account_id="123", org_name="acme")
    provider._org = fake_org
    provider._github = fake_github

    resource = MagicMock(resource_type="github.repo", external_id="acme/repo")

    edges = []
    async for edge in provider.discover_iam_edges(resource):
        edges.append(edge)

    assert edges[0].principal_external_id == "octocat"
    assert edges[0].permission == "github.repo.admin"

    org_edge = next(
        edge for edge in edges if edge.resource_external_id is None
    )
    assert org_edge.principal_external_id == "jane"
    assert org_edge.permission == "github.org.admin"
