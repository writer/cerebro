from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cerebro.providers.aws.provider import AWSProvider


@pytest.mark.asyncio
async def test_authenticate_success(monkeypatch):
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    session.client.return_value = sts

    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_access_key_id", "id")
    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_secret_access_key", "secret")
    monkeypatch.setattr("cerebro.providers.aws.provider.boto3.Session", MagicMock(return_value=session))

    provider = AWSProvider(account_id="acct", aws_account_id="123456789012", region="us-east-1")

    assert await provider.authenticate() is True
    session.client.assert_called_with("sts")


@pytest.mark.asyncio
async def test_authenticate_wrong_account(monkeypatch):
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "000000000000"}
    session.client.return_value = sts

    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_access_key_id", "id")
    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_secret_access_key", "secret")
    monkeypatch.setattr("cerebro.providers.aws.provider.boto3.Session", MagicMock(return_value=session))

    provider = AWSProvider(account_id="acct", aws_account_id="123456789012", region="us-east-1")

    assert await provider.authenticate() is False


@pytest.mark.asyncio
async def test_discover_principals_yields_users(monkeypatch):
    def paginator_for(name):
        paginator = MagicMock()
        if name == "list_users":
            paginator.paginate.return_value = [{
                "Users": [
                    {
                        "Arn": "arn",
                        "UserName": "alice",
                        "Path": "/",
                        "CreateDate": MagicMock(isoformat=lambda: "now"),
                        "PasswordLastUsed": None,
                    }
                ]
            }]
        elif name == "list_roles":
            paginator.paginate.return_value = [{"Roles": []}]
        else:
            paginator.paginate.return_value = [{"Groups": []}]
        return paginator

    sts_client = MagicMock()
    sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

    iam_client = MagicMock()
    iam_client.get_paginator.side_effect = paginator_for

    session = MagicMock()

    def select_client(service_name):
        if service_name == "sts":
            return sts_client
        return iam_client

    session.client.side_effect = select_client

    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_access_key_id", "id")
    monkeypatch.setattr("cerebro.providers.aws.provider.settings.aws_secret_access_key", "secret")
    monkeypatch.setattr("cerebro.providers.aws.provider.boto3.Session", MagicMock(return_value=session))

    provider = AWSProvider(account_id="acct", aws_account_id="123456789012", region="us-east-1")
    assert await provider.authenticate() is True

    principals = []
    async for principal in provider.discover_principals():
        principals.append(principal)

    assert principals[0].principal_type == "user"
    assert principals[0].display_name == "alice"
