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
