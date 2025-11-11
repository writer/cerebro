import pytest

from cerebro.core.config import IntegrationRetrySettings, Settings


def test_settings_migrates_legacy_auth_fields(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")

    settings = Settings(
        secret_key="super-secret",
        algorithm="HS512",
        access_token_expire_minutes=60,
        refresh_token_expire_days=3,
    )

    assert settings.auth.secret_key is not None
    assert settings.secret_key == "super-secret"
    assert settings.algorithm == "HS512"
    assert settings.access_token_expire_minutes == 60
    assert settings.refresh_token_expire_days == 3


def test_settings_requires_secret_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(ValueError):
        Settings(environment="production")


def test_integration_retry_properties_expose_nested(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")

    settings = Settings(
        integration_retry=IntegrationRetrySettings(
            enabled=False,
            cooldown_seconds=900,
            lookback_minutes=None,
        )
    )

    assert settings.integration_retry.enabled is False
    assert settings.integration_sync_retry_enabled is False
    assert settings.integration_sync_retry_cooldown_seconds == 900
    assert settings.integration_sync_retry_lookback_minutes is None
