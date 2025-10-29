import pytest

from cerebro_sdk.config import SettingsProxy, get_settings, refresh_settings


def test_get_settings_cached() -> None:
    first = get_settings()
    second = get_settings()
    assert first is second


def test_refresh_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    current = get_settings()
    refreshed = refresh_settings()

    assert refreshed is get_settings()
    assert refreshed is not current
    assert refreshed.log_level.lower() == "debug"


def test_settings_proxy_snapshot() -> None:
    proxy = SettingsProxy()
    assert proxy.snapshot() is get_settings()
