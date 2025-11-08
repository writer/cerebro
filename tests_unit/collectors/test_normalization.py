import os

os.environ.setdefault("ENVIRONMENT", "development")

from cerebro.collectors.normalization import normalize_exposure, normalize_severity


def test_normalize_severity_provider_specific_override():
    assert normalize_severity("MODERATE", provider="github") == "medium"


def test_normalize_severity_default_fallback():
    assert normalize_severity("informational", provider="unknown") == "informational"


def test_normalize_severity_unknown_input():
    assert normalize_severity("mystery", provider="github") == "unknown"


def test_normalize_exposure_default_mapping():
    assert normalize_exposure("External", provider="github") == "public"


def test_normalize_exposure_unknown_returns_unknown():
    assert normalize_exposure(None, provider="github") == "unknown"
