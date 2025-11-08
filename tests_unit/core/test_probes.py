import os
import sys
import types

import pytest

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("KMS_PROVIDER", "aws")

from cerebro.core import probes


class _Session:
    async def execute(self, _query):
        return 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):  # noqa: D401 - async context contract
        return False


class _FailingSession(_Session):
    async def execute(self, _query):
        raise RuntimeError("boom")


def _connection_factory(success: bool = True):
    class _Conn:
        def connect(self):
            if not success:
                raise RuntimeError("broker down")

        def release(self):
            return None

    return _Conn()


@pytest.mark.asyncio
async def test_check_database_success(monkeypatch):
    monkeypatch.setattr(probes, "async_session_factory", lambda: _Session())

    healthy, error = await probes.check_database()

    assert healthy is True
    assert error is None


@pytest.mark.asyncio
async def test_check_database_failure(monkeypatch):
    monkeypatch.setattr(probes, "async_session_factory", lambda: _FailingSession())

    healthy, error = await probes.check_database()

    assert healthy is False
    assert error is not None


@pytest.mark.asyncio
async def test_check_celery_workers_success(monkeypatch):
    module = types.SimpleNamespace(
        celery_app=types.SimpleNamespace(
            control=types.SimpleNamespace(ping=lambda timeout: [{"worker@host": "pong"}]),
            connection=lambda: _connection_factory(True),
        )
    )
    monkeypatch.setitem(sys.modules, "cerebro.tasks.celery_app", module)

    healthy, error = await probes.check_celery_workers()

    assert healthy is True
    assert error is None


@pytest.mark.asyncio
async def test_check_celery_workers_failure(monkeypatch):
    module = types.SimpleNamespace(
        celery_app=types.SimpleNamespace(
            control=types.SimpleNamespace(ping=lambda timeout: []),
            connection=lambda: _connection_factory(True),
        )
    )
    monkeypatch.setitem(sys.modules, "cerebro.tasks.celery_app", module)

    healthy, error = await probes.check_celery_workers()

    assert healthy is False
    assert error == "No Celery workers responded to ping"


@pytest.mark.asyncio
async def test_check_broker_connection_failure(monkeypatch):
    module = types.SimpleNamespace(
        celery_app=types.SimpleNamespace(
            control=types.SimpleNamespace(ping=lambda timeout: [{"worker@host": "pong"}]),
            connection=lambda: _connection_factory(False),
        )
    )
    monkeypatch.setitem(sys.modules, "cerebro.tasks.celery_app", module)

    healthy, error = await probes.check_broker_connection()

    assert healthy is False
    assert error == "broker down"


@pytest.mark.asyncio
async def test_run_target_api_ready(monkeypatch):
    module = types.SimpleNamespace(
        celery_app=types.SimpleNamespace(
            control=types.SimpleNamespace(ping=lambda timeout: [{"worker@host": "pong"}]),
            connection=lambda: _connection_factory(True),
        )
    )
    monkeypatch.setitem(sys.modules, "cerebro.tasks.celery_app", module)
    monkeypatch.setattr(probes, "async_session_factory", lambda: _Session())

    ready, checks = await probes._run_target("api-ready", timeout=0.1)

    assert ready is True
    assert checks["database"]["healthy"] is True
