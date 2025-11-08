import asyncio
from typing import List

import pytest

from cerebro.providers.utils.connector import (
    call_async_with_retries,
    call_sync_with_retries,
    iterate_sync_iterator,
)


class FailableCallable:
    def __init__(self, failures: int, result):
        self._failures = failures
        self._result = result
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls <= self._failures:
            raise RuntimeError("boom")
        return self._result


@pytest.mark.asyncio
async def test_call_sync_with_retries_succeeds_after_retries():
    operation = FailableCallable(failures=2, result="ok")
    result = await call_sync_with_retries(operation, retries=3, backoff=0.01, exceptions=(RuntimeError,))
    assert result == "ok"
    assert operation.calls == 3


@pytest.mark.asyncio
async def test_call_sync_with_retries_raises_after_exhausting_attempts():
    operation = FailableCallable(failures=5, result="never")
    with pytest.raises(RuntimeError):
        await call_sync_with_retries(operation, retries=3, backoff=0.01, exceptions=(RuntimeError,))
    assert operation.calls == 3


@pytest.mark.asyncio
async def test_call_async_with_retries_handles_coroutines():
    calls: List[int] = []

    async def op():
        calls.append(1)
        if len(calls) < 2:
            raise ValueError("retry")
        return "done"

    result = await call_async_with_retries(op, retries=3, backoff=0.01, exceptions=(ValueError,))
    assert result == "done"
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_iterate_sync_iterator_yields_values_in_order():
    def generator():
        for i in range(3):
            yield i

    collected = []
    async for item in iterate_sync_iterator(generator):
        collected.append(item)

    assert collected == [0, 1, 2]


@pytest.mark.asyncio
async def test_iterate_sync_iterator_retries_on_error(monkeypatch):
    attempts = {"count": 0}

    def generator():
        def _inner():
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("transient")
            yield 42

        return _inner()

    async for item in iterate_sync_iterator(generator, retries=2, backoff=0.01, exceptions=(RuntimeError,)):
        assert item == 42
        break
