"""Utilities for building resilient provider connectors.

The helpers defined here centralise common concerns across ingestion
connectors such as executing blocking SDK calls in executors, applying
exponential backoff when transient errors occur, and normalising pagination
loops exposed by provider SDKs.  Consolidating this behaviour keeps each
provider focused on translating API primitives into the collector contracts
without duplicating boilerplate retry logic.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from concurrent.futures import Executor
from typing import (
    Any,
    TypeVar,
)

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)

_STOP = object()

DEFAULT_RETRY_EXCEPTIONS: tuple[type[BaseException], ...] = (Exception,)


def _run_next(iterator: Iterable[T]) -> Any:
    """Advance a synchronous iterator returning a sentinel when exhausted."""

    try:
        return next(iterator)  # type: ignore[call-overload]
    except StopIteration:
        return _STOP


async def call_async_with_retries(
    operation: Callable[[], Awaitable[T]],
    *,
    retries: int = 3,
    backoff: float = 0.5,
    exceptions: Sequence[type[BaseException]] = DEFAULT_RETRY_EXCEPTIONS,
    logger: logging.Logger | None = None,
) -> T:
    """Execute an async callable with exponential backoff retries."""

    attempt = 1
    while True:
        try:
            return await operation()
        except tuple(exceptions) as exc:
            if attempt >= retries:
                raise

            if logger:
                logger.warning(
                    "Async provider call failed; retrying (attempt %s/%s): %s",
                    attempt,
                    retries,
                    exc,
                )

            await asyncio.sleep(backoff * attempt)
            attempt += 1


async def call_sync_with_retries(
    operation: Callable[[], T],
    *,
    retries: int = 3,
    backoff: float = 0.5,
    exceptions: Sequence[type[BaseException]] = DEFAULT_RETRY_EXCEPTIONS,
    logger: logging.Logger | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
    executor: Executor | None = None,
) -> T:
    """Run a blocking callable in the default executor with retries."""

    if loop is None:
        loop = asyncio.get_running_loop()

    attempt = 1
    while True:
        try:
            return await loop.run_in_executor(executor, operation)
        except tuple(exceptions) as exc:
            if attempt >= retries:
                raise

            if logger:
                logger.warning(
                    "Sync provider call failed; retrying (attempt %s/%s): %s",
                    attempt,
                    retries,
                    exc,
                )

            await asyncio.sleep(backoff * attempt)
            attempt += 1


async def iterate_sync_iterator(
    iterator_factory: Callable[[], Iterable[T]],
    *,
    retries: int = 3,
    backoff: float = 0.5,
    exceptions: Sequence[type[BaseException]] = DEFAULT_RETRY_EXCEPTIONS,
    logger: logging.Logger | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
    executor: Executor | None = None,
) -> AsyncIterator[T]:
    """Iterate over a synchronous iterator with retries and executor dispatch."""

    if loop is None:
        loop = asyncio.get_running_loop()

    iterator = iterator_factory()

    while True:
        attempt = 1
        while True:
            try:
                item = await loop.run_in_executor(executor, _run_next, iterator)
                break
            except tuple(exceptions) as exc:
                if attempt >= retries:
                    raise

                if logger:
                    logger.warning(
                        "Paginator iteration error; retrying (attempt %s/%s): %s",
                        attempt,
                        retries,
                        exc,
                    )

                await asyncio.sleep(backoff * attempt)
                attempt += 1

        if item is _STOP:
            break

        yield item  # type: ignore[misc]


def partial(operation: Callable[..., T], *args: Any, **kwargs: Any) -> Callable[[], T]:
    """Return a no-argument callable for convenient retry usage."""

    return functools.partial(operation, *args, **kwargs)


__all__ = [
    "call_async_with_retries",
    "call_sync_with_retries",
    "iterate_sync_iterator",
    "partial",
]
