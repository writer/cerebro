"""Simple dependency injection container for core services."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar, cast

T = TypeVar("T")


class Container:
    """Minimal registry for constructors."""

    def __init__(self) -> None:
        self._factories: dict[type[object], Callable[[], object]] = {}

    def register(self, key: type[T], factory: Callable[[], T]) -> None:
        self._factories[key] = factory

    def resolve(self, key: type[T]) -> T:
        try:
            factory = self._factories[key]
        except KeyError as exc:
            raise KeyError(f"No factory registered for {key}") from exc
        return cast(T, factory())


container = Container()
