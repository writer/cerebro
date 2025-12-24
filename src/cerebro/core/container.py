"""Simple dependency injection container for core services."""

from __future__ import annotations

from typing import Callable, Dict, Type, TypeVar, cast

T = TypeVar("T")


class Container:
    """Minimal registry for constructors."""

    def __init__(self) -> None:
        self._factories: Dict[Type[object], Callable[[], object]] = {}

    def register(self, key: Type[T], factory: Callable[[], T]) -> None:
        self._factories[key] = factory

    def resolve(self, key: Type[T]) -> T:
        try:
            factory = self._factories[key]
        except KeyError as exc:
            raise KeyError(f"No factory registered for {key}") from exc
        return cast(T, factory())


container = Container()
