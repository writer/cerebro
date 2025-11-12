"""Typed context representation shared across finding producers."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from types import MappingProxyType
from typing import Any
from uuid import UUID

from .rules import coerce_rule_id


class ProducerRunContext(Mapping[str, Any]):
    """Immutable mapping exposing optional metadata for producer runs."""

    __slots__ = ("_extras", "organization_domains", "rule_id")

    def __init__(
        self,
        *,
        rule_id: UUID | str | None = None,
        organization_domains: Iterable[str] | None = None,
        extras: Mapping[str, Any] | None = None,
    ) -> None:
        coerced_rule_id = coerce_rule_id(rule_id)
        self.rule_id: UUID | None = coerced_rule_id

        domains: list[str] = []
        if organization_domains is not None:
            for domain in organization_domains:
                if isinstance(domain, str) and domain:
                    domains.append(domain)
        self.organization_domains: tuple[str, ...] = tuple(domains)

        base_extras: dict[str, Any] = {}
        if extras:
            base_extras.update(extras)

        base_extras.pop("rule_id", None)
        base_extras.pop("organization_domains", None)

        self._extras = MappingProxyType(base_extras)

    @classmethod
    def ensure(
        cls,
        context: ProducerRunContext | Mapping[str, Any] | None,
    ) -> ProducerRunContext | None:
        """Normalize arbitrary context inputs into a run context."""

        if context is None:
            return None

        if isinstance(context, ProducerRunContext):
            return context

        rule_id = context.get("rule_id")
        organization_domains = context.get("organization_domains")

        raw_domains: list[str] = []
        if isinstance(organization_domains, str):
            raw_domains.append(organization_domains)
        elif isinstance(organization_domains, Iterable):
            for domain in organization_domains:
                if isinstance(domain, str) and domain:
                    raw_domains.append(domain)

        extras = {
            key: value
            for key, value in context.items()
            if key not in {"rule_id", "organization_domains"}
        }

        return cls(rule_id=rule_id, organization_domains=raw_domains, extras=extras)

    def __getitem__(self, key: str) -> Any:
        if key == "rule_id":
            return self.rule_id
        if key == "organization_domains":
            return self.organization_domains
        return self._extras[key]

    def __iter__(self) -> Iterator[str]:
        if self.rule_id is not None:
            yield "rule_id"
        if self.organization_domains:
            yield "organization_domains"
        yield from self._extras

    def __len__(self) -> int:
        count = len(self._extras)
        if self.rule_id is not None:
            count += 1
        if self.organization_domains:
            count += 1
        return count

    def get(self, key: str, default: Any = None) -> Any:
        if key == "rule_id":
            return self.rule_id if self.rule_id is not None else default
        if key == "organization_domains":
            return self.organization_domains if self.organization_domains else default
        return self._extras.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        """Expose context values as a shallow dictionary."""

        data: dict[str, Any] = dict(self._extras)
        if self.rule_id is not None:
            data["rule_id"] = self.rule_id
        if self.organization_domains:
            data["organization_domains"] = self.organization_domains
        return data
