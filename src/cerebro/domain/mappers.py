"""Shared mapper contracts bridging infrastructure records and domain entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Iterable, MutableMapping, Protocol, Type, TypeVar

RecordT = TypeVar("RecordT")
DomainT = TypeVar("DomainT")
DtoT = TypeVar("DtoT")


class DomainMapper(Protocol[RecordT, DomainT]):
    """Bidirectional mapper between a persistence record and a domain entity."""

    def to_domain(self, record: RecordT) -> DomainT:
        """Convert a stored record into a domain entity."""

    def to_record(self, domain: DomainT) -> RecordT:
        """Convert a domain entity back into its persistence representation."""


class DomainDtoAdapter(Protocol[DomainT, DtoT]):
    """Optional adapter for interface-layer DTO conversions."""

    def to_dto(self, domain: DomainT) -> DtoT:
        """Render the domain entity into a DTO suited for interface layers."""

    def from_dto(self, dto: DtoT) -> DomainT:
        """Rehydrate a domain entity from a DTO payload."""


@dataclass
class MapperRegistry(Generic[RecordT, DomainT]):
    """Registry coordinating mapper lookups by record type."""

    _mappers: MutableMapping[Type[RecordT], DomainMapper[RecordT, DomainT]]

    def __init__(self) -> None:
        self._mappers = {}

    def register(
        self, record_type: Type[RecordT], mapper: DomainMapper[RecordT, DomainT]
    ) -> None:
        """Register a mapper for a given record type."""

        if record_type in self._mappers:
            raise ValueError(f"Mapper already registered for {record_type!r}")
        self._mappers[record_type] = mapper

    def resolve(self, record_type: Type[RecordT]) -> DomainMapper[RecordT, DomainT]:
        """Resolve the mapper associated with a record type."""

        try:
            return self._mappers[record_type]
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise LookupError(f"No mapper registered for {record_type!r}") from exc

    def registered_types(self) -> Iterable[Type[RecordT]]:
        """Return iterable of registered record types."""

        return self._mappers.keys()
