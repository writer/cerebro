import dataclasses
from typing import Any

import pytest

from cerebro.domain.mappers import DomainMapper, MapperRegistry


@dataclasses.dataclass
class Record:
    value: int


@dataclasses.dataclass
class Domain:
    value: int


class RecordMapper(DomainMapper[Record, Domain]):
    def to_domain(self, record: Record) -> Domain:
        return Domain(record.value)

    def to_record(self, domain: Domain) -> Record:
        return Record(domain.value)


def test_register_and_resolve_mapper():
    registry: MapperRegistry[Record, Domain] = MapperRegistry()
    mapper = RecordMapper()

    registry.register(Record, mapper)

    resolved = registry.resolve(Record)
    assert resolved is mapper
    assert list(registry.registered_types()) == [Record]


def test_register_duplicate_mapper_raises():
    registry: MapperRegistry[Record, Domain] = MapperRegistry()
    registry.register(Record, RecordMapper())

    with pytest.raises(ValueError):
        registry.register(Record, RecordMapper())


def test_resolve_missing_mapper_raises():
    registry: MapperRegistry[Record, Domain] = MapperRegistry()

    with pytest.raises(LookupError):
        registry.resolve(Record)
