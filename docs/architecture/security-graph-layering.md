# Security Graph Layering Refactor

## 1. Current Package Inventory

| Package | Primary Responsibility | Notable Dependencies |
|---------|------------------------|-----------------------|
| `cerebro.core` | SQLAlchemy models, configuration, database/session utilities, observability | Imported by almost every subsystem including `attack_path`, `query`, `collectors` |
| `cerebro.attack_path` | Service identity discovery, graph construction, scoring, path analysis | Depends on `core` models, query engine, providers; exports FastAPI routes via `api` |
| `cerebro.query` | Query engine, table registry, analytics helpers | Pulls from `core.database`, `core.models`, and exposes helpers consumed by `attack_path`, `agents` |
| `cerebro.collectors` | Ingestion pipelines and normalization rules | Uses provider SDK adapters (`providers`), writes via `core.models` |
| `cerebro.providers` | External API clients & adapters | Depends on `core.config`, `core.database` and sometimes `query` for bootstrap |
| `cerebro.domain` | Dataclass entities & ports abstractions | Light-weight but currently bypassed by most ingestion paths |
| `cerebro.infrastructure` | Provider registry, adapter orchestration | Couples domain ports to provider implementations |
| `cerebro.agents` | Tooling wrappers, runtime orchestration | Imports `query` and `attack_path` directly |
| `cerebro.api` | FastAPI application and route composition | Glues routes from `attack_path`, `query`, `collectors`, etc. |

### Key Observations

- `attack_path` blends graph domain logic, persistence lookups, and API wiring in a single package.
- `query` provides both infrastructural table bootstrap and higher-level analytics without clear separation.
- Domain dataclasses in `cerebro.domain.entities` duplicate fields from SQLAlchemy models (`core.models`) and DTOs defined in API schemas.
- Provider ingestion workflows call directly into SQLAlchemy models, bypassing domain interfaces defined in `cerebro.domain`.

## 2. Proposed Layered Architecture

```
┌────────────────────────────┐
│ Interface Layer            │  → FastAPI routers, CLI entrypoints, SDK façade
├────────────────────────────┤
│ Domain Layer               │  → Entities, aggregates, mapping interfaces, domain services
├────────────────────────────┤
│ Ingestion / Application    │  → Collectors, attack-graph builders, schedulers orchestrating use cases
├────────────────────────────┤
│ Infrastructure Layer       │  → SQLAlchemy models, provider adapters, task queues, persistence mappers
└────────────────────────────┘
```

### Layer Ownership

- **Interface** (new `cerebro.interface` namespace): will host FastAPI routers, CLI commands, and any SDK-specific DTOs. Existing content in `cerebro.api` and selected `agents.tools` modules migrate here.
- **Domain** (`cerebro.domain`): becomes the single source of truth for graph entities, query projections, and business rules. New mapper contracts (see §3) mediate between persistence records and domain objects.
- **Ingestion/Application** (`cerebro.application` and `attack_path` orchestrators): coordinates workflows (e.g., building service identity edges, triggering collectors) while depending only on domain ports.
- **Infrastructure** (`cerebro.infrastructure`, `core`, `providers`): remains responsible for persistence, external service integration, and message queues. `core` will be narrowed to platform primitives (config, db sessions, telemetry, SQLAlchemy metadata).

### Package Reassignment Snapshot

| Current Module | Future Home | Notes |
|----------------|-------------|-------|
| `attack_path.graph_model` | Split: domain graph aggregates + application service | Domain portion (`AttackGraph`, scoring) moves to `domain.graph`, orchestration remains in `application.attack_graph` |
| `attack_path.service_identity` | Application layer | Discovery routines depend on infrastructure providers; results surfaced via domain mappers |
| `attack_path.scoring` | Domain layer | Already largely pure; will move under `cerebro.domain.graph.scoring` |
| `query.engine` | Infrastructure (engine) + domain projections | Bootstrap logic stays infra, query result DTOs move to domain |
| `collectors.*` | Application ingestion | Will consume domain mappers instead of writing SQLAlchemy models directly |
| `providers.*` | Infrastructure | Continue to implement adapters fulfilling domain ports |

## 3. Shared Mapper Strategy

Introduce `cerebro.domain.mappers` to define reusable conversions:

- `RecordT` → `DomainT`: hydrate domain entities from SQLAlchemy rows or provider payloads.
- `DomainT` → `RecordT`: persist aggregate changes via infrastructure repositories.
- Optional `to_dto` helpers for interface-layer serialization without leaking ORM models.

Core constructs:

```python
from typing import Generic, Protocol, TypeVar

RecordT = TypeVar("RecordT")
DomainT = TypeVar("DomainT")
DtoT = TypeVar("DtoT")

class DomainMapper(Protocol[RecordT, DomainT]):
    def to_domain(self, record: RecordT) -> DomainT: ...
    def to_record(self, domain: DomainT) -> RecordT: ...

class MapperRegistry(Generic[RecordT, DomainT]):
    def register(self, mapper: DomainMapper[RecordT, DomainT]) -> None: ...
    def resolve(self, record_type: type[RecordT]) -> DomainMapper[RecordT, DomainT]: ...
```

This registry becomes the single entry point used by collectors, attack graph builders, and interface serializers. Transition helpers will live alongside initial mapper implementations (e.g., `GraphNodeMapper`, `ServiceIdentityMapper`).

## 4. Transition Plan & Follow-Up Tasks

1. **Mapper Foundations (this change)**
   - Add `cerebro.domain.mappers` module with contracts and lightweight registry.
   - Provide initial tests covering registry behaviour.
2. **Attack Graph Alignment**
   - Extract domain entities (`AttackNode`, `AttackEdge`, `ServiceIdentityEdge`) into `cerebro.domain.graph`.
   - Replace direct SQLAlchemy usage in `attack_path.graph_model` with mapper invocations.
3. **Query Engine Split**
   - Move DTO definitions and analytics calculations into `cerebro.domain.query`.
   - Limit `cerebro.query.engine` to infrastructure responsibilities (connections, caching).
4. **Collector Refactor**
   - Introduce domain repositories (ports) for writing graph and account state.
   - Update collectors to compose repositories through the mapper registry.
5. **Interface Layer Migration**
   - Relocate attack graph routes to `cerebro.interface.attack_path` consuming domain DTOs.
   - Ensure CLI/SDK serialize via mapper-provided DTO helpers.
6. **Circular Dependency Guardrails**
   - Domain layer must never import `core` or `providers`.
   - Application layer may depend on domain + infrastructure via ports.
   - Infrastructure depends on `core` and may implement domain ports but cannot import interface modules.

Documented follow-up tickets should reference these milestones to avoid broad, unsafe moves.
