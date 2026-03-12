# DevEx Codegen Catalog

Generated from `devex/codegen_catalog.json` via `go run ./scripts/generate_devex_codegen_docs/main.go`.

- Catalog API version: **devex.cerebro/v1alpha1**
- Catalog kind: **CodegenCatalog**
- Families: **10**

## CI to Local Map

| Family | Generator | Local Checks | CI Jobs | Outputs |
|---|---|---|---|---|
| `openapi` | `openapi-sync` | `openapi-check` | `openapi-route-parity` | `api/openapi.yaml` |
| `config-docs` | `config-docs` | `config-docs-check` | `config-docs-drift` | `docs/CONFIG_ENV_VARS.md` |
| `api-contracts` | `api-contract-docs` | `api-contract-compat`, `api-contract-docs-check` | `api-contract-compat`, `api-contract-docs-drift` | `docs/API_CONTRACTS.json`, `docs/API_CONTRACTS_AUTOGEN.md` |
| `ontology-docs` | `ontology-docs` | `graph-ontology-guardrails`, `ontology-docs-check` | `graph-ontology-guardrails`, `ontology-docs-drift` | `docs/GRAPH_ONTOLOGY_AUTOGEN.md` |
| `cloudevents` | `cloudevents-docs` | `cloudevents-contract-compat`, `cloudevents-docs-check` | `cloudevents-contract-compat`, `cloudevents-docs-drift` | `docs/CLOUDEVENTS_AUTOGEN.md`, `docs/CLOUDEVENTS_CONTRACTS.json` |
| `report-contracts` | `report-contract-docs` | `report-contract-compat`, `report-contract-docs-check` | `report-contract-compat`, `report-contract-docs-drift` | `docs/GRAPH_REPORT_CONTRACTS.json`, `docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md` |
| `entity-facets` | `entity-facet-docs` | `entity-facet-contract-compat`, `entity-facet-docs-check` | `entity-facet-contract-compat`, `entity-facet-docs-drift` | `docs/GRAPH_ENTITY_FACETS.json`, `docs/GRAPH_ENTITY_FACETS_AUTOGEN.md` |
| `agent-sdk` | `agent-sdk-docs` | `agent-sdk-contract-compat`, `agent-sdk-docs-check`, `agent-sdk-packages-check` | `agent-sdk-contract-compat`, `agent-sdk-docs-drift`, `agent-sdk-packages` | `docs/AGENT_SDK_AUTOGEN.md`, `docs/AGENT_SDK_CONTRACTS.json`, `docs/AGENT_SDK_PACKAGES_AUTOGEN.md`, `sdk/go/cerebro/client.go`, `sdk/python/cerebro_sdk/__init__.py`, `sdk/python/cerebro_sdk/client.py`, `sdk/python/pyproject.toml`, `sdk/typescript/package.json`, `sdk/typescript/src/index.ts`, `sdk/typescript/tsconfig.json` |
| `connector-provisioning` | `connector-docs` | `connector-docs-check` | - | `docs/CONNECTOR_PROVISIONING_AUTOGEN.md`, `docs/CONNECTOR_PROVISIONING_CATALOG.json` |
| `devex-codegen-catalog` | `devex-codegen` | `devex-codegen-check` | - | `docs/DEVEX_CODEGEN_AUTOGEN.md`, `docs/DEVEX_CODEGEN_CATALOG.json` |

## Families

### `openapi`

Keeps registered routes, placeholder synchronization, and OpenAPI linting aligned.

- Change reason: API route or OpenAPI surface changed
- Generator: `openapi-sync` -> `openapi-sync`
- Checks:
  - `openapi-check` -> `openapi-check`
- Triggers: `api/openapi.yaml`, `internal/api/**`, `scripts/openapi_route_parity.go`
- Outputs: `api/openapi.yaml`
- CI jobs: `openapi-route-parity`

### `config-docs`

Generates the environment/config reference from the live config loading surface.

- Change reason: config loading or config docs changed
- Generator: `config-docs` -> `config-docs`
- Checks:
  - `config-docs-check` -> `config-docs-check`
- Triggers: `docs/CONFIG_ENV_VARS.md`, `internal/app/app_config.go`, `internal/config/**`, `scripts/generate_config_docs/**`
- Outputs: `docs/CONFIG_ENV_VARS.md`
- CI jobs: `config-docs-drift`

### `api-contracts`

Generates the machine-readable HTTP API baseline and enforces OpenAPI compatibility across endpoint evolution.

- Change reason: HTTP API route or schema surface changed
- Generator: `api-contract-docs` -> `api-contract-docs`
- Checks:
  - `api-contract-docs-check` -> `api-contract-docs-check`
  - `api-contract-compat` -> `go run ./scripts/check_api_contract_compat/main.go --require-baseline --base-ref={base_ref}`
- Triggers: `api/openapi.yaml`, `docs/API_CONTRACTS.json`, `docs/API_CONTRACTS_AUTOGEN.md`, `internal/api/**`, `internal/apicontractcompat/**`, `scripts/check_api_contract_compat/**`, `scripts/generate_api_contract_docs/**`
- Outputs: `docs/API_CONTRACTS.json`, `docs/API_CONTRACTS_AUTOGEN.md`
- CI jobs: `api-contract-compat`, `api-contract-docs-drift`

### `ontology-docs`

Generates ontology reference docs and runs guardrails for ingest-schema drift.

- Change reason: ontology or ingest mapping inputs changed
- Generator: `ontology-docs` -> `ontology-docs`
- Checks:
  - `ontology-docs-check` -> `ontology-docs-check`
  - `graph-ontology-guardrails` -> `graph-ontology-guardrails`
- Triggers: `docs/GRAPH_ONTOLOGY_AUTOGEN.md`, `internal/graph/edge.go`, `internal/graph/node.go`, `internal/graph/schema_registry.go`, `internal/graph/schema_registry_test.go`, `internal/graphingest/**`, `scripts/generate_graph_ontology_docs/**`
- Outputs: `docs/GRAPH_ONTOLOGY_AUTOGEN.md`
- CI jobs: `graph-ontology-guardrails`, `ontology-docs-drift`

### `cloudevents`

Generates platform and ingest event catalogs and enforces baseline compatibility.

- Change reason: CloudEvents-producing surfaces changed
- Generator: `cloudevents-docs` -> `cloudevents-docs`
- Checks:
  - `cloudevents-docs-check` -> `cloudevents-docs-check`
  - `cloudevents-contract-compat` -> `go run ./scripts/check_cloudevents_contract_compat/main.go --require-baseline --base-ref={base_ref}`
- Triggers: `docs/CLOUDEVENTS_AUTOGEN.md`, `docs/CLOUDEVENTS_CONTRACTS.json`, `internal/api/server_handlers_graph_writeback.go`, `internal/graphingest/**`, `internal/platformevents/**`, `internal/webhooks/**`, `scripts/check_cloudevents_contract_compat/**`, `scripts/generate_cloudevents_docs/**`
- Outputs: `docs/CLOUDEVENTS_AUTOGEN.md`, `docs/CLOUDEVENTS_CONTRACTS.json`
- CI jobs: `cloudevents-contract-compat`, `cloudevents-docs-drift`

### `report-contracts`

Generates report registry artifacts and enforces report contract compatibility.

- Change reason: report runtime or report contracts changed
- Generator: `report-contract-docs` -> `report-contract-docs`
- Checks:
  - `report-contract-docs-check` -> `report-contract-docs-check`
  - `report-contract-compat` -> `go run ./scripts/check_report_contract_compat/main.go --require-baseline --base-ref={base_ref}`
- Triggers: `docs/GRAPH_REPORT_CONTRACTS.json`, `docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md`, `internal/api/server_handlers_graph_intelligence.go`, `internal/api/server_handlers_platform.go`, `internal/graph/report*`, `scripts/check_report_contract_compat/**`, `scripts/generate_report_contract_docs/**`
- Outputs: `docs/GRAPH_REPORT_CONTRACTS.json`, `docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md`
- CI jobs: `report-contract-compat`, `report-contract-docs-drift`

### `entity-facets`

Generates facet contract catalogs and enforces compatibility across facet evolution.

- Change reason: entity facet surfaces changed
- Generator: `entity-facet-docs` -> `entity-facet-docs`
- Checks:
  - `entity-facet-docs-check` -> `entity-facet-docs-check`
  - `entity-facet-contract-compat` -> `go run ./scripts/check_entity_facet_compat/main.go --require-baseline --base-ref={base_ref}`
- Triggers: `docs/GRAPH_ENTITY_FACETS.json`, `docs/GRAPH_ENTITY_FACETS_AUTOGEN.md`, `docs/GRAPH_ENTITY_FACET_ARCHITECTURE.md`, `internal/api/server_handlers_platform_entities.go`, `internal/graph/entity_facet*`, `internal/graph/entity_facets.go`, `internal/graph/entity_subresources.go`, `internal/graph/entity_summary_report.go`, `scripts/check_entity_facet_compat/**`, `scripts/generate_entity_facet_docs/**`
- Outputs: `docs/GRAPH_ENTITY_FACETS.json`, `docs/GRAPH_ENTITY_FACETS_AUTOGEN.md`
- CI jobs: `entity-facet-contract-compat`, `entity-facet-docs-drift`

### `agent-sdk`

Generates SDK contract catalogs and client packages from the shared tool surface.

- Change reason: Agent SDK contracts changed
- Generator: `agent-sdk-docs` -> `agent-sdk-docs`
- Checks:
  - `agent-sdk-docs-check` -> `agent-sdk-docs-check`
  - `agent-sdk-contract-compat` -> `go run ./scripts/check_agent_sdk_contract_compat/main.go --require-baseline --base-ref={base_ref}`
  - `agent-sdk-packages-check` -> `agent-sdk-packages-check`
- Triggers: `docs/AGENT_SDK_AUTOGEN.md`, `docs/AGENT_SDK_CONTRACTS.json`, `docs/AGENT_SDK_PACKAGES_AUTOGEN.md`, `internal/agentsdk/**`, `internal/api/server_handlers_agent_sdk*`, `internal/app/app_agent_sdk*`, `internal/app/app_cerebro_tools*`, `scripts/check_agent_sdk_contract_compat/**`, `scripts/generate_agent_sdk_docs/**`, `scripts/generate_agent_sdk_packages/**`, `sdk/**`
- Outputs: `docs/AGENT_SDK_AUTOGEN.md`, `docs/AGENT_SDK_CONTRACTS.json`, `docs/AGENT_SDK_PACKAGES_AUTOGEN.md`, `sdk/go/cerebro/client.go`, `sdk/python/cerebro_sdk/__init__.py`, `sdk/python/cerebro_sdk/client.py`, `sdk/python/pyproject.toml`, `sdk/typescript/package.json`, `sdk/typescript/src/index.ts`, `sdk/typescript/tsconfig.json`
- CI jobs: `agent-sdk-contract-compat`, `agent-sdk-docs-drift`, `agent-sdk-packages`

### `connector-provisioning`

Generates the cloud connector provisioning catalog used by CLI scaffolding, validation, and rollout docs.

- Change reason: connector provisioning contracts changed
- Generator: `connector-docs` -> `connector-docs`
- Checks:
  - `connector-docs-check` -> `connector-docs-check`
- Triggers: `Makefile`, `docs/CONNECTOR_PROVISIONING_ARCHITECTURE.md`, `docs/CONNECTOR_PROVISIONING_AUTOGEN.md`, `docs/CONNECTOR_PROVISIONING_CATALOG.json`, `internal/cli/connector*`, `internal/connectors/**`, `scripts/generate_connector_docs/**`
- Outputs: `docs/CONNECTOR_PROVISIONING_AUTOGEN.md`, `docs/CONNECTOR_PROVISIONING_CATALOG.json`
- CI jobs: -

### `devex-codegen-catalog`

Publishes the machine-readable CI-to-local codegen map used by DevEx tooling.

- Change reason: codegen governance surfaces changed
- Generator: `devex-codegen` -> `devex-codegen`
- Checks:
  - `devex-codegen-check` -> `devex-codegen-check`
- Triggers: `.github/workflows/ci.yml`, `Makefile`, `devex/codegen_catalog.json`, `docs/DEVELOPMENT.md`, `docs/DEVEX_CODEGEN_AUTOGEN.md`, `docs/DEVEX_CODEGEN_CATALOG.json`, `internal/devex/**`, `scripts/generate_devex_codegen_docs/**`
- Outputs: `docs/DEVEX_CODEGEN_AUTOGEN.md`, `docs/DEVEX_CODEGEN_CATALOG.json`
- CI jobs: -

## Notes

- `devex/codegen_catalog.json` is the source of truth for generator families, trigger globs, local checks, and CI job mapping.
- `docs/DEVEX_CODEGEN_CATALOG.json` is the machine-readable artifact for editors and external tooling.
- `scripts/devex.py` consumes this catalog so new generator families stop requiring handwritten routing branches.
