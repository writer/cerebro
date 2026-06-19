# DevEx Codegen Catalog

Maintained from `devex/codegen_catalog.json`.

- Catalog API version: **devex.cerebro/v1alpha1**
- Catalog kind: **CodegenCatalog**
- Families: **4**

## CI To Local Map

| Family | Generator | Local Checks | CI Jobs | Outputs |
|---|---|---|---|---|
| `openapi` | `openapi-sync` | `openapi-check`, `openapi-lint` | `openapi` | `api/openapi.yaml` |
| `proto` | `proto-generate` | `proto-breaking`, `proto-generate-check`, `proto-lint` | `proto` | `gen/cerebro/v1`, `sdk/python/cerebro/v1` |
| `graph-actions` | `graph-action-generate` | `graph-action-check` | `graph-actions` | `internal/graphactions/registry_gen.go` |
| `detection-catalog` | `detection-catalog-generate` | `catalog-check`, `detection-catalog-check` | `catalog` | `docs/domains/policies.md` |

## Families

### `openapi`

Keeps registered routes, placeholder synchronization, and OpenAPI linting aligned.

- Change reason: API route or OpenAPI surface changed
- Generator: `openapi-sync` -> `make openapi-sync`
- Checks:
  - `openapi-check` -> `make openapi-check`
  - `openapi-lint` -> `make openapi-lint`
- Triggers: `api/openapi.yaml`, `internal/bootstrap/routes.go`, `scripts/openapi_route_parity.go`
- Outputs: `api/openapi.yaml`
- CI jobs: `openapi`

### `proto`

Keeps proto definitions, generated Go/Python outputs, and breaking-change checks aligned.

- Change reason: proto definitions or generated SDK/runtime types changed
- Generator: `proto-generate` -> `make proto-generate`
- Checks:
  - `proto-lint` -> `make proto-lint`
  - `proto-generate-check` -> `make proto-generate-check`
  - `proto-breaking` -> `make proto-breaking`
- Triggers: `buf.gen.yaml`, `buf.yaml`, `proto/**`
- Outputs: `gen/cerebro/v1`, `sdk/python/cerebro/v1`
- CI jobs: `proto`

### `graph-actions`

Keeps graph action catalog definitions and generated Go registry wiring aligned.

- Change reason: graph action catalog, generated registry, or provider action metadata changed
- Generator: `graph-action-generate` -> `make graph-action-generate`
- Checks:
  - `graph-action-check` -> `make graph-action-check`
- Triggers: `internal/graphactions/action_catalog.yaml`, `internal/graphactions/registry_gen.go`, `tools/graphactiongen/**`
- Outputs: `internal/graphactions/registry_gen.go`
- CI jobs: `graph-actions`

### `detection-catalog`

Keeps generated detection catalog artifacts aligned with policy definitions.

- Change reason: policy definitions or detection catalog generation changed
- Generator: `detection-catalog-generate` -> `make detection-catalog-generate`
- Checks:
  - `detection-catalog-check` -> `make detection-catalog-check`
  - `finding-dsl-check` -> `make finding-dsl-check`
  - `catalog-check` -> `make catalog-check`
- Triggers: `policies/**`, `internal/findingdsl/**`, `tools/findingdsl/**`, `tools/detectioncatalog/**`
- Outputs: `docs/domains/policies.md`
- CI jobs: `catalog`

## Notes

- `devex/codegen_catalog.json` is the source of truth for generator families, trigger globs, local checks, and CI job mapping.
- `docs/engineering/devex-codegen-catalog.json` is the machine-readable artifact for editors and external tooling.
- Retired generator families are intentionally omitted until their scripts and Make targets exist again.
