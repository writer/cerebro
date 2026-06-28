# Release Contract

This guide explains Cerebro's public release artifacts and the runtime deploy contract. It is for OSS users who want to consume releases, verify artifacts, or wire their own deployment automation.

Use it with:

- [`README.md`](../../README.md) "Release and deploy artifacts".
- [`docs/operations/hosting.md`](hosting.md) for how to run the image.
- [`docs/operations/runtime-profiles.md`](runtime-profiles.md) for profile-specific dependencies, config, and checks.
- [`docs/operations/deployment-readiness.md`](deployment-readiness.md) for rollout gates and preflight receipts.
- [`docs/domains/source-runtime-guide.md`](../domains/source-runtime-guide.md) for source runtime manifests.
- [`tools/sourcedeploy`](../../tools/sourcedeploy) for contract rendering code.

## Release tags

Releases are tag-driven:

```text
vMAJOR.MINOR.PATCH[-PRERELEASE]
```

Examples:

```text
v1.2.3
v1.2.3-rc.1
```

Stable tags can publish a `latest` runtime image tag. Prerelease tags should be consumed explicitly by version.

## Public artifacts

A release can include:

- GoReleaser CLI archives,
- Linux runtime binaries,
- multi-arch runtime image,
- image provenance and signatures,
- target-specific runtime contracts, named `cerebro-runtime-contract-<target>.json`,
- matching runtime contract signatures,
- matching runtime contract certificates.

Runtime image:

```text
ghcr.io/writer/cerebro:<tag>
```

Run:

```bash
docker run --rm ghcr.io/writer/cerebro:<tag> version
```

## Release verification

The release workflow runs the same broad validation families used in CI:

- build,
- tests,
- SDK tests,
- lint,
- proto checks,
- OpenAPI checks,
- catalog checks,
- README checks,
- OSS audit,
- release smoke,
- Docker smoke,
- structural and architecture checks.

For local preflight before release-oriented changes:

```bash
make verify
make release-smoke
make docker-smoke
```

For public docs and config changes:

```bash
make readme-check docs-drift-check oss-audit
```

## Runtime deploy contract

The runtime deploy contract is a JSON handoff from this public repo to deployment automation.

Schema version:

```text
cerebro.runtime-deploy-contract/v1
```

Render locally:

```bash
go run ./cmd/sourcedeploy \
  -env <environment> \
  -tenant <tenant-id> \
  -format contract-json \
  -image-tag vX.Y.Z \
  -out .dist/cerebro-runtime-contract.json
```

Use placeholder environment and tenant values for local experiments. Real values belong in your deployment system.

## Contract fields

Top-level shape:

```json
{
  "schema_version": "cerebro.runtime-deploy-contract/v1",
  "image_tag": "vX.Y.Z",
  "environment": "<environment>",
  "tenant_id": "<tenant-id>",
  "required_secrets": ["PROVIDER_API_TOKEN"],
  "runtime_profiles": [],
  "required_env_vars": [],
  "required_backing_services": [],
  "optional_capabilities": [],
  "post_deploy_health_checks": [],
  "compatibility_notes": [],
  "sources": []
}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | contract schema identifier |
| `image_tag` | release image tag used by deployment automation |
| `environment` | caller-supplied environment label |
| `tenant_id` | caller-supplied tenant identifier |
| `required_secrets` | union of source runtime secret env vars needed by rendered manifests |
| `runtime_profiles` | portable profiles and their backing-service requirements |
| `required_env_vars` | conditional environment variable names needed by hosted deployments |
| `required_backing_services` | Postgres, JetStream, Neo4j/Aura, or other services required by runtime capabilities |
| `optional_capabilities` | config gates, dependencies, and health checks for optional surfaces |
| `post_deploy_health_checks` | public-safe commands or probes deployment automation should run after rollout |
| `compatibility_notes` | deployment compatibility and source-of-truth notes for contract consumers |
| `sources` | per-source capability and runtime metadata |

Environment variable entries:

| Field | Meaning |
| --- | --- |
| `name` | environment variable name |
| `required_for` | profile or capability that needs the variable |
| `secret` | whether the value must stay in a secret manager or orchestrator secret |

Backing-service entries:

| Field | Meaning |
| --- | --- |
| `name` | service identifier such as `postgres`, `nats-jetstream`, or `neo4j` |
| `required_for` | runtime behavior that depends on the service |
| `config_vars` | environment variable names that wire the service |

Per-source fields:

| Field | Meaning |
| --- | --- |
| `source_id` | source catalog ID |
| `emitted_kinds` | event kinds declared by the source catalog |
| `supported_families` | runtime families inferred from catalog and manifests |
| `required_secrets` | source-level secret env var names |
| `role_assumption_config_keys` | config keys that may contain role assumption targets |
| `source_health_receipt` | optional source health receipt JSON |
| `runtimes` | rendered runtime definitions for this source |

Per-runtime fields:

| Field | Meaning |
| --- | --- |
| `id` | fully qualified runtime ID |
| `source_id` | source integration ID |
| `tenant_id` | tenant identifier embedded in the runtime |
| `family` | optional runtime family |
| `required_secrets` | env vars referenced by runtime config |
| `role_assumptions` | role assumption metadata derived from config |
| `config` | runtime config with `env:` references preserved |

## Source deploy manifests

Sources can declare deploy metadata in:

```text
sources/<source-id>/deploy.yaml
```

Manifest shape:

```yaml
sourceId: example
secretKeys:
  - EXAMPLE_API_TOKEN
runtimes:
  - localId: default
    config:
      api_token: env:EXAMPLE_API_TOKEN
      family: default
```

Rules enforced by the renderer:

- `sourceId` must match the source catalog ID.
- `sourceId` uses lowercase kebab or snake case.
- `localId` uses lowercase kebab case.
- secret keys use `SCREAMING_SNAKE_CASE`.
- sensitive config values must use `env:VAR`.
- `env:VAR` references must be declared in `secretKeys`.
- duplicate runtime local IDs and duplicate secret keys are rejected.

## What the contract is for

Use the contract to:

- know which source runtimes a release declares,
- know which secret env vars must exist before deployment,
- know which source event kinds and runtime families are expected,
- pair an image tag with source runtime config,
- drive your own deployment automation without scraping docs.

## What the contract is not for

The contract intentionally does not define:

- cloud accounts,
- DNS names,
- private network topology,
- secret manager paths,
- concrete secret values,
- rollout approvals,
- deployment schedules,
- source sync cadence,
- customer assignments,
- alert thresholds.

Keep those in your deployment system.

## Signature artifacts

Releases can upload one signed contract per deployment target:

```text
cerebro-runtime-contract-<target>.json
cerebro-runtime-contract-<target>.json.sig
cerebro-runtime-contract-<target>.json.pem
```

Use the signature and certificate with your preferred Sigstore verification workflow. Verification policy is environment-specific, but the contract content is public and should not contain live secrets.

## Consuming a release

Suggested flow:

1. Select an immutable release tag.
2. Pull or pin `ghcr.io/writer/cerebro:<tag>`.
3. Download the contract whose suffix matches your deployment target, such as `cerebro-runtime-contract-<target>.json`.
4. Verify the contract signature if your deployment process requires it.
5. Check `required_secrets` against your secret manager.
6. Check source runtimes against your intended tenants and schedules.
7. Deploy the image with matching config.
8. Run `/livez`, `/health`, source runtime health, and graph health checks.

## Local contract inspection

Render and inspect:

```bash
mkdir -p .dist
go run ./cmd/sourcedeploy \
  -env local \
  -tenant example \
  -format contract-json \
  -image-tag v0.0.0-local \
  -out .dist/cerebro-runtime-contract.json

python3 -m json.tool .dist/cerebro-runtime-contract.json
```

List required secrets:

```bash
python3 - <<'PY'
import json
from pathlib import Path
contract = json.loads(Path(".dist/cerebro-runtime-contract.json").read_text())
for key in contract.get("required_secrets", []):
    print(key)
PY
```

## Compatibility expectations

Consumers should treat `schema_version` as the compatibility boundary. If the schema version changes, update contract consumers before using the new release contract.

Within the current schema:

- unknown fields should be ignored by tolerant consumers,
- required known fields should be validated,
- `env:` references should be resolved only by the deployment system,
- concrete secret values should never be expected in the contract.
