# Cerebro

WriterInternal Cerebro owns the deployment and operations surface for the current Cerebro runtime. It keeps environment-specific infrastructure, stack configuration, image promotion, runtime verification, and deployment workflows in one reviewed repository.

This repository is intentionally narrow: it deploys and operates Cerebro for Writer environments. Product/runtime source lives in the `writer/cerebro` image, and the optional web console ships as the `writerinternal/cerebro-web` image; this repository pins, verifies, mirrors, and deploys those artifacts.

## Cross-repo contract

- `writer/cerebro` is authoritative for runtime behavior, CLI/API contracts, source catalogs, release artifacts, and runtime deploy contracts.
- `WriterInternal/cerebro` is authoritative for Pulumi stacks, environment config, image promotion, deployment workflows, and operational verification.
- The release bridge is the signed runtime image plus `cerebro-runtime-contract.json`; promotion and deploy workflows should reject stack/runtime combinations that violate that contract.

## Current responsibilities

- **AWS runtime stacks** in `infra/aws` for `sec-dev` and `go-prod`.
- **GCP Workload Identity Federation** in `infra/gcp` for AWS-to-GCP scanner access.
- **Container image promotion** from GHCR to environment ECR repositories using pinned Pulumi stack config.
- **Supply-chain checks** for runtime and web images before promotion, including signature and attestation verification.
- **Private runtime networking**: VPC/subnets, internal ALBs, ACM certificates, WAF, Tailscale access, ALB access logs, and trusted proxy settings.
- **Runtime services**: ECS Fargate API, optional web console service, EventBridge-scheduled orchestrator tasks, RDS Postgres, NATS JetStream, and Neo4j/Aura.
- **Access controls**: API authentication, tenant allowlists, capability tokens, MCP OAuth configuration, optional web OIDC, and secret import boundaries.
- **Source runtime bootstrap**: declarative source definitions, per-runtime schedules, S3 source IAM scopes, and drift/coverage verification.
- **Panopticon integration**: sec-dev and go-prod Panopticon `s3Sources`, alert/case/IOC source runtimes, source schedules, and task-role outputs/fallbacks.
- **Observability and operations**: CloudWatch dashboards/alarms, graph health checks, source runtime verification, and bulk closeout audit storage.

## Non-goals

- No repository rename.
- No product/runtime implementation beyond deployment-specific IAM and config shims.
- No plaintext credentials or long-lived service account keys in source control.
- No stale v1 platform docs or old provider tree.
- No unreviewed production changes; deployment stays explicit, validated, and auditable.

## Architecture

`infra/aws` is the primary Pulumi program. Each AWS stack deploys or wires:

- An ECS Fargate API service behind an ALB and WAF.
- An optional ECS web console service behind its own ALB and optional OIDC listener auth.
- EventBridge rules that launch orchestrator ECS tasks for source sync, finding evaluation, and graph ingest.
- RDS Postgres for current state, NATS JetStream for the append log, and Neo4j/Aura for graph projections.
- KMS keys, CloudWatch logs, dashboards, alarms, log metric filters, ECR repositories, and optional ALB access logs.
- Optional Tailscale subnet routing for internal access.
- External secret imports and Pulumi-encrypted stack values for runtime credentials.
- A closeout audit S3 bucket with narrow write scope from the runtime task role.

`infra/gcp` configures GCP Workload Identity Federation and scanner IAM so approved AWS task roles can access configured GCP projects without static service account keys.

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/CODEOWNERS` | Review ownership for repository, stack, workflow, and docs changes. |
| `.github/dependabot.yml` | Dependency update policy for GitHub Actions and infra Python dependencies. |
| `.github/scripts` | Shared CI helpers for image verification and ECR availability checks. |
| `.github/workflows/ci.yml` | Static CI plus runtime/web image mirroring into ECR. |
| `.github/workflows/infra-deploy.yml` | Static infra validation, Pulumi previews on PRs, deploys on `main`, and deploy verification. |
| `.github/workflows/propose-image-tag.yml` | Proposes or applies verified Cerebro runtime image tag updates. |
| `.github/workflows/propose-web-image-tag.yml` | Proposes verified web console image tag updates. |
| `.github/workflows/source-runtime-verify.yml` | Manually verifies recent or newly started source runtime ECS runs. |
| `.github/workflows/source-runtime-drift.yml` | Scheduled/manual source runtime coverage and drift checks. |
| `.github/workflows/graph-health-insight.yml` | Runs deep graph health insight after successful infra deploys or manual dispatch. |
| `.github/workflows/closeout.yml` | Dispatches audited bulk closeout ECS tasks. |
| `docs/OBSERVABILITY.md` | OTEL deployment config, secret mounting, validation, and post-deploy checks. |
| `docs/SOURCE_ONBOARDING.md` | Canonical runbook for adding or changing source runtime instances. |
| `docs/EVIDENCE_CAS_REFERENCES.md` | Integration contract for carrying EvidenceCAS pointers as source evidence without materializing payloads. |
| `infra/aws` | AWS Pulumi program for networking, compute, storage, auth, monitoring, and runtime bootstrap. |
| `infra/aws/Pulumi.sec-dev.yaml` | `sec-dev` AWS stack configuration. |
| `infra/aws/Pulumi.go-prod.yaml` | `go-prod` AWS stack configuration. |
| `infra/gcp` | GCP Pulumi program for WIF and scanner IAM. |
| `infra/gcp/Pulumi.gcp-dev.yaml` | Development GCP WIF/scanner stack configuration. |
| `infra/gcp/Pulumi.gcp-prod.yaml` | Production GCP WIF/scanner stack configuration. |
| `infra/scripts` | Validation, promotion, deploy verification, graph health, drift, and closeout helper scripts. |
| `infra/tests` | Python `unittest` coverage for Pulumi helpers, scripts, workflows, and config validators. |
| `infra/README.md` | Infra-focused runbook and emergency/manual deploy notes. |

## Operating model

Image versions are explicit. Runtime deploys are driven by `cerebro:imageTag`; web console deploys are driven by `cerebro:webImageTag` when `cerebro:webEnabled` is true. Promotion workflows verify the referenced GHCR artifact, update the relevant stack config, and keep deployment auditable through PRs or the guarded `sec-dev` release-dispatch path.

The `go-prod` runtime image must not lag behind `sec-dev`. The image proposal workflow updates `sec-dev` alongside `go-prod` when needed so production is never ahead of development validation.

The API service can run as a singleton or scale out within stack-configured bounds. `cerebro:apiMaxInstances` defaults to `1`; values above `1` require `cerebro:imageTag >= v2.1.25`, where source-runtime cursor advances are protected by the same Postgres lease used by orchestrator runs. The orchestrator remains scheduled ECS tasks through EventBridge, not a second long-running API service.

Source runtimes are GitOps-managed in stack config. Add or change `cerebro:sourceRuntimes`, `cerebro:sourceSecretKeys`, `cerebro:orchestratorSchedules`, and optional `cerebro:s3Sources` in the target stack, then follow `docs/SOURCE_ONBOARDING.md`.

Source evidence that is stored in EvidenceCAS should enter Cerebro as a pointer
containing an `evidencecas://` URI, digest, Merkle root, and commit id rather
than as payload bytes. See
[`docs/EVIDENCE_CAS_REFERENCES.md`](docs/EVIDENCE_CAS_REFERENCES.md) for the
operator and source-runtime contract.

Panopticon export wiring is active in both `sec-dev` and `go-prod`: the stack
config declares least-privilege `cerebro:s3Sources`, `writer-panopticon-alerts`,
`writer-panopticon-cases`, and `writer-panopticon-iocs` source runtimes,
EventBridge schedules for each family, and cross-repo validators against the
Panopticon Pulumi export contract. The integration consumes canonical S3
NDJSON archives only; legacy claims-NDJSON import is not supported.

## Common operator tasks

| Task | Where to start | Validation / follow-up |
| --- | --- | --- |
| Promote a runtime image | Update `cerebro:imageTag` through `.github/workflows/propose-image-tag.yml` or a reviewed stack-config PR. | Confirm image verification, ECR mirror, Pulumi preview/deploy, and deploy verification. |
| Promote a web console image | Use `.github/workflows/propose-web-image-tag.yml` for `cerebro:webImageTag`. | Confirm web image verification, ECR mirror, and affected stack preview/deploy. |
| Change AWS stack config | Edit `infra/aws/Pulumi.<stack>.yaml`. | Run stack validation and review Pulumi preview for only intended resources. |
| Change GCP WIF/scanner IAM | Edit `infra/gcp/Pulumi.<stack>.yaml` or `infra/gcp`. | Run GCP config validation and the relevant Pulumi preview. |
| Add or change a source runtime | Follow `docs/SOURCE_ONBOARDING.md`. | Run stack validation, preview the target stack, then verify source runtime and graph health after deploy. |
| Enable OTEL export | Follow `docs/OBSERVABILITY.md` and provision the OTLP header secret first. | Run stack validation, preview ECS task definition env/secrets, then verify trace ids in CloudWatch and collector spans. |
| Update Panopticon exports | Coordinate with the Panopticon Pulumi export outputs, then update `cerebro:s3Sources`, source runtimes, and schedules for the target stack. | Run stack validation plus the Panopticon cross-repo contract test before deploy. |
| Investigate source runtime drift | Dispatch `.github/workflows/source-runtime-drift.yml`. | Review coverage/drift artifacts and reconcile stack config or runtime state. |
| Investigate graph health | Dispatch `.github/workflows/graph-health-insight.yml` or use deploy verification outputs. | Treat regressions as deploy blockers until explained or intentionally accepted. |
| Run bulk closeout | Dispatch `.github/workflows/closeout.yml`. | Keep dry-run/apply inputs reviewed and preserve audit bucket output. |

## Rollback and post-merge watch

Rollback is a reviewed config change, not a manual mutation. Revert or adjust the relevant stack config, or use `.github/workflows/propose-image-tag.yml` / `.github/workflows/propose-web-image-tag.yml` to move the runtime or web console back to a verified tag, then let `infra-deploy.yml` preview, deploy, and verify the affected stack.

After merges that change runtime images, source runtimes, graph health logic, or deploy verification, watch:

- `infra-deploy.yml` for Pulumi preview/deploy, runtime verification, and graph health jobs.
- `.github/workflows/source-runtime-verify.yml` for recent source runtime ECS task health.
- `.github/workflows/source-runtime-drift.yml` for coverage and schedule drift.
- `.github/workflows/graph-health-insight.yml` for graph lag, ingest, and quality regressions.

## Local workflow

Prerequisites:

- Python 3.11+; CI runs Python 3.12.
- `uv`.
- Pulumi CLI and access to the `writer-ai` Pulumi organization.
- AWS/GCP credentials for any cloud preview or deploy you run locally.

Install dependencies:

```bash
cd infra
uv sync
```

Run local validators:

```bash
cd infra
uv lock --check
uv run python -m compileall aws gcp scripts tests
uv run python scripts/validate_pulumi_project_config.py
uv run python scripts/validate_stack_config.py
uv run python scripts/validate_gcp_config.py
uv run python -m unittest discover -s tests
```

Choose validators by change type:

| Change type | Minimum local validation |
| --- | --- |
| README-only | `git diff --check README.md` |
| Pulumi project config | `uv run python scripts/validate_pulumi_project_config.py` plus the affected stack validators |
| AWS stack config | `uv run python scripts/validate_pulumi_project_config.py` and `uv run python scripts/validate_stack_config.py` plus `uv run pulumi preview --stack <stack>` from `infra/aws` |
| GCP stack config | `uv run python scripts/validate_pulumi_project_config.py` and `uv run python scripts/validate_gcp_config.py` plus `uv run pulumi preview --stack <stack>` from `infra/gcp` |
| Infra Python code or scripts | `uv run python -m compileall aws gcp scripts tests` and `uv run python -m unittest discover -s tests` |
| Source runtime config | Stack validation, target AWS Pulumi preview, and post-deploy source runtime verification |
| Workflow or promotion logic | Relevant unit tests under `infra/tests`, static validation, and careful review of changed workflow paths |

Preview AWS changes:

```bash
cd infra/aws
uv run pulumi preview --stack sec-dev
uv run pulumi preview --stack go-prod
```

Preview GCP changes:

```bash
cd infra/gcp
uv run pulumi preview --stack gcp-dev
uv run pulumi preview --stack gcp-prod
```

For README-only changes, at minimum run:

```bash
git diff --check README.md
```

## Key config surfaces

`infra/aws/Pulumi.yaml` and `infra/gcp/Pulumi.yaml` are authoritative. Common AWS config families include:

| Key family | Purpose |
| --- | --- |
| `cerebro:ecrBaseUri`, `cerebro:imageTag` | Runtime ECR target and pinned runtime image tag. |
| `cerebro:web*` | Optional web console image, ALB, OIDC, proxy, and scaling settings. |
| `cerebro:domain`, certificate keys, `cerebro:alb*` | API/web ALB exposure, certificates, idle timeouts, ingress CIDRs, and internal/public placement. |
| `cerebro:publicOrigin`, `cerebro:trustedProxy*` | Runtime public origin and trusted forwarded-header boundary. |
| `cerebro:apiCpu`, `cerebro:apiMemory`, `cerebro:apiMinInstances`, `cerebro:apiMaxInstances` | ECS API sizing and autoscaling bounds. |
| `cerebro:apiRequestCountPerTarget*`, latency alarm keys | API/web ALB request saturation and p95 latency scaling or alarm thresholds. |
| `cerebro:postgres*` | RDS Postgres sizing, backups, deletion protection, storage, and Multi-AZ behavior. |
| `cerebro:nats*`, `cerebro:jetstream*` | NATS JetStream service settings and lag alarms. |
| `cerebro:neo4jAura*` | Neo4j/Aura graph projection settings and imported graph secrets. |
| `cerebro:apiAuthEnabled`, `cerebro:allowedTenants`, capability token keys | API authentication and tenant scoping. |
| `cerebro:mcpOauth*` | MCP OAuth issuer, redirect, client secret references, group allowlist, and token tenant scope. |
| `cerebro:sourceRuntimes`, `cerebro:sourceSecretKeys` | Declarative source runtime definitions and allowed secret-backed env references. |
| `cerebro:orchestrator*` | Default and named EventBridge schedules plus ECS task sizing for source sync and graph ingest. |
| `cerebro:s3Sources` | Least-privilege IAM read scope for S3-backed source runtimes, including Panopticon archive prefixes. |
| `cerebro:graphAgentLlm*`, `cerebro:openrouterApiKeySecret` | Optional graph agent LLM configuration and secret reference. |
| `cerebro:accessAudit*`, `cerebro:dashboardLatency*`, `cerebro:alarm*` | Access audit, dashboard latency, and alarm notification settings. |
| `cerebro:enableInfisicalSyncRole`, `cerebro:externalSecretsPrefix` | External secret import boundary. |
| `cerebro:enableTailscale`, `cerebro:tailscale*` | Optional Tailscale subnet router settings. |

## CI and deployment

- Pull requests run static infra validation for infra-relevant changes and Pulumi previews for affected stacks.
- Pull requests mirror the `sec-dev` runtime and web images to ECR when the referenced GHCR artifacts exist and verify successfully.
- Merges to `main` deploy affected AWS/GCP stacks through `Infrastructure Deploy`; `go-prod` uses the production environment gate.
- Deploy verification can check source runtime ECS runs, source role trust drift, graph health, and graph health regressions depending on the changed paths.
- Scheduled/manual workflows maintain source runtime drift reports, graph health insight, and runtime/web image tag proposals.
- `workflow_dispatch` supports manual deployment for `sec-dev`, `go-prod`, `gcp-dev`, and `gcp-prod`.
- Release promotion workflows use a short-lived, preflighted GitHub App installation token for automation branches and PRs. Trusted `sec-dev` release dispatches auto-merge their PRs only after required checks pass; the resulting normal `main` push runs deploys without direct branch writes or explicit deploy dispatches. Configure `CEREBRO_DEPLOY_APP_CLIENT_ID` as a repository variable and `CEREBRO_DEPLOY_APP_PRIVATE_KEY` as a repository secret; the App installation needs Contents write, Pull requests write, Issues write, Commit statuses read, and the implicit Metadata read permission for this repository.
- AWS `sec-dev` and `go-prod` deploy jobs create GitHub Deployment records and update them to `in_progress`, `success`, or `failure` around Pulumi and post-deploy verification.

Common CI failure triage:

| Failure area | First check |
| --- | --- |
| Image verification or mirror | Confirm the GHCR tag exists, the release signature/attestations are present, and the stack config references the intended tag. |
| Runtime contract verification | Compare the release `cerebro-runtime-contract.json` with changed stack source-runtime config. |
| Pulumi preview | Confirm diffs are limited to the intended stack/resources before merging. |
| Source runtime verification | Check task exit status and source role trust before widening schedules or retrying. |
| Graph health insight | Compare ingest runs, graph lag, and recent deploy changes before accepting a degradation. |

## Security notes

- Never commit plaintext credentials, tokens, API keys, or service-specific secrets.
- Keep Pulumi secrets encrypted in stack config.
- Use approved external secret imports for runtime credentials.
- Keep ALBs internal unless there is an explicit reviewed reason to expose one.
- Preserve least-privilege S3 source IAM scopes in `cerebro:s3Sources`.
- Keep signed image, attestation, and runtime contract checks in the promotion path.
- Keep source runtime role trust and GCP WIF changes reviewed in the owning repositories before production rollout.
