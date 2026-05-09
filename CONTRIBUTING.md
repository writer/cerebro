# Contributing to Cerebro

This repository contains WriterInternal deployment infrastructure for Cerebro. Keep changes scoped to Pulumi infrastructure, stack configuration, CI workflows, and deployment documentation.

## Local setup

```bash
cd infra
uv sync
```

## Validate infrastructure changes

For AWS changes:

```bash
cd infra/aws
uv run pulumi preview --stack sec-dev
uv run pulumi preview --stack go-prod
```

For GCP changes:

```bash
cd infra/gcp
uv run pulumi preview --stack gcp-dev
uv run pulumi preview --stack gcp-prod
```

If cloud credentials are unavailable, at minimum run Python compilation from the repository root:

```bash
python3 -m compileall -q infra/aws infra/gcp
```

## Boundaries

- Do not add application source code here.
- Do not add automatic repository-to-repository promotion workflows.
- Keep runtime image promotion explicit through reviewed `cerebro:imageTag` changes.
- Do not commit plaintext secrets.
- Keep Pulumi secrets encrypted and runtime secrets in the approved secret systems.
- Preserve the singleton API deployment limit until source runtime cursor locking is made cross-task safe.
