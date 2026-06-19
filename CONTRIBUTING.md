# Contributing to Cerebro

Thanks for contributing.

## Development Setup

1. Install Go 1.26+.
2. Clone the repository.
3. Check and build the local toolchain:

```bash
make doctor
make build
```

Run the lightweight server:

```bash
make serve
```

Run the durable local stack:

```bash
docker compose up --build
```

## Code Quality Checks

Before opening a PR, run the focused tests for your change and then:

```bash
make check
```

For CI-parity validation:

```bash
make verify
```

For public docs, config, or example changes:

```bash
make readme-check
make docs-drift-check
make oss-audit
```

## Architecture Boundaries

- Use `CEREBRO_*` configuration variables only.
- Do not add embedded or in-memory production stores.
- Keep new source integrations within the Source CDK budget unless the shared CDK changes first.
- Update `docs/engineering/non-goals.md` when intentionally crossing a documented non-goal.
