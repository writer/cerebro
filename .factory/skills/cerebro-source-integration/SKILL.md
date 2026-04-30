---
name: cerebro-source-integration
description: Scaffold Cerebro source integrations following existing source, preview, runtime, and test patterns.
---

# Cerebro Source Integration

## Instructions

1. Start from the closest existing integration under `sources/`.
2. Implement config parsing with safe defaults, strict validation, and clear error mapping.
3. Add preview behavior and runtime sync behavior only within the requested scope.
4. Protect network-facing settings against loopback, unsafe schemes, malformed URLs, unbounded responses, and pagination loops.
5. Add package tests for config validation, preview decoding, pagination, and error handling.
6. Run focused source package tests, then `make verify` when feasible.

## Boundaries

- Do not introduce new external dependencies unless explicitly requested.
- Do not add live-service tests unless they are opt-in behind environment variables.
