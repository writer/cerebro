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
5. Expose the exact attributes any downstream finding rule will use, with tests for label-quality fields, fallback IDs, absent optional fields, and future/deadline timestamps.
6. Add package tests for config validation, preview decoding, pagination, and error handling.
7. Run focused source package tests, then `make changed-check`, then `make verify` when feasible.

## Boundaries

- Do not introduce new external dependencies unless explicitly requested.
- Do not add live-service tests unless they are opt-in behind environment variables.
- Canonicalize provider-controlled identifiers before they reach URNs, event IDs, or fingerprints — see the finding-rule design notes in [AGENTS.md](../../../AGENTS.md).
