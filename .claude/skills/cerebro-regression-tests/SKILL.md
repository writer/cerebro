---
name: cerebro-regression-tests
description: Add focused regression coverage for Cerebro review findings, bugs, and security edge cases.
---

# Cerebro Regression Tests

## Instructions

1. Reproduce the reported bug class with the smallest package-level test.
2. Prefer table-driven Go tests for parser, validator, projection, graph, and source connector edge cases; Rust kernel behavior belongs in the owning crate's tests (property tests where the crate already uses them).
3. Include security boundary cases for URL, host, tenant, auth, pagination, size-limit, and error-mapping fixes.
4. Keep fixtures local to the package unless an existing shared fixture pattern already exists.
5. Run the focused package test with `-count=1 -v` (Go) or `cargo test -p <crate>` (Rust), then `make changed-check`, then `make verify` when feasible.

## Success Criteria

- The new test fails against the unfixed behavior or clearly asserts the regression boundary.
- The production fix is minimal and covered by the new test.
