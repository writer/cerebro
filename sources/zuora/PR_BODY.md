## Summary

- Invalidates the generated `zuora` Source Runtime provider API proof.
- Records the provider Swagger mismatch for generated `account`, `revenue_event`, and `revenue_schedule` runtime paths.
- Leaves the runtime in place, but blocks promotion until those families are rewritten against documented provider paths or removed.

## Provider API result

- Status: `invalidated`
- Reason: `generated_runtime_paths_not_in_provider_spec`
- Affected families: `account`, `revenue_event`, `revenue_schedule`
- Missing paths:
  - `/v1/payment-methods/credit-cards/accounts/{account-key}`
  - `/v1/revenue-events/revenue-schedules/{rs-number}`
  - `/v1/revenue-items/revenue-events/{event-number}`

## Next rewrite

- Rewrite `account` against documented account or payment-method endpoints.
- Rewrite or remove `revenue_event` and `revenue_schedule` unless provider-backed paths are found.
- Promote the remaining provider-backed families after the invalid families are removed from the runtime contract.

## Tests

- `go test ./sources/zuora ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make catalog-check`
- `make connector-catalog-review connector-api-discovery`
