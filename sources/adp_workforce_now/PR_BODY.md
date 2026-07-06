## Summary

- Promotes the `adp_workforce_now` Source Runtime SDK to provider-verified API proof.
- Narrows the runtime to documented ADP Workforce Now Workers and Event Notifications endpoints, removing generated placeholder families that do not have matching public Workforce Now endpoints.
- Updates the adapter, connector catalog definition, health receipt, fixtures, projections, and runtime metadata to use `GET /hr/v2/workers` and `GET /core/v1/event-notification-messages`.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=adp_workforce_now`
- Provider API proof: `verified` / score 100
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/adp_workforce_now ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/adp_workforce_now/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
