# DigitalOcean

Generated Source Runtime SDK scaffold for `digitalocean`.

## Runtime input

- Source type: `rest`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/digitalocean`
- Health endpoint: `/source-runtimes/health?source_id=digitalocean`
- Source health receipt: `sources/digitalocean/source_health_receipt.json`
- EvidenceCAS reference kind: `digitalocean.evidence_cas_reference`

## Families

- `droplets`, emits `digitalocean.droplets`, reads `/v2/droplets`
- `vpcs`, emits `digitalocean.vpcs`, reads `/v2/vpcs`
- `firewalls`, emits `digitalocean.firewalls`, reads `/v2/firewalls`

## Tests

- `go test ./sources/digitalocean ./internal/sourceprojection -count=1`
- `make catalog-check`
