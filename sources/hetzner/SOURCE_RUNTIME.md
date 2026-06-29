# Hetzner Cloud

Generated Source Runtime SDK scaffold for `hetzner`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hetzner`
- Health endpoint: `/source-runtimes/health?source_id=hetzner`
- Source health receipt: `sources/hetzner/source_health_receipt.json`
- EvidenceCAS reference kind: `hetzner.evidence_cas_reference`

## Families

- `placement_group`, emits `hetzner.placement_group`, reads `/placement_groups`
- `certificate`, emits `hetzner.certificate`, reads `/certificates`
- `firewall`, emits `hetzner.firewall`, reads `/firewalls`
- `ssh_key`, emits `hetzner.ssh_key`, reads `/ssh_keys`

## Tests

- `go test ./sources/hetzner ./internal/sourceprojection -count=1`
- `make catalog-check`
