# Fleetdm

Generated Source Runtime SDK scaffold for `fleetdm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fleetdm`
- Health endpoint: `/source-runtimes/health?source_id=fleetdm`
- Source health receipt: `sources/fleetdm/source_health_receipt.json`
- EvidenceCAS reference kind: `fleetdm.evidence_cas_reference`

## Families

- `hosts`, emits `fleetdm.hosts`, reads `/api/v1/fleet/hosts`
- `policies`, emits `fleetdm.policies`, reads `/api/v1/fleet/policies`
- `audit_activities`, emits `fleetdm.audit_activities`, reads `/api/v1/fleet/activities`

## Tests

- `go test ./sources/fleetdm ./internal/sourceprojection -count=1`
- `make catalog-check`
