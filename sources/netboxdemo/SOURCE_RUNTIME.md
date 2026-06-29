# NetBox

Generated Source Runtime SDK scaffold for `netboxdemo`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netboxdemo`
- Health endpoint: `/source-runtimes/health?source_id=netboxdemo`
- Source health receipt: `sources/netboxdemo/source_health_receipt.json`
- EvidenceCAS reference kind: `netboxdemo.evidence_cas_reference`

## Families

- `cluster_group`, emits `netboxdemo.cluster_group`, reads `/virtualization/cluster-groups/`
- `secret`, emits `netboxdemo.secret`, reads `/secrets/secrets/`
- `connected_device`, emits `netboxdemo.connected_device`, reads `/dcim/connected-device/`
- `device_role`, emits `netboxdemo.device_role`, reads `/dcim/device-roles/`

## Tests

- `go test ./sources/netboxdemo ./internal/sourceprojection -count=1`
- `make catalog-check`
