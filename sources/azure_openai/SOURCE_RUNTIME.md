# Azure OpenAI

Source Runtime SDK implementation for `azure_openai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/azure_openai`
- Health endpoint: `/source-runtimes/health?source_id=azure_openai`
- Source health receipt: `sources/azure_openai/source_health_receipt.json`
- EvidenceCAS reference kind: `azure_openai.evidence_cas_reference`

## Families

- `deployments`, emits `azure_openai.deployments`, reads `/subscriptions/${config.subscription_id}/resourceGroups/${config.resource_group}/providers/Microsoft.CognitiveServices/accounts/${config.account_name}/deployments`
- `model_catalog`, emits `azure_openai.model_catalog`, reads `/subscriptions/${config.subscription_id}/providers/Microsoft.CognitiveServices/locations/${config.location}/models`
- `rai_policies`, emits `azure_openai.rai_policies`, reads `/subscriptions/${config.subscription_id}/resourceGroups/${config.resource_group}/providers/Microsoft.CognitiveServices/accounts/${config.account_name}/raiPolicies`
- `rai_blocklists`, emits `azure_openai.rai_blocklists`, reads `/subscriptions/${config.subscription_id}/resourceGroups/${config.resource_group}/providers/Microsoft.CognitiveServices/accounts/${config.account_name}/raiBlocklists`
- `private_endpoint_connections`, emits `azure_openai.private_endpoint_connections`, reads `/subscriptions/${config.subscription_id}/resourceGroups/${config.resource_group}/providers/Microsoft.CognitiveServices/accounts/${config.account_name}/privateEndpointConnections`

## Tests

- `go test ./sources/azure_openai -count=1`
