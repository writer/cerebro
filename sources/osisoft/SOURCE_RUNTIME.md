# OSIsoft PI Web API

Generated Source Runtime SDK scaffold for `osisoft`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/osisoft`
- Health endpoint: `/source-runtimes/health?source_id=osisoft`
- Source health receipt: `sources/osisoft/source_health_receipt.json`
- EvidenceCAS reference kind: `osisoft.evidence_cas_reference`

## Families

- `search`, emits `osisoft.search`, reads `/eventframes/search`
- `securityidentity`, emits `osisoft.securityidentity`, reads `/assetservers/${config.webid}/securityidentities`
- `notificationcontacttemplates_search`, emits `osisoft.notificationcontacttemplates_search`, reads `/notificationcontacttemplates/search`
- `analysisruleplugin`, emits `osisoft.analysisruleplugin`, reads `/assetservers/${config.webid}/analysisruleplugins`
- `baseelementtemplate`, emits `osisoft.baseelementtemplate`, reads `/elementtemplates/${config.webid}/baseelementtemplates`
- `assetserver`, emits `osisoft.assetserver`, reads `/assetservers`
- `elementtemplate`, emits `osisoft.elementtemplate`, reads `/assetdatabases/${config.webid}/elementtemplates`
- `eventframe`, emits `osisoft.eventframe`, reads `/assetdatabases/${config.webid}/eventframes`
- `elements_eventframe`, emits `osisoft.elements_eventframe`, reads `/elements/${config.webid}/eventframes`
- `eventframes_eventframe`, emits `osisoft.eventframes_eventframe`, reads `/eventframes/${config.webid}/eventframes`
- `eventframeattribute`, emits `osisoft.eventframeattribute`, reads `/assetdatabases/${config.webid}/eventframeattributes`
- `eventframes_eventframeattribute`, emits `osisoft.eventframes_eventframeattribute`, reads `/eventframes/${config.webid}/eventframeattributes`

## Tests

- `go test ./sources/osisoft ./internal/sourceprojection -count=1`
- `make catalog-check`
