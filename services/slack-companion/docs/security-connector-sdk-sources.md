# Security Connector SDK Sources

Indexed on 2026-06-30 from live GitHub repository metadata and official API documentation.

Use this file as a source map for connector implementation and recall. Store stable source facts as `connector_context` with `source_artifacts` such as `github:<owner>/<repo>` or `docs:<url>`. Store auth scopes, API tokens, service accounts, group mappings, and write boundaries as `access_context`. Store alert, incident, finding, scan, or ticket semantics as `detection_context`.

This is not an allowlist of tools the agent can call. It is a map of authoritative sources to reopen before implementing or answering exact connector questions.

## Source Rules

- Prefer active vendor-owned SDK repos over community wrappers.
- Prefer generated or official API clients when the vendor publishes them.
- Use official API docs when no maintained SDK exists.
- Mark archived SDKs as reference-only.
- Do not store raw setup steps, credentials, token names, or tenant-specific values in memory.
- Before building a connector, verify current auth requirements, rate limits, pagination, and write permissions from the source artifact.

## Work Management And Response Connectors

| Surface | Source artifacts | Use for | Notes |
| --- | --- | --- | --- |
| Slack | `github:slackapi/node-slack-sdk` | Slack reads, posts, reactions, modals, workflow handoffs | Active official Node SDK. |
| GitHub | `github:octokit/octokit.js`, `github:octokit/rest.js` | Repository, PR, issue, commit, workflow, and code search automation | Active GitHub SDK family. Use GitHub app tools where available before raw API calls. |
| GitLab | `docs:https://docs.gitlab.com/api/`, `github:gitlabhq/gitlabhq` | Repository, merge request, pipeline, and vulnerability source context | GitHub repo is a mirror; API docs are the implementation source. |
| Linear | `github:linear/linear`, `github:linear/linear-node-sdk` | Issue create/search/update and team/project metadata | `linear/linear` is the active tools repo; `linear-node-sdk` is archived and reference-only. |
| Jira and Atlassian | `docs:https://developer.atlassian.com/cloud/jira/platform/rest/v3/`, `github:atlassian-api/atlassian-python-api` | Jira issue search/create/update and project metadata | The Python wrapper is community maintained; use Atlassian REST docs as authority. |
| PagerDuty | `github:PagerDuty/api-schema`, `github:PagerDuty/go-pagerduty`, `github:PagerDuty/pagerduty-api-python-client` | Incident, service, escalation policy, and on-call context | Go client and OpenAPI schema are active; Python client is archived. |
| ServiceNow | `github:ServiceNow/sdk`, `github:ServiceNow/sdk-examples`, `docs:https://developer.servicenow.com/` | Incidents, change requests, CMDB context, service ownership | Active official SDK and examples. Verify instance version and app scope. |
| Tines | `github:tines/go-sdk`, `github:tines/terraform-provider-tines`, `docs:https://www.tines.com/api/` | SOAR action status, story metadata, webhook endpoints | Active Go SDK and Terraform provider. Treat action execution as approval-gated. |
| Torq | `docs:https://developers.torq.io/` | SOAR workflow metadata and execution status | Public SDK repo was not found in GitHub search; use official API docs. |

## Cloud, Identity, And Infrastructure Connectors

| Surface | Source artifacts | Use for | Notes |
| --- | --- | --- | --- |
| AWS | `github:aws/aws-sdk-js-v3` | Account inventory, Security Hub, Inspector, GuardDuty, IAM, CloudTrail, Config | Active official JavaScript SDK. Prefer read-only service clients unless a workflow has explicit approval. |
| Azure | `github:Azure/azure-sdk-for-js` | Subscription inventory, Defender for Cloud, Entra ID, resource graph, policy | Active official JavaScript SDK. Verify tenant, subscription, and app registration scopes. |
| Google Cloud | `github:googleapis/google-cloud-node`, `github:googleapis/google-api-nodejs-client` | Asset inventory, SCC, IAM, Cloud Logging, project/org context | Active official Node client libraries. |
| Microsoft Graph | `github:microsoftgraph/msgraph-sdk-javascript`, `github:microsoftgraph/msgraph-sdk-python`, `github:microsoftgraph/msgraph-sdk-go` | Entra ID users, groups, apps, devices, audit logs | Active official SDK family. Store required scopes as `access_context`. |
| Okta | `github:okta/okta-sdk-nodejs`, `github:okta/okta-sdk-python` | Users, groups, apps, assignments, admin roles, factors | Active official management SDKs. |
| Auth0 | `github:auth0/node-auth0` | Tenants, applications, organizations, users, logs | Active official Node client. |
| Cloudflare | `github:cloudflare/cloudflare-typescript`, `github:cloudflare/cloudflare-python` | Zones, DNS, access policies, WAF, logs, Zero Trust metadata | Active official SDKs. |
| Kubernetes | `github:kubernetes-client/javascript`, `github:kubernetes-client/python` | Cluster inventory, workload metadata, RBAC, events | Active official clients. Treat mutation as explicit approval work. |
| Terraform providers | `github:hashicorp/terraform-provider-aws`, `github:hashicorp/terraform-provider-azurerm`, `github:hashicorp/terraform-provider-google` | Cloud resource schema, drift hints, IaC-to-cloud mapping | Use as source context for schema/provider behavior, not as live-state APIs. |
| osquery | `github:osquery/osquery`, `github:osquery/osquery-go`, `github:osquery/osquery-python` | Endpoint telemetry schema and osquery integration context | Bindings are useful when endpoint telemetry is exposed through osquery. |

## Security Platform And Scanner Connectors

| Surface | Source artifacts | Use for | Notes |
| --- | --- | --- | --- |
| Panther | `github:panther-labs/mcp-panther`, `github:panther-labs/panther-analysis`, `github:panther-labs/panther_analysis_tool`, `github:panther-labs/terraform-provider-panther`, `github:panther-labs/panther-cli`, `github:panther-labs/panther_detection_helpers`, `github:panther-labs/pypanther` | Detection authoring, alert investigation, rule metadata, Panther MCP integration | Active source family. Store rule semantics as `detection_context` and connector setup as `connector_context`. |
| Prisma Cloud | `github:PaloAltoNetworks/prisma-cloud-docs`, `github:PaloAltoNetworks/prismacloud-api-python`, `github:PaloAltoNetworks/prisma-cloud-go`, `github:PaloAltoNetworks/prisma-cloud-compute-go`, `github:PaloAltoNetworks/pan-os-python` | Cloud security posture, compute/runtime, connector docs, PAN-OS context | Use [Prisma Cloud connector sources](prisma-cloud-connector-sources.md) for connector docs and SDK repos for API automation. |
| CrowdStrike | `github:CrowdStrike/falconpy`, `github:CrowdStrike/gofalcon`, `github:CrowdStrike/psfalcon` | Endpoint detections, hosts, identities, incidents, response context | Active official SDKs. Store write-action constraints as `access_context`. |
| Snyk | `github:snyk/cli`, `docs:https://docs.snyk.io/snyk-api`, `github:snyk/code-sdk-java` | Dependency, container, IaC, and code scan context | CLI is active. Java API SDK is archived/narrow; use API docs for automation. |
| Semgrep | `github:semgrep/semgrep` | SAST scan results, rules, CI findings | Active official CLI/source repo. |
| Checkov | `github:bridgecrewio/checkov` | IaC misconfiguration scans and policy context | Active Bridgecrew/Palo Alto source repo. |
| Trivy | `github:aquasecurity/trivy`, `github:aquasecurity/trivy-action`, `github:aquasecurity/trivy-operator`, `github:aquasecurity/trivy-mcp` | Vulnerability, secret, SBOM, IaC, Kubernetes scan context | Active source family, including an MCP plugin. |
| OpenSSF Scorecard | `github:ossf/scorecard`, `github:ossf/scorecard-action`, `github:ossf/scorecard-webapp` | Open source project security posture and supply-chain signal | Active OSSF source family. |
| Dependabot | `github:dependabot/dependabot-core` | Dependency update and advisory remediation context | Active source for Dependabot behavior. Use GitHub APIs for live alerts when available. |
| Lacework | `github:lacework/go-sdk` | Lacework alert, inventory, and compliance API automation | Active official Go SDK. |
| Tenable | `github:tenable/pyTenable` | Vulnerability, asset, and exposure-management API automation | Active official Python SDK. |
| Splunk | `github:splunk/splunk-sdk-python`, `github:splunk/splunk-sdk-javascript` | Search, saved searches, index metadata, alert context | Active official SDKs. |
| Datadog | `github:DataDog/datadog-api-client-typescript`, `github:DataDog/datadog-api-client-python` | Monitors, logs, events, security signals, service metadata | Active generated API clients. |
| Elastic | `github:elastic/elasticsearch-js`, `github:elastic/go-elasticsearch`, `github:elastic/kibana` | Elasticsearch searches, Kibana/security detection context | Active official clients and Kibana source. |
| Sentry | `github:getsentry/sentry-javascript`, `github:getsentry/sentry-python` | Error events, releases, ownership clues, incident context | Active official SDKs. Use Sentry API docs for server-side reads. |
| Wiz | `docs:https://docs.wiz.io/` | Cloud security posture and graph queries when tenant docs/API access exist | Public GitHub search did not find a clear official SDK/CLI repo; verify from tenant docs before implementation. |

## Secrets, Credentials, And Compliance Connectors

| Surface | Source artifacts | Use for | Notes |
| --- | --- | --- | --- |
| Infisical | `github:Infisical/infisical`, `github:Infisical/node-sdk-v2`, `github:Infisical/python-sdk-official`, `github:Infisical/go-sdk` | Secret metadata, project/environment context, token health | Active official SDK family. Never store secret values in memory. |
| 1Password | `github:1Password/onepassword-sdk-js`, `github:1Password/onepassword-sdk-python`, `github:1Password/onepassword-sdk-go`, `github:1Password/op-js` | Vault item metadata, service-account context, credential ownership | SDKs are beta; use read-only metadata patterns and never store secret values. |
| Doppler | `github:DopplerHQ/cli`, `docs:https://docs.doppler.com/reference/api` | Secret project/config context and CLI automation | CLI is active; use official API docs for server automation. |
| Bitwarden | `github:bitwarden/agent-access` | Agent credential access architecture and guardrails | Useful for design reference; treat tenant credential access as explicit approval work. |
| Drata | `docs:https://developers.drata.com/` | Compliance evidence, controls, tests, assets, personnel context | Public SDK repo was not found in GitHub search; use official API docs. |
| Vanta | `docs:https://developer.vanta.com/` | Compliance evidence, controls, tests, vendor/security reviews | Public SDK repo was not found in GitHub search; use official API docs. |

## Implementation Priority

Build or enrich connectors in this order when the goal is a useful Infosec assistant:

1. Current evidence sources: Cerebro, Panther MCP, GitHub, Jira/Linear, PagerDuty.
2. Identity and owner context: Okta, Microsoft Graph, Slack, service catalog, CODEOWNERS.
3. Cloud posture context: AWS, Azure, Google Cloud, Cloudflare, Kubernetes.
4. Scanner context: Prisma Cloud, Snyk, Semgrep, Checkov, Trivy, CrowdStrike, Tenable.
5. Response and compliance: ServiceNow, Tines, Drata, Vanta, Infisical, 1Password.

## Memory Write Examples

```json
{
  "kind": "connector_context",
  "topic": "CrowdStrike Falcon SDK sources",
  "summary": "CrowdStrike publishes active Python, Go, and PowerShell SDKs for Falcon API automation.",
  "tags": ["crowdstrike", "falcon", "sdk", "connector"],
  "entities": ["crowdstrike", "falconpy", "gofalcon", "psfalcon"],
  "scope": "connector-family:crowdstrike:falcon",
  "verified_by": ["github_repo_metadata"],
  "source_artifacts": [
    "github:CrowdStrike/falconpy",
    "github:CrowdStrike/gofalcon",
    "github:CrowdStrike/psfalcon"
  ],
  "staleness_policy": "until_reverified",
  "promotion_state": "promoted"
}
```

```json
{
  "kind": "access_context",
  "topic": "Microsoft Graph connector scope source",
  "summary": "Microsoft Graph connector implementations must verify tenant app permissions and Graph scopes from the official SDK/docs before reading identity or device data.",
  "tags": ["microsoft-graph", "identity", "access", "connector"],
  "entities": ["microsoft-graph", "entra-id"],
  "scope": "connector-family:microsoft-graph",
  "verified_by": ["github_repo_metadata"],
  "source_artifacts": [
    "github:microsoftgraph/msgraph-sdk-javascript",
    "github:microsoftgraph/msgraph-sdk-python",
    "github:microsoftgraph/msgraph-sdk-go"
  ],
  "staleness_policy": "until_reverified",
  "promotion_state": "promoted"
}
```
