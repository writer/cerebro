# Aperio Integration Contract

This document defines the integration boundary between Writer Aperio and Cerebro.

Aperio owns the opinionated SaaS security product surface: curated detection packs, provider-specific rule toggles,
severity and MITRE context, custom rule UX, Shadow IT/OAuth risk scoring, incident workflows, and analyst approvals.
Cerebro owns the durable shared fabric: source runtimes, claims, findings, evidence, graph projection, GRC context,
risk scoring, Ask/agent workflows, action audit, and cross-source inventory. Cerebro Web is the workbench over those
runtime contracts.

## Runtime Identity

The default Aperio producer runtime is:

```text
runtime_id=writer-aperio-saas-dr
source_id=aperio_saas_dr
owner=aperio
surface=aperio_saas_dr
```

Deployments may override the runtime id, but the source id should remain stable so Web, reports, coverage, and Ask
can identify Aperio-produced SaaS detection and response context.

## Claim Vocabulary

Aperio should write facts through source-runtime claims. Neo4j remains a projection of those claims and must not be
treated as the source of truth.

For SaaS findings, Aperio should continue to emit the generic finding shape:

```text
finding exists
asset exists
integration exists
finding affects asset
finding observed_by integration
finding.title/provider/severity/riskScore/status/ruleId attributes
```

For Shadow IT and OAuth risk, Aperio should additionally emit this vocabulary when the data is known:

```text
oauth_app exists
oauth_grant exists
oauth_scope exists
identity exists
resource_family exists

finding concerns_oauth_app oauth_app
finding concerns_oauth_grant oauth_grant
identity has_oauth_grant oauth_grant
oauth_grant granted_by identity
oauth_grant authorized_app oauth_app
oauth_grant has_scope oauth_scope
oauth_app accesses resource_family
oauth_app observed_by integration
```

Recommended attributes:

| Subject | Attributes |
| --- | --- |
| `oauth_app` | `provider`, `externalAppId`, `displayName`, `riskScore`, `criticality`, `riskReason`, `clientType` |
| `oauth_grant` | `status`, `scopeCount`, `lastObservedAt`, `anonymous`, `nativeApp` |
| `oauth_scope` | `scope`, `resourceFamily` |
| `identity` | `email` |

The resource-family relation is intentionally coarse. It gives Ask, evidence packets, and impact queries enough
semantic shape to explain Gmail, Drive, directory/admin, cloud-data, GitHub repo/org, and Slack workspace exposure
without requiring every SaaS product to implement a full native source first.

## External Lifecycle References

When Aperio owns the user workflow, it should link the Cerebro finding back to Aperio with
`LinkFindingExternalRef` or the HTTP equivalent:

```text
system=aperio
kind=finding | incident | response_action | oauth_grant
external_id=<Aperio id>
url=<Aperio URL>
external_status=<Aperio status>
lifecycle_owner=external_owned
observed_at=<Aperio observation/update time>
```

Cerebro should preserve these references on finding reads and Web should present Aperio as the workflow owner.
Agent and MCP proposals should not directly close externally owned findings unless the calling workflow explicitly
intends to hand ownership back to Cerebro.

## Response Actions

Aperio response actions should use the Cerebro action ladder:

1. Write or refresh claims that identify the affected finding, target, OAuth grant, user, and resource family.
2. Attach or refresh an Aperio external lifecycle reference.
3. Use `ExecuteGraphAction` with `dry_run=true` for provider-backed plans where Cerebro owns the adapter.
4. Require `approved=true` for mutating execution.
5. Use `ReconcileGraphAction` to refresh provider status and update the linked external reference.

Initial action names to align across the products:

```text
google_workspace.revoke_oauth_grant
slack.revoke_app_install
github.revoke_oauth_app
okta.suspend_user
microsoft_365.revoke_sessions
atlassian.revoke_user_access
salesforce.remove_admin_role
```

Actions that are still owned by Aperio should still be represented as external refs and workflow events so Cerebro
evidence packets, reports, audit logs, and Ask can explain what happened.

`GET /platform/runtime-response/capabilities` advertises those Aperio-owned SaaS response actions with
`mode=external_aperio_workflow`, `external_owner=aperio`, `supported=false`, `dry_run=true`, and
`approval_required=true`. That lets Web and agents discover the action vocabulary, target types, and required context
keys while preserving Aperio as the workflow owner. Until a specific provider adapter moves into Cerebro, callers
should use the Aperio MCP proposal path, especially `aperio.propose_cerebro_response`, rather than POSTing those
external workflow actions to `/platform/runtime-response/actions`.

## Detection Pack And Coverage Metadata

Aperio detection packs should publish stable pack metadata alongside findings:

```text
pack_id
pack_version
provider
rule_id
severity
mitre_techniques
intent
tags
custom_rule_id
source_coverage_refs
control_refs
```

Cerebro should consume this as detection catalog, evidence, and coverage metadata. Aperio remains the product surface
for pack toggles and custom rule authoring; Cerebro remains the durable reporting and evidence fabric.

## Ask Context

Web and product surfaces should pass these context keys when available:

```text
aperio_finding_id
aperio_incident_id
oauth_app_id
oauth_grant_id
pack_id
rule_id
mcp_resource_uri
```

Ask should preserve Aperio workflow ownership in responses, prioritize the scoped finding or OAuth grant before broad
search, and cite Cerebro tools or evidence packets when they are used.

## Traceability

Aperio should propagate W3C `traceparent` into Cerebro claim writes, external-ref updates, action requests, MCP calls,
and Web deep links. Cerebro Web should surface the returned trace id so an analyst can follow a detection from Aperio
sync through claim projection, graph reasoning, evidence packet generation, and response action reconciliation.
