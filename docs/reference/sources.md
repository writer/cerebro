# Built-In Sources

Cerebro sources live under `sources/<id>` and expose their capabilities through `sources/*/catalog.yaml`.

Source-specific configuration is passed as `key=value` pairs in CLI calls or query parameters in HTTP calls. Required keys vary by source and family.

Declarative connector catalog entries are cataloged when a spec exists. They are callable only when the connector has wired auth and an earned validation grade of `fixture_validated` or higher in `internal/connectorvalidation/registry.yaml`; entries without evidence remain `generated_from_docs`.

| Source ID | Description | Emitted kinds / families |
| --- | --- | --- |
| `akeyless` | Akeyless secrets management source | items, auth methods, roles, audit events |
| `anthropic` | Anthropic organization governance source | organization, users, invites, workspaces and members, API keys, service accounts, federation, external keys, usage/cost reports, rate/spend limits, compliance activity |
| `archetype` | Archetype repository vulnerability scan source | scans, vulnerabilities |
| `asana` | Asana source | asana.audit_events, asana.projects, asana.users |
| `aurelius` | SaaS/business-operation export source | configured catalog families |
| `auth0` | Auth0 Management API source | users, roles, audit events |
| `aws` | AWS IAM, cloud, workload, network exposure, and CloudTrail source | access keys, IAM users/groups/roles/trust, EC2, ECS, EKS, Lambda, public endpoints, resource exposure, CloudTrail |
| `azure` | Azure Entra ID, RBAC, activity, and audit source | activity logs, directory audit, users, groups, role/app assignments, service principals, credentials, resource exposure |
| `backstage` | Backstage catalog source | components |
| `box` | Box source | box.audit_events, box.content_assets, box.users |
| `cerebro` | Cerebro product access telemetry source backed by structured NDJSON archives | API access audit events |
| `cloudflare` | Cloudflare account and network source | accounts, members, roles, zones, DNS records, Gateway rules, Workers scripts |
| `conjur` | Conjur source | conjur.authenticator, conjur.resource, conjur.resource_2, conjur.resource_3 |
| `cosmo` | Cosmo workflow and message source | messages, survey feedback, configured families |
| `datadog` | Datadog observability and incident source | users, roles, teams, monitors, SLOs, dashboards, incidents, audit events |
| `discord` | Discord source | discord.audit_log, discord.member, discord.permission, discord.role |
| `doppler` | Doppler secrets management source | secrets, projects, audit events |
| `duo` | Duo identity and MFA source | users, groups, endpoints, phones, tokens, WebAuthn credentials |
| `email_domain_health` | Email domain authentication posture source (SPF, DKIM, DMARC, MX, MTA-STS) | health |
| `evidence_cas` | EvidenceCAS content-addressed evidence reference source | object manifests |
| `gcp` | GCP IAM, Cloud Identity, service-account, and audit source | audit, groups, IAM role assignments, service accounts, resource exposure |
| `github` | GitHub audit, repository, Dependabot, and pull request source | audit, repository, Dependabot alerts, pull requests; repository and optional org-inventory audit-log freshness probes |
| `google_workspace` | Google Workspace Directory and Admin audit source | audit, groups, group members, role assignments, users |
| `grc` | Governance/risk/compliance source | configured GRC families |
| `hashicorp_vault` | HashiCorp Vault secrets management source | users, secrets, audit events |
| `kandji` | Kandji device/application/vulnerability source | devices, applications, vulnerabilities |
| `kolide` | Kolide device posture source | configured catalog families |
| `kubernetes` | Kubernetes inventory source | clusters, namespaces, pods, containers, service accounts, workloads, workload identity bindings |
| `langchain` | LangChain LangSmith governance and observability source | organization, workspaces, members, roles, service keys, service accounts, tracing projects, runs, feedback, datasets, usage limits, audit logs |
| `langfuse` | Langfuse LLM observability and prompt-management source | projects, project memberships, project API keys, traces, observations, scores, prompts, sessions, metrics, annotation queues |
| `linode` | Linode source | linode.credential, linode.event, linode.issue, linode.user |
| `meraki` | Cisco Meraki Dashboard API source | event types, organizations, Meraki auth users, access policies |
| `okta` | Okta audit, identity inventory, app, group, authenticator, assignment, and admin role source | audit, users, groups, applications, assignments, admin roles, authenticators, threat insight |
| `openai` | OpenAI organization governance source | audit logs, users, invites, groups, roles, projects, project access, service accounts, API keys, usage/costs, retention, spend alerts, certificates, rate limits, model/tool permissions |
| `pagerduty` | PagerDuty incident management source | users, teams, services, schedules, escalation policies, integrations, vendors |
| `panopticon` | Panopticon security operations API source | cases by default; alerts and IOCs explicitly |
| `probely` | Probely web vulnerability scanning source | findings needing attention, events, users, frameworks |
| `rootly` | Rootly incident response source | alerts, incidents, monitors, dashboards, audit events |
| `sdk` | Generic SDK push source for onboarded applications | validates pushed integration config; optional declared inventory URN discovery; preview reads are empty |
| `sentinelone` | SentinelOne endpoint posture and threat source | agents, threats, activities, applications, exclusions, groups, sites |
| `security_tooling_map` | Security tooling inventory source | configured tooling-map families |
| `slack` | Slack workspace source | teams, users, channels, user groups |
| `tailscale` | Tailscale network source | tailnets, users, devices, groups, tags, services, grants |
| `trivy` | Trivy report source | image scans, image packages, image vulnerabilities, fixes |
| `trusted_endpoint` | Trusted Endpoint posture, AI trust, GRC evidence, and trust-gate source | metadata-only endpoint posture, AI risk, evidence, findings, and action outcomes |
| `twilio` | Twilio source | twilio.accounts, twilio.audit_events, twilio.keys |
| `vulnview` | Vulnerability and attack-surface source | sites, scans, vulnerabilities, assets, DNS alerts |
| `writer` | Writer AI Studio source | models, Knowledge Graphs, files, no-code agents, application graph associations, async application jobs |
