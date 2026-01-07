# Cerebro Asset Inventory Capabilities

## Executive Summary

Cerebro provides a comprehensive asset inventory system that aggregates resources, principals (identities), configurations, and IAM relationships across multiple cloud providers and security tools. The system uses a normalized schema to enable cross-provider analysis, compliance reporting, and security findings generation.

---

## Core Data Model

### Entity Hierarchy

```
Organization
    └── Account (provider-specific tenant)
            ├── Resource (cloud/SaaS objects)
            │       └── ConfigSnapshot (point-in-time configurations)
            ├── Principal (users, groups, service accounts, apps, roles)
            └── IamEdge (permission relationships between principals and resources)
```

### Key Entities

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| **Organization** | Top-level tenant | org_id, name, slack_config |
| **Account** | Provider-specific account | account_id, provider, external_id, display_name |
| **Resource** | Cloud/SaaS object | resource_id, resource_type, external_id, name, parent_external_id |
| **Principal** | Identity entity | principal_id, principal_type, external_id, email, is_human |
| **ConfigSnapshot** | Point-in-time configuration | snapshot_id, captured_at, normalized_config, config_sha |
| **IamEdge** | Permission relationship | principal_id, resource_id, permission, via, is_admin |

---

## Source Systems & Providers

### Cloud Providers

| Provider | Resource Types Supported | Data Collected |
|----------|-------------------------|----------------|
| **AWS** | `aws.s3.bucket`, `aws.ec2.instance`, `aws.ec2.vpc`, `aws.ec2.security_group`, `aws.elbv2.load_balancer`, `aws.codebuild.project`, `aws.iam.role` | Resources, IAM users/roles/groups, policies, configurations, S3 ACLs/policies, security group rules |
| **GCP** | `gcp.compute.instance`, `gcp.storage.bucket`, `gcp.compute.network` | Compute instances, storage buckets, IAM bindings, network configs |
| **Azure** | `azure.storage.account`, `azure.storage.container` | Storage accounts, containers, blob configurations |

### Identity Providers

| Provider | Resource Types | Data Collected |
|----------|---------------|----------------|
| **Okta** | `okta_user`, `okta_application`, `okta_group` | Users, applications, groups, MFA status, authentication policies |
| **Microsoft 365** | `m365_user`, `m365_application`, `m365_conditional_access_policy` | Users, applications, conditional access policies, sign-in activity, licenses |
| **Google Workspace** | `workspace.user`, `workspace.group`, `workspace.orgunit`, `workspace.device.chromeos`, `workspace.admin.role` | Users, groups, org units, Chrome OS devices, admin roles |

### Code & Repository Platforms

| Provider | Resource Types | Data Collected |
|----------|---------------|----------------|
| **GitHub** | `github.repo`, `github.team`, `github.repository` | Repositories, teams, vulnerability alerts, secret scanning alerts, branch protection, collaborators |

### Infrastructure Platforms

| Provider | Resource Types | Data Collected |
|----------|---------------|----------------|
| **Kubernetes** | Various K8s resources | Cluster admin bindings, service accounts, pods, ingress, network policies |

### Endpoint Security Tools

| Integration | Data Collected | Key Capabilities |
|-------------|----------------|------------------|
| **SentinelOne** | Agents, threats, activities | Host telemetry, threat detection, agent health, installed software, IP addresses |
| **Kandji** | Devices, vulnerabilities, compliance | Device inventory, vulnerability detections, patch status, audit events, compliance scores, blueprints |

---

## Asset Data Categories

### 1. Resources (Infrastructure Assets)

Tracked via normalized `Resource` model with provider-specific enrichment:

| Schema Type | Standard Columns |
|-------------|------------------|
| **CORE** | id, provider, account_id, region, created_at, updated_at, tags, metadata |
| **ASSET** | hostname, ip_address, mac_address, os_family, os_version, agent_version, last_seen, status, criticality, owner, environment, network_interfaces, installed_software |
| **CONFIG** | resource_type, resource_name, arn, configuration, compliance_status, compliance_rules, availability_zone, relationships |

### 2. Identities (Principals)

Principal types supported:
- `user` - Human users
- `group` - User groups
- `service_account` - Service/machine accounts
- `app` - Applications
- `role` - IAM roles

Identity schema columns:
- user_id, username, email, display_name
- status, last_login, failed_logins
- groups, roles, mfa_enabled, locked
- password_changed, attributes

### 3. Security Findings/Alerts

Alert schema columns:
- alert_id, severity, status, title, description
- host_id, user_id, confidence
- tactics, techniques (MITRE ATT&CK)
- indicators, raw_event

### 4. Vulnerabilities

Vulnerability schema columns:
- vulnerability_id, cve_id, severity, cvss_score
- title, description, host_id
- package_name, package_version, fixed_version
- exploit_available, patch_available
- first_seen, remediation

### 5. Host Telemetry (Endpoints)

Full endpoint telemetry via `HostTelemetry` model:
- **Identity**: host_id, hostname, serial_number
- **System**: os_family, os_version, kernel_version, architecture
- **Network**: ip_addresses, mac_addresses
- **Software**: installed_packages (name, version, vendor, signature)
- **Health**: agent_health (status, last_heartbeat, issues)
- **Processes**: active process inventory (pid, name, command, binary_hash, user)
- **Connections**: network connections (protocol, local/remote address/port, status)
- **Threats**: detected threats with MITRE mappings
- **Drift**: configuration drift from baseline

---

## Linkages & Relationships

### 1. IAM Permission Graph

```
Principal ──[IamEdge]──► Resource
    │
    ├── permission: specific action allowed
    ├── via: how permission was granted (direct, group, role)
    ├── is_admin: administrative privileges
    ├── effective_at: when permission became active
    └── expires_at: expiration (for temporary access)
```

### 2. Resource Hierarchy

```
Account
    └── Resource (parent_external_id links to parent resource)
            └── ConfigSnapshot (historical configuration states)
```

### 3. Cross-Provider Identity Correlation

The system enables cross-provider analysis through:
- Email-based identity matching
- Finding producers that evaluate consistency (e.g., `InconsistentMfaEnforcementProducer`)
- Unified principal model across all providers

### 4. Finding Linkages

```
Finding
    ├── Organization (org_id)
    ├── Account (account_id)
    ├── Resource (resource_id)
    ├── Principal (principal_id)
    └── Rule (rule_id - the policy that triggered the finding)
```

---

## Query Capabilities

### SQL-like Query Interface

The system provides a Steampipe-inspired SQL query interface with standardized tables:

| Table Category | Examples |
|----------------|----------|
| **AWS Tables** | `aws_ec2_instance`, `aws_iam_user`, `aws_security_group` |
| **GCP Tables** | `gcp_compute_instance`, `gcp_storage_bucket`, `gcp_iam_binding` |
| **Okta Tables** | `okta_user`, `okta_application`, `okta_group` |
| **M365 Tables** | `m365_user`, `m365_application`, `m365_conditional_access_policy` |
| **GitHub Tables** | `github_repository`, `github_vulnerability_alert`, `github_secret_scanning_alert` |

### Query Context Features

- Column filtering and selection
- Time-based queries on timestamps
- Provider and account scoping
- Severity and status filtering
- Pagination (limit/offset)
- Order by support

---

## Finding Producers by Domain

### AWS Findings
- S3 public access detection
- Encryption enforcement
- IAM user MFA verification
- Administrative privilege detection

### GitHub Findings
- Branch protection enforcement
- Repository secret exposure
- Admin 2FA verification
- Vulnerability alert tracking
- Runner exposure detection

### GCP Findings
- Default VPC network detection
- Public storage bucket access

### Kubernetes Findings
- Cluster admin binding detection
- Service account token risks
- Privileged pod detection
- Public exposure (ingress, service, node)
- Network policy gaps

### Microsoft 365 Findings
- SharePoint anonymous links
- External file sharing
- Inactive admin detection
- Guest admin detection

### SentinelOne Findings
- Threat detection and classification
- MITRE ATT&CK technique mapping

### Cross-Provider Findings
- Inconsistent MFA enforcement across providers

---

## Data Collection Methods

### 1. Provider API Collection

Direct API integration via `BaseProvider` interface:
- `discover_resources()` - Enumerate cloud resources
- `discover_principals()` - Enumerate identities
- `get_resource_configuration()` - Fetch detailed configs
- `discover_iam_edges()` - Map permission relationships

### 2. Telemetry Ingestion

Real-time telemetry pipelines:
- **Repository Telemetry**: Secrets scan, dependency scan, SBOM, code metrics
- **Host Telemetry**: Endpoint state, processes, connections, software inventory
- **Runtime Telemetry**: Security events, configuration drift, health metrics

### 3. Integration Sync

Scheduled sync from external security tools:
- SentinelOne: Agents, threats, activities
- Kandji: Devices, vulnerabilities, patches, audit events

---

## Compliance Framework Support

### Framework Mappings

Rules and findings are mapped to compliance frameworks:
- **CWE** (Common Weakness Enumeration)
- **CIS** (Center for Internet Security Benchmarks)
- **NIST 800-53**
- **MITRE ATT&CK**
- **SOC 2**
- **ISO 27001**

### Evidence Collection

Compliance evidence collected via:
- Configuration snapshots (point-in-time proof)
- Finding history (remediation tracking)
- IAM edge analysis (access control verification)
- Audit events (activity logging)

---

## Metrics & Observability

### Collection Metrics
- Resources collected per provider/account
- Configuration snapshots captured per resource type
- IAM edges discovered
- Sync timestamps and event counts

### Integration Health
- Last sync timestamp per integration
- Events ingested count
- Error tracking

---

## Current Gaps & Future Considerations

### Potential Enhancements
1. **Azure Full Support**: Currently limited to storage; expand to VMs, networking, IAM
2. **Additional Identity Providers**: Auth0, Ping Identity, OneLogin
3. **Container Registries**: ECR, GCR, ACR vulnerability scanning
4. **Network Assets**: Firewalls, VPNs, network devices
5. **Secrets Managers**: HashiCorp Vault, AWS Secrets Manager inventory
6. **CI/CD Pipelines**: Jenkins, CircleCI, GitLab CI asset tracking

### Architecture Notes
- All providers implement the `BaseProvider` contract
- Finding producers registered via `FindingProducerRegistry`
- Telemetry ingestion via `TelemetryIngestionService`
- State tracking for incremental syncs via `IntegrationStateRepository`
