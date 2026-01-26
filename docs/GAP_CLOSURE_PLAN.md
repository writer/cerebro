# Cerebro Gap Closure Plan

## Executive Summary

This document outlines the implementation plan to address 50 identified compliance gaps (GitHub issues #220-269) between Cerebro's current capabilities and comprehensive security monitoring requirements. The gaps were identified through analysis of external compliance tooling.

## Implementation Phases

### Phase 1: Cloud Infrastructure Policies (Priority: HIGH)
**Issues**: #220-240
**Estimated Effort**: 2-3 weeks
**Dependencies**: Existing AWS/GCP sync engine

#### 1.1 AWS Configuration & Monitoring Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| AWS Config enabled all regions | `aws-config-enabled-all-regions.json` | `aws_config_configuration_recorders` | Exists |
| CloudTrail KMS encryption | `aws-cloudtrail-kms-encryption.json` | `aws_cloudtrail_trails` | NEW |
| CloudTrail S3 data events | `aws-cloudtrail-s3-data-events.json` | `aws_cloudtrail_trails` | NEW |
| CloudTrail log integrity | `aws-cloudtrail-log-integrity.json` | `aws_cloudtrail_trails` | NEW |
| Security Hub enabled | `aws-security-hub-enabled.json` | `aws_securityhub_hubs` | NEW |
| IAM Support role exists | `aws-iam-support-role.json` | `aws_iam_roles` | NEW |
| IAM Access Analyzer enabled | `aws-iam-access-analyzer.json` | `aws_accessanalyzer_analyzers` | NEW |
| IAM expired certificates | `aws-iam-expired-certs.json` | `aws_iam_server_certificates` | NEW |

#### 1.2 S3/RDS/EBS Security Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| S3 cross-region replication | `aws-s3-cross-region-replication.json` | `aws_s3_buckets` | NEW |
| S3 block public access | `aws-s3-block-public-access.json` | `aws_s3_buckets` | Exists |
| S3 HTTPS only | `aws-s3-https-only.json` | `aws_s3_bucket_policies` | NEW |
| S3 MFA delete on logging buckets | `aws-s3-mfa-delete-logging.json` | `aws_s3_buckets` | Exists |
| RDS publicly accessible | `aws-rds-publicly-accessible.json` | `aws_rds_instances` | Exists |
| RDS auto minor upgrade | `aws-rds-auto-minor-upgrade.json` | `aws_rds_instances` | NEW |
| RDS Multi-AZ | `aws-rds-multi-az.json` | `aws_rds_instances` | Exists |
| EBS encryption by default | `aws-ebs-encryption-default.json` | `aws_ec2_ebs_volumes` | Exists |

#### 1.3 IAM Security Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| Password policy minimum length | `aws-password-policy-length.json` | `aws_iam_account_password_policy` | NEW |
| Password policy no reuse | `aws-password-policy-reuse.json` | `aws_iam_account_password_policy` | NEW |
| Single access key per user | `aws-iam-single-access-key.json` | `aws_iam_users`, `aws_iam_user_access_keys` | NEW |
| Access keys rotated 90 days | `aws-iam-access-key-rotation.json` | `aws_iam_user_access_keys` | Exists |
| No root access keys | `aws-iam-no-root-keys.json` | `aws_iam_credential_reports` | Exists |
| IAM users via groups only | `aws-iam-users-via-groups.json` | `aws_iam_user_attached_policies` | NEW |
| No full admin policies | `aws-iam-no-admin-star.json` | `aws_iam_policies` | Exists |

#### 1.4 Network Security Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| VPC flow logs enabled | `aws-vpc-flow-logs.json` | `aws_ec2_vpcs`, `aws_ec2_flow_logs` | Exists |
| Default SG no rules | `aws-default-sg-no-rules.json` | `aws_ec2_security_groups` | NEW |
| NACL admin ports restricted | `aws-nacl-admin-ports.json` | `aws_ec2_network_acls` | NEW |
| SG admin ports IPv4/IPv6 | `aws-sg-admin-ports.json` | `aws_ec2_security_groups` | Exists |

#### 1.5 GuardDuty & Logging Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| GuardDuty enabled | `aws-guardduty-enabled.json` | `aws_guardduty_detectors` | Exists |
| GuardDuty notifications | `aws-guardduty-notifications.json` | `aws_eventbridge_rules` | NEW |
| Log retention 365 days | `aws-log-retention.json` | `aws_cloudwatch_log_groups` | Exists |

#### 1.6 EKS/ECS Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| EKS public endpoint restricted | `aws-eks-public-endpoint.json` | `aws_eks_clusters` | Exists |
| EKS private endpoint | `aws-eks-private-endpoint.json` | `aws_eks_clusters` | NEW |
| EKS audit logs | `aws-eks-audit-logs.json` | `aws_eks_clusters` | Exists |
| EKS secrets encryption | `aws-eks-secrets-encryption.json` | `aws_eks_clusters` | Exists |
| ECS ports restricted | `aws-ecs-ports-restricted.json` | `aws_ecs_services` | NEW |
| ECS SSH denied | `aws-ecs-ssh-denied.json` | `aws_ecs_services` | NEW |
| EC2 IAM roles (no keys) | `aws-ec2-iam-roles.json` | `aws_ec2_instances` | NEW |
| EC2 IMDSv2 | `aws-ec2-imdsv2.json` | `aws_ec2_instances` | Exists |

#### 1.7 GKE Hardening Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| GKE no alpha clusters | `gcp-gke-no-alpha.json` | `gcp_container_clusters` | NEW |
| GKE dashboard disabled | `gcp-gke-dashboard-disabled.json` | `gcp_container_clusters` | NEW |
| GKE secrets KMS encryption | `gcp-gke-secrets-kms.json` | `gcp_container_clusters` | NEW |
| GKE private endpoint | `gcp-gke-private-endpoint.json` | `gcp_container_clusters` | Exists |
| GKE network policy | `gcp-gke-network-policy.json` | `gcp_container_clusters` | NEW |
| GKE shielded nodes | `gcp-gke-shielded-nodes.json` | `gcp_container_clusters` | NEW |
| GKE auto-repair | `gcp-gke-auto-repair.json` | `gcp_container_node_pools` | NEW |
| GKE auto-upgrade | `gcp-gke-auto-upgrade.json` | `gcp_container_node_pools` | NEW |
| GKE COS containerd | `gcp-gke-cos-containerd.json` | `gcp_container_node_pools` | NEW |
| GKE metadata server | `gcp-gke-metadata-server.json` | `gcp_container_node_pools` | NEW |

### Phase 2: New Data Source Integrations (Priority: HIGH)
**Issues**: #252-259
**Estimated Effort**: 3-4 weeks
**Dependencies**: Provider framework

#### 2.1 Identity Providers
| Provider | File | Tables | Status |
|----------|------|--------|--------|
| Okta | `internal/providers/okta.go` | users, groups, apps, factors, logs | Exists (enhance) |
| Google Workspace | `internal/providers/google_workspace.go` | users, groups, mfa_status, drive_sharing | NEW |
| Entra ID (Azure AD) | `internal/providers/entra.go` | users, groups, apps, conditional_access, mfa | NEW |

#### 2.2 Endpoint/MDM Providers
| Provider | File | Tables | Status |
|----------|------|--------|--------|
| Kandji | `internal/providers/kandji.go` | devices, users, compliance | NEW |
| Jamf Pro | `internal/providers/jamf.go` | computers, mobile_devices, policies | NEW |
| Microsoft Intune | `internal/providers/intune.go` | devices, compliance_policies, apps | NEW |

#### 2.3 Security/EDR Providers
| Provider | File | Tables | Status |
|----------|------|--------|--------|
| SentinelOne | `internal/providers/sentinelone.go` | agents, threats, vulnerabilities | Exists (enhance) |

#### 2.4 Business Application Providers
| Provider | File | Tables | Status |
|----------|------|--------|--------|
| HRIS/Rippling | `internal/providers/rippling.go` | employees, departments, terminations | NEW |
| Jira | `internal/providers/jira.go` | issues, projects, security_issues | NEW |
| Salesforce | `internal/providers/salesforce.go` | users, profiles, login_history | NEW |
| Tailscale | `internal/providers/tailscale.go` | devices, users, acls | NEW |
| Slack | `internal/providers/slack.go` | users, channels, integrations | NEW |

### Phase 3: Operational Security Policies (Priority: MEDIUM)
**Issues**: #241-251
**Estimated Effort**: 2 weeks
**Dependencies**: Phase 2 data sources

#### 3.1 Endpoint Security Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| Disk encryption enabled | `endpoint-disk-encryption.json` | MDM devices | NEW |
| EDR agent installed | `endpoint-edr-installed.json` | MDM devices, S1 agents | NEW |
| EDR agent reporting | `endpoint-edr-reporting.json` | S1 agents | NEW |
| Screen lock configured | `endpoint-screenlock.json` | MDM devices | NEW |
| Password manager installed | `endpoint-password-manager.json` | MDM devices | NEW |

#### 3.2 Identity & Access Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| Account deprovisioning | `identity-account-deprovision.json` | HRIS, IdP users | NEW |
| SaaS MFA enforcement | `identity-saas-mfa.json` | IdP users | NEW |
| Stale accounts disabled | `identity-stale-accounts.json` | IdP users | NEW |
| Offboarding within SLA | `identity-offboarding-sla.json` | HRIS terminations | NEW |

#### 3.3 Vendor Risk Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| Vendor security review | `vendor-security-review.json` | Vendor data | NEW |
| Vendor DPA exists | `vendor-dpa-exists.json` | Vendor contracts | NEW |
| Vendor risk assessed | `vendor-risk-assessed.json` | Vendor data | NEW |

#### 3.4 Vulnerability Management Policies
| Policy | File | Tables Required | Status |
|--------|------|-----------------|--------|
| Vuln SLA critical | `vuln-sla-critical.json` | Vulnerability data | NEW |
| Vuln SLA high | `vuln-sla-high.json` | Vulnerability data | NEW |
| Security issue SLA | `security-issue-sla.json` | Jira security issues | NEW |

### Phase 4: Governance & Compliance Policies (Priority: MEDIUM)
**Issues**: #260-269
**Estimated Effort**: 2 weeks
**Dependencies**: Document/evidence storage

#### 4.1 Incident Response & BCDR
| Policy | File | Status |
|--------|------|--------|
| IR plan exists | `compliance-ir-plan.json` | NEW |
| IR plan tested | `compliance-ir-tested.json` | NEW |
| BCDR plan exists | `compliance-bcdr-plan.json` | NEW |
| BCDR plan tested | `compliance-bcdr-tested.json` | NEW |

#### 4.2 Privacy & Data Protection
| Policy | File | Status |
|--------|------|--------|
| Data inventory maintained | `privacy-data-inventory.json` | NEW |
| DPA with processors | `privacy-dpa-processors.json` | NEW |
| Privacy policy current | `privacy-policy-current.json` | NEW |

#### 4.3 Risk Management
| Policy | File | Status |
|--------|------|--------|
| Risk assessment annual | `risk-assessment-annual.json` | NEW |
| Risk register maintained | `risk-register-maintained.json` | NEW |

#### 4.4 PCI DSS Specific
| Policy | File | Status |
|--------|------|--------|
| CDE segmentation | `pci-cde-segmentation.json` | NEW |
| PAN encrypted | `pci-pan-encrypted.json` | NEW |
| PCI vendor compliance | `pci-vendor-compliance.json` | NEW |

## Implementation Details

### Policy JSON Structure

All policies follow this structure:

```json
{
  "id": "unique-policy-id",
  "name": "Human Readable Name",
  "description": "Detailed description of the security requirement",
  "effect": "forbid",
  "resource": "provider::service::resource_type",
  "conditions": [
    "field == value",
    "nested.field != expected"
  ],
  "severity": "critical|high|medium|low",
  "remediation": "Step-by-step remediation guidance",
  "tags": ["category", "compliance-framework"],
  "risk_categories": ["MISCONFIGURATION", "EXTERNAL_EXPOSURE"],
  "frameworks": [
    {"name": "SOC 2", "controls": ["CC6.1"]},
    {"name": "ISO 27001:2022", "controls": ["A.5.15"]}
  ],
  "mitre_attack": [
    {"tactic": "Initial Access", "technique": "T1190"}
  ]
}
```

### Provider Implementation Pattern

New providers follow this pattern:

```go
package providers

type NewProvider struct {
    *BaseProvider
    // API client fields
}

func NewNewProvider() *NewProvider {
    return &NewProvider{
        BaseProvider: NewBaseProvider("provider_name", ProviderTypeX),
    }
}

func (p *NewProvider) Configure(ctx context.Context, config map[string]interface{}) error
func (p *NewProvider) Test(ctx context.Context) error
func (p *NewProvider) Schema() []TableSchema
func (p *NewProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error)
```

### Table Naming Convention

Tables follow CloudQuery conventions:
- `{provider}_{service}_{resource}` (e.g., `aws_s3_buckets`)
- Custom tables: `{provider}_{entity}` (e.g., `okta_users`)

### Condition Operators

Supported in policy conditions:
- `==` - Equality
- `!=` - Inequality
- `>`, `<` - Numeric comparison
- `contains` - String contains
- `exists`, `not exists` - Field presence

### Testing Strategy

1. **Unit tests**: Each policy file has corresponding test cases
2. **Integration tests**: Sync engine tests with mock data
3. **Policy validation**: Schema validation on load

## File Structure

```
cerebro/
├── policies/
│   ├── aws/
│   │   ├── aws-cloudtrail-kms-encryption.json      # NEW
│   │   ├── aws-cloudtrail-s3-data-events.json      # NEW
│   │   ├── aws-cloudtrail-log-integrity.json       # NEW
│   │   ├── aws-security-hub-enabled.json           # NEW
│   │   ├── aws-iam-support-role.json               # NEW
│   │   ├── aws-iam-access-analyzer.json            # NEW
│   │   ├── aws-iam-expired-certs.json              # NEW
│   │   ├── aws-password-policy-length.json         # NEW
│   │   ├── aws-password-policy-reuse.json          # NEW
│   │   ├── aws-iam-single-access-key.json          # NEW
│   │   ├── aws-iam-users-via-groups.json           # NEW
│   │   ├── aws-s3-https-only.json                  # NEW
│   │   ├── aws-rds-auto-minor-upgrade.json         # NEW
│   │   ├── aws-default-sg-no-rules.json            # NEW
│   │   ├── aws-nacl-admin-ports.json               # NEW
│   │   ├── aws-guardduty-notifications.json        # NEW
│   │   ├── aws-eks-private-endpoint.json           # NEW
│   │   ├── aws-ecs-ports-restricted.json           # NEW
│   │   ├── aws-ecs-ssh-denied.json                 # NEW
│   │   └── aws-ec2-iam-roles.json                  # NEW
│   ├── gcp/
│   │   ├── gcp-gke-no-alpha.json                   # NEW
│   │   ├── gcp-gke-dashboard-disabled.json         # NEW
│   │   ├── gcp-gke-secrets-kms.json                # NEW
│   │   ├── gcp-gke-network-policy.json             # NEW
│   │   ├── gcp-gke-shielded-nodes.json             # NEW
│   │   ├── gcp-gke-auto-repair.json                # NEW
│   │   ├── gcp-gke-auto-upgrade.json               # NEW
│   │   ├── gcp-gke-cos-containerd.json             # NEW
│   │   ├── gcp-gke-metadata-server.json            # NEW
│   │   └── gcp-cloud-ids-notifications.json        # NEW
│   ├── identity/                                    # NEW CATEGORY
│   │   ├── identity-account-deprovision.json
│   │   ├── identity-saas-mfa.json
│   │   ├── identity-stale-accounts.json
│   │   └── identity-offboarding-sla.json
│   ├── endpoint/                                    # NEW CATEGORY
│   │   ├── endpoint-disk-encryption.json
│   │   ├── endpoint-edr-installed.json
│   │   ├── endpoint-edr-reporting.json
│   │   ├── endpoint-screenlock.json
│   │   └── endpoint-password-manager.json
│   ├── vendor/                                      # NEW CATEGORY
│   │   ├── vendor-security-review.json
│   │   ├── vendor-dpa-exists.json
│   │   └── vendor-risk-assessed.json
│   ├── compliance/                                  # NEW CATEGORY
│   │   ├── compliance-ir-plan.json
│   │   ├── compliance-bcdr-plan.json
│   │   ├── privacy-data-inventory.json
│   │   └── risk-assessment-annual.json
│   └── pci/                                         # NEW CATEGORY
│       ├── pci-cde-segmentation.json
│       └── pci-pan-encrypted.json
├── internal/
│   └── providers/
│       ├── google_workspace.go                      # NEW
│       ├── entra.go                                 # NEW
│       ├── kandji.go                                # NEW
│       ├── jamf.go                                  # NEW
│       ├── intune.go                                # NEW
│       ├── rippling.go                              # NEW
│       ├── jira.go                                  # NEW (expand existing)
│       ├── salesforce.go                            # NEW
│       ├── tailscale.go                             # NEW
│       └── slack.go                                 # NEW
```

## Success Metrics

1. **Policy Coverage**: 100% of identified gaps have corresponding policies
2. **Data Source Coverage**: All connected integrations have data flowing
3. **Test Coverage**: >80% unit test coverage on new code
4. **Finding Generation**: Policies generate findings when violations exist

## Timeline

| Phase | Duration | Start | End |
|-------|----------|-------|-----|
| Phase 1: Cloud Policies | 2-3 weeks | Week 1 | Week 3 |
| Phase 2: Data Sources | 3-4 weeks | Week 2 | Week 6 |
| Phase 3: Operational Policies | 2 weeks | Week 5 | Week 7 |
| Phase 4: Governance Policies | 2 weeks | Week 6 | Week 8 |

**Total Estimated Duration**: 8 weeks

## Next Steps

1. Begin Phase 1 implementation with AWS policies
2. Set up test infrastructure for new policies
3. Create provider skeletons for Phase 2
4. Document API requirements for each new provider
