# Prisma Cloud Connector Sources

Source repo: [PaloAltoNetworks/prisma-cloud-docs](https://github.com/PaloAltoNetworks/prisma-cloud-docs)

Indexed snapshot: `2db8d8faca11409ec9882d88e0f6f566b9099971` from the `master` branch.

Use this file as a source map for connector recall. Store connector catalog facts as `connector_context` with `source_artifacts` pointing to `prisma-cloud-docs:<path>`. Store permissions, role, token, SSO, or network tunnel requirements as `access_context`. Store alert destination semantics as `detection_context`. Do not copy raw setup steps into memory; use the source artifact to re-open the current docs before giving exact instructions.

## Enterprise Connectors

### Cloud Accounts

Source root: `docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts`

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| Cloud accounts index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/connect-cloud-accounts.adoc` | Entry point for cloud onboarding providers. |
| AWS account and organization onboarding | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-aws/onboard-aws.adoc` | Use for AWS account/org connection routing. |
| AWS permissions and ingested APIs | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-aws/aws-apis-ingested-by-prisma-cloud.adoc` | Use as source context for AWS coverage questions. |
| Azure account, tenant, subscription, and AD onboarding | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-azure-account/onboard-your-azure-account.adoc` | Use for Azure onboarding source lookup. |
| Azure APIs ingested | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-azure-account/microsoft-azure-apis-ingested-by-prisma-cloud.adoc` | Use as source context for Azure coverage questions. |
| GCP project and organization onboarding | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-gcp/onboard-gcp.adoc` | Use for GCP onboarding source lookup. |
| GCP APIs ingested | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-gcp/gcp-apis-ingested-by-prisma-cloud.adoc` | Use as source context for GCP coverage questions. |
| OCI tenant onboarding | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-oci-account/onboard-your-oci-account.adoc` | Use for OCI onboarding source lookup. |
| OCI APIs ingested | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-oci-account/oci-apis-ingested-by-prisma-cloud.adoc` | Use as source context for OCI coverage questions. |
| Alibaba Cloud onboarding | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-alibaba-account/onboard-your-alibaba-account.adoc` | Use for Alibaba Cloud onboarding source lookup. |
| Alibaba APIs ingested | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/connect/connect-cloud-accounts/onboard-your-alibaba-account/alibaba-apis-ingested-by-prisma-cloud.adoc` | Use as source context for Alibaba coverage questions. |

### Code And Build Providers

Source root: `docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers`

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| Code and build provider index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/connect-code-and-build-providers.adoc` | Entry point for Application Security connectors. |
| Code repositories index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/code-repositories.adoc` | Entry point for repository provider connectors. |
| GitHub | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-github.adoc` | SaaS GitHub repository connector. |
| GitHub Server | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-github-server.adoc` | Self-hosted GitHub connector. |
| GitLab | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-gitlab.adoc` | SaaS GitLab repository connector. |
| GitLab self-managed | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-gitlab-selfmanaged.adoc` | Self-managed GitLab connector. |
| Bitbucket | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-bitbucket.adoc` | SaaS Bitbucket connector. |
| Bitbucket Server | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-bitbucket-server.adoc` | Self-hosted Bitbucket connector. |
| Azure Repos | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-azurerepos.adoc` | Azure repository connector. |
| CI/CD runs index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/ci-cd-runs.adoc` | Entry point for CI/CD run connectors. |
| GitHub Actions | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-github-actions.adoc` | CI/CD run connector. |
| GitLab Runner | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-gitlab-runner.adoc` | CI/CD run connector. |
| Jenkins | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-jenkins.adoc` | CI/CD run connector. |
| CircleCI | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-circleci.adoc` | CI/CD run connector. |
| Azure Pipelines | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-azure-pipelines.adoc` | CI/CD run connector. |
| AWS CodeBuild | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-aws-codebuild.adoc` | CI/CD run connector. |
| Checkov | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-checkov.adoc` | CI/CD run connector. |
| Terraform Cloud / Enterprise run tasks | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-terraform-run-tasks.adoc` | Terraform run-task connector. |
| Terraform Enterprise run tasks | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-terraform-enterprise-run-tasks.adoc` | Terraform Enterprise run-task connector. |
| Terraform Enterprise | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-terraform-enterprise.adoc` | Terraform Enterprise connector. |
| Terraform Cloud Sentinel | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-runs/add-terraform-cloud-sentinel.adoc` | Terraform policy connector. |
| CI/CD systems index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-systems/ci-cd-systems.adoc` | Entry point for CI/CD systems. |
| Jenkins server | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-systems/add-jenkins-cicd-system.adoc` | CI/CD system connector. |
| CircleCI system | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ci-cd-systems/add-circleci-cicd-system.adoc` | CI/CD system connector. |
| Private registries | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/add-private-registries.adoc` | Package registry connector. |
| VS Code | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ides/connect-vscode.adoc` | IDE connector. |
| JetBrains | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/ides/connect-jetbrains.adoc` | IDE connector. |
| Network tunnel / Transporter | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/manage-network-tunnel/transporter-connectivity-overview.adoc` | Use for private VCS connectivity context. |

### External Integrations And Alert Destinations

Source root: `docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud`

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| Integrations index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/prisma-cloud-integrations.adoc` | Entry point for external integrations. |
| Supported capabilities | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrations-feature-support.adoc` | Use for capability/status-check questions. |
| Notification templates | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/add-notification-template.adoc` | Use for template setup context. |
| Amazon SQS | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-amazon-sqs.adoc` | Alert destination. |
| Azure Service Bus Queue | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-azure-service-bus-queue.adoc` | Alert destination. |
| Slack | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-slack.adoc` | Alert destination. |
| Splunk | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-splunk.adoc` | Alert destination. |
| Jira | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-jira.adoc` | Alert destination and ticketing integration. |
| Google Cloud SCC | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-google-cloud-security-command-center.adoc` | Alert destination. |
| ServiceNow | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-servicenow.adoc` | Alert destination and ticketing integration. |
| Webhooks | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-webhooks.adoc` | Generic alert destination. |
| PagerDuty | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-pagerduty.adoc` | Incident notification destination. |
| AWS Security Hub | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-aws-security-hub.adoc` | Cloud security destination. |
| Microsoft Teams | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-microsoft-teams.adoc` | Alert destination. |
| Cortex XSOAR | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-cortex-xsoar.adoc` | SOAR integration. |
| Qualys | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-qualys.adoc` | Vulnerability scanner integration. |
| Tenable | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-tenable.adoc` | Vulnerability scanner integration. |
| Amazon GuardDuty | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-amazon-guardduty.adoc` | Cloud detection source integration. |
| AWS Inspector | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-aws-inspector.adoc` | Scanner integration. |
| Amazon S3 | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-external-integrations-on-prisma-cloud/integrate-prisma-cloud-with-amazon-s3.adoc` | External storage/export integration. |
| Alert notification routing | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/alerts/send-prisma-cloud-alert-notifications-to-third-party-tools.adoc` | Use for alert-rule destination flow. |

### Identity And SSO

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| IAM security IdP services | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-iam-security/integrate-prisma-cloud-with-idp-services.adoc` | Entry point for identity provider integration. |
| Okta IAM security integration | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-iam-security/integrate-prisma-cloud-with-okta.adoc` | Okta integration context. |
| AWS IAM Identity Center | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/configure-iam-security/integrate-prisma-cloud-with-aws-id-center.adoc` | AWS identity integration context. |
| SSO overview | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/setup-sso-integration-on-prisma-cloud/setup-sso-integration-on-prisma-cloud.adoc` | SSO setup entry point. |
| SAML SSO overview | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/setup-sso-integration-on-prisma-cloud/get-started-with-saml-sso/get-started-with-saml-sso.adoc` | SAML source lookup. |
| OIDC SSO overview | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/setup-sso-integration-on-prisma-cloud/get-started-with-oidc-sso/get-started-with-oidc-sso.adoc` | OIDC source lookup. |
| SAML: Okta, Azure AD, OneLogin, Google, ADFS | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/setup-sso-integration-on-prisma-cloud/get-started-with-saml-sso/` | Use provider-specific file in this directory. |
| OIDC: Okta, Azure | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/administration/setup-sso-integration-on-prisma-cloud/get-started-with-oidc-sso/` | Use provider-specific file in this directory. |

## Runtime Security Connectors

### Cloud Accounts And Agentless Scanning

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| Runtime cloud accounts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/cloud-service-providers/use-cloud-accounts.adoc` | Runtime security cloud account source lookup. |
| Runtime cloud discovery | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/cloud-service-providers/cloud-discovery.adoc` | Cloud discovery context. |
| Agentless AWS | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/agentless-scanning/onboard-accounts/configure-aws.adoc` | Agentless scanning source lookup. |
| Agentless Azure | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/agentless-scanning/onboard-accounts/configure-azure.adoc` | Agentless scanning source lookup. |
| Agentless GCP | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/agentless-scanning/onboard-accounts/configure-gcp.adoc` | Agentless scanning source lookup. |
| Agentless OCI | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/agentless-scanning/onboard-accounts/configure-oci.adoc` | Agentless scanning source lookup. |

### Registry Scanning

Source root: `docs/en/enterprise-edition/content-collections/runtime-security/vulnerability-management/registry-scanning`

Supported source pages include `scan-acr.adoc`, `scan-alibaba.adoc`, `scan-artifactory.adoc`, `scan-coreos-quay.adoc`, `scan-docker.adoc`, `scan-ecr.adoc`, `scan-gar.adoc`, `scan-gcr.adoc`, `scan-gitlab.adoc`, `scan-harbor.adoc`, `scan-ibm.adoc`, `scan-nexus.adoc`, `scan-openshift.adoc`, and `webhooks.adoc`.

Store one `connector_context` record per registry connector only if the team actively uses or evaluates that connector. Use the exact source artifact path for the relevant file.

### Runtime CI, Alerts, Credentials, And Secrets

| Connector family | Source artifact | Notes for recall |
| --- | --- | --- |
| Runtime CI index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/continuous-integration/continuous-integration.adoc` | Runtime CI connector entry point. |
| Runtime code repository scanning | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/continuous-integration/code-repo-scanning.adoc` | Runtime code repo scan context. |
| Runtime alerts index | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/alerts.adoc` | Runtime alert destination entry point. |
| Runtime alert mechanisms | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/alert-mechanism.adoc` | Runtime alert mechanism context. |
| Runtime email alerts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/email.adoc` | Runtime email notification destination. |
| Runtime Google Cloud Pub/Sub alerts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/google-cloud-pub-sub.adoc` | Runtime Pub/Sub notification destination. |
| Runtime IBM Cloud Security Advisor alerts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/ibm-cloud-security-advisor.adoc` | Runtime IBM destination. |
| Runtime PagerDuty alerts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/pagerduty.adoc` | Runtime incident notification destination. |
| Runtime Cortex XDR alerts | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/alerts/xdr.adoc` | Runtime XDR destination. |
| AWS credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/aws-credentials.adoc` | Credential-store access context. |
| Azure credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/azure-credentials.adoc` | Credential-store access context. |
| GCP credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/gcp-credentials.adoc` | Credential-store access context. |
| IBM credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/ibm-credentials.adoc` | Credential-store access context. |
| Kubernetes credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/kubernetes-credentials.adoc` | Credential-store access context. |
| GitLab credentials store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/authentication/credentials-store/gitlab-credentials.adoc` | Credential-store access context. |
| Secrets stores overview | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/integrate-with-secrets-stores.adoc` | Secrets connector entry point. |
| AWS Secrets Manager | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/secrets-stores/aws-secrets-manager.adoc` | Runtime secrets connector. |
| AWS Systems Manager Parameter Store | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/secrets-stores/aws-systems-manager-parameters-store.adoc` | Runtime secrets connector. |
| Azure Key Vault | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/secrets-stores/azure-key-vault.adoc` | Runtime secrets connector. |
| CyberArk Enterprise Password Vault | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/secrets-stores/cyberark-enterprise-password-vault.adoc` | Runtime secrets connector. |
| HashiCorp Vault | `prisma-cloud-docs:docs/en/enterprise-edition/content-collections/runtime-security/secrets/secrets-stores/hashicorp-vault.adoc` | Runtime secrets connector. |

### API Description Roots

Use these sources when the assistant needs API-level context for automation or status reads. Store API capability facts as `connector_context`; store required auth, credential, proxy, SAML, OIDC, LDAP, or certificate facts as `access_context`.

| API family | Source artifact | Notes for recall |
| --- | --- | --- |
| Cloud discovery and scan APIs | `prisma-cloud-docs:docs/api/descriptions/cloud/` | Cloud account discovery and scan API source root. |
| Code repository APIs | `prisma-cloud-docs:docs/api/descriptions/coderepos/` | Runtime code repository scan API source root. |
| CI code repository APIs | `prisma-cloud-docs:docs/api/descriptions/coderepos-ci/` | CI code repository scan API source root. |
| Credentials APIs | `prisma-cloud-docs:docs/api/descriptions/credentials/` | Credential store API source root. |
| Registry APIs | `prisma-cloud-docs:docs/api/descriptions/registry/` | Registry scan, status, webhook, and download API source root. |
| Settings alert APIs | `prisma-cloud-docs:docs/api/descriptions/settings/alerts_get.md` | Alert settings read API. |
| Settings auth APIs | `prisma-cloud-docs:docs/api/descriptions/settings/` | Includes LDAP, OAuth, OIDC, SAML, proxy, certificate, registry, secrets, and scan settings descriptions. |
| Registry status API | `prisma-cloud-docs:docs/api/descriptions/statuses/registry_get.md` | Registry status source lookup. |

## Legacy And Mirror Trees

The repo also contains classic and versioned Compute docs with overlapping connector pages. Prefer the enterprise-edition content above for current recall. Use these trees only when a user asks about a classic UI, older Compute edition, or a source artifact already points there:

| Doc tree | Source artifact | Notes for recall |
| --- | --- | --- |
| Classic AppSec repositories | `prisma-cloud-docs:docs/en/classic/appsec-admin-guide/get-started/connect-your-repositories/` | Mirrors code repository, CI/CD, IDE, and package registry connectors. |
| Classic CSPM cloud accounts | `prisma-cloud-docs:docs/en/classic/cspm-admin-guide/connect-your-cloud-platform-to-prisma-cloud/` | Mirrors AWS, Azure, GCP, OCI, and Alibaba onboarding docs. |
| Classic CSPM external integrations | `prisma-cloud-docs:docs/en/classic/cspm-admin-guide/configure-external-integrations-on-prisma-cloud/` | Mirrors alert destinations and integrations. |
| Classic SSO | `prisma-cloud-docs:docs/en/classic/cspm-admin-guide/manage-prisma-cloud-administrators/` | Mirrors SAML and OIDC setup docs. |
| Classic Compute CI | `prisma-cloud-docs:docs/en/classic/compute-admin-guide/continuous-integration/` | Mirrors runtime CI scan docs. |
| Classic Compute registry scanning | `prisma-cloud-docs:docs/en/classic/compute-admin-guide/vulnerability-management/registry-scanning/` | Mirrors runtime registry scan docs. |
| Versioned Compute admin guides | `prisma-cloud-docs:docs/en/compute-edition/` | Version-specific Compute connector and runtime docs. |

## Memory Write Examples

```json
{
  "kind": "connector_context",
  "topic": "Prisma Cloud GitHub connector source",
  "summary": "Prisma Cloud Application Security has a GitHub code repository connector documented under the code repositories provider source tree.",
  "tags": ["prisma-cloud", "connector", "github", "code-repository"],
  "entities": ["github", "prisma-cloud", "code-repositories"],
  "scope": "connector:prisma-cloud:github",
  "verified_by": ["prisma_cloud_docs_repo"],
  "source_artifacts": [
    "prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-github.adoc"
  ],
  "staleness_policy": "until_reverified",
  "promotion_state": "promoted"
}
```

```json
{
  "kind": "detection_context",
  "topic": "Prisma Cloud alert notification connector flow",
  "summary": "Prisma Cloud alert rules can send policy violation notifications to configured third-party destinations; use the alert notification routing page to locate the destination-specific setup doc.",
  "tags": ["prisma-cloud", "alerts", "connector", "notifications"],
  "entities": ["prisma-cloud-alerts"],
  "scope": "connector-family:prisma-cloud:alert-destinations",
  "verified_by": ["prisma_cloud_docs_repo"],
  "source_artifacts": [
    "prisma-cloud-docs:docs/en/enterprise-edition/content-collections/alerts/send-prisma-cloud-alert-notifications-to-third-party-tools.adoc"
  ],
  "staleness_policy": "until_reverified",
  "promotion_state": "promoted"
}
```
