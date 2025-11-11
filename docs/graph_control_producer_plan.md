# Graph Controls Detection Coverage Expansion Plan

## 1. Executive Summary

- **Total controls in Graph Controls catalog:** 1,402
- **Controls currently mapped to Cerebro producers:** 3 (≈0.2%)
- **Immediate goal:** design and stage producer implementations plus supporting data integrations so that Cerebro can automatically evaluate the remaining 1,399 controls.
- **Approach:** build coverage in waves by control theme (public exposure, credential leakage, identity hygiene, runtime compromise, AI/ML data protection, CI/CD supply chain) while standing up the cross-cutting telemetry required for each theme.

## 2. Current State Assessment

### 2.1 Data ingestion that already exists in Cerebro

| Area | Capability today | Key modules |
| --- | --- | --- |
| Cloud inventory | AWS `ec2`, `s3`, `iam`, `vpc` discovery with config snapshots; early GCP compute/service-account ingestion | `src/cerebro/providers/aws/`, `providers/gcp/`, `collectors/collector.py` |
| SaaS & identity | GitHub org/repo/branch protection data, Okta MFA findings, M365 sharing | `providers/github/`, `providers/okta/`, `findings/producers/okta/` |
| Endpoint & runtime telemetry | SentinelOne connector, desktop agent events, runtime telemetry schemas (process/network/package inventory) | `integrations/sentinelone.py`, `telemetry/services.py`, `telemetry/schemas.py` |
| Evidence + compliance plumbing | Control test orchestration, framework registry, evidence store | `compliance/control_tests.py`, `compliance/framework_integration.py` |

### 2.2 Existing finding producers

The repository currently registers producers for a narrow set of issues:

- **AWS:** public S3 bucket (`S3BucketPublicProducer`), EC2 instances with public IPs (`EC2InstancePublicIPProducer`), IAM users without MFA (`IAMUserWithoutMFAProducer`).
- **GitHub:** default branch without protection, admins without MFA, organisation-wide 2FA gaps.
- **Okta:** users missing MFA.
- **M365:** externally shared files.
- **Cross-provider:** inconsistent MFA enforcement heuristics.

These producers only satisfy three Graph Controls outright (public S3 bucket and two AWS IAM MFA variants). Every other catalog item lacks automated coverage because we do not yet ingest the right telemetry or we have not modelled the evaluation logic.

### 2.3 Key coverage gaps

1. **Internet-facing compute exposed to in-the-wild CVEs** – requires vulnerability signals tied to host inventory across AWS, Azure, GCP, on-prem, and container platforms.
2. **Container runtime and Kubernetes privilege issues** – needs cluster state, workload descriptors, admission controller policies, runtime threat telemetry.
3. **Secrets & API key exposure in storage and code** – needs object storage scanning, repository/CI secret detection, SaaS audit logs.
4. **Identity posture (MFA, credential misuse, lateral movement paths)** – needs IdP event ingestion (Okta, Azure AD), usage analytics, IAM relationship graphing.
5. **AI/ML data protection** – requires inventory of model training artifacts, storage buckets, and access posture for services like Bedrock, Vertex, custom Kubernetes ML stacks.
6. **CI/CD runners and supply chain** – needs inventory of self-hosted runners, build service configs, exposure of service accounts and tokens.
7. **Malware/ransomware detections** – must correlate SentinelOne (and other EDR) telemetry with cloud workload metadata.

## 3. Control Taxonomy Snapshot

Automated parsing of the catalog produced the following theme counts (non-exclusive tags):

| Theme | Count |
| --- | ---: |
| Public VM / serverless exposure | 272 |
| Explicit CVE references | 167 |
| Secrets & API keys (OpenAI, Okta, cloud keys, SSH) | 140 |
| Public containers / images | 136 |
| Code repository & CI/CD pipeline issues | 177 |
| Service account misuse / lateral movement | 123 |
| Kubernetes-specific findings | 90 |
| Identity provider anomalies (Okta, Entra, Cognito) | 67 |
| Malware / cryptominer / ransomware | 56 |
| AI/ML training asset exposure | 511 |
| Databases exposed (SQL, PaaS DB) | 52 |

These figures drive the priority order in the coverage roadmap below.

## 4. Theme-by-Theme Coverage Plan

Each subsection enumerates (a) the Graph Control themes it addresses, (b) the systems and telemetry we must ingest, (c) the specific finding producers to build, and (d) implementation notes pointing to the Cerebro modules to extend.

### 4.1 Internet-Facing Compute & CVE Exploitation

**Representative controls:** multiple entries like “Publicly exposed VM vulnerable to CVE-2024-23897”, “VM with high privileges using IMDSv1 and cleartext keys”, “Public API endpoint exposing sensitive software”.

**Telemetry needed:**

- **Cloud provider inventory:**
  - AWS: extend `AWSProvider` to enrich EC2, ALB, Lambda, and Security Group data (ingest `describe_security_groups`, `describe_network_interfaces`, `describe_load_balancers`).
  - Azure: new provider using Microsoft Graph + Azure Resource Manager to enumerate VM scale sets, public IP associations, NSGs.
  - GCP: enhance `GCPProvider` to cover firewall rules, Cloud Run, GCE metadata (IMDS), load balancers.
- **Vulnerability intelligence:**
  - Integrate AWS Inspector, Azure Security Center, GCP Security Command Center APIs for managed findings.
  - Ingest EDR software inventory (SentinelOne `installed_packages` in `HostTelemetry`) and join with NVD CVE feeds to detect unpatched software.
- **Network exposure verification:**
  - Capture public DNS/IP from cloud APIs and confirm exposure via Shodan-like recon or Cloud provider `describe_addresses`/`listForwardingRules`.
- **Credential adjacency:**
  - Use `ConfigSnapshot` data for attached IAM roles, instance profiles.

**Producer roadmap:**

| Producer | Scope | Inputs | Detection logic |
| --- | --- | --- | --- |
| `AwsVmCveExposureProducer` | AWS EC2 / Lambda | EC2 config + Inspector findings + security groups | Flag when CVE severity ≥ High exists on public IP reachable ports. | 
| `AzureVmCveExposureProducer` | Azure VMs | Azure Security Center recommendations + NSG rules | Same pattern as AWS but via Microsoft Defender findings.
| `GcpComputeCveExposureProducer` | GCE / Cloud Run | SCC findings + firewall rules + metadata server usage | Detect exposures including IMDSv1 usage.
| `VmImdsAbuseProducer` (multi-cloud) | AWS/GCP/Azure | Instance metadata config + network logs | Flag IMDSv1 + SSRF chains referenced by controls.

**Implementation notes:**

- New providers should inherit from `BaseProvider` and plug into `ConfigCollector` for asset discovery.
- CVE correlation lives in a shared service (e.g. `cerebro/analysis/vuln_enrichment.py`) that normalises Inspector/Defender/SCC payloads.
- Producers belong under `findings/producers/aws/azure/gcp/` and should map to the CVE-specific Graph Controls through `framework_mappings`.
- Extend `telemetry/services.py` to attach host telemetry (SentinelOne package list) to cloud instances by asset tags for cross-validation.

### 4.2 Container Runtime & Kubernetes Privilege Concerns

**Representative controls:** “Internet-facing container with high Kubernetes privileges…”, “Kubernetes cluster with Ingress NGINX Controller vulnerable to RCE”, “Publicly exposed kubelet port 10255”.

**Telemetry needed:**

- **Cluster inventory:**
  - Add Kubernetes provider (`providers/kubernetes/`) using kubeconfig/Cluster API to fetch `Pod`, `Deployment`, `Ingress`, `Service`, `ClusterRole`, `RoleBinding` objects.
  - For managed services (EKS/GKE/AKS), integrate cloud APIs for control plane settings.
- **Admission controller & daemon metrics:** fetch from Kubernetes API (ValidatingWebhookConfiguration, MutatingWebhookConfiguration) and NGINX Ingress config maps.
- **Container registry metadata:** use AWS ECR/GCP Artifact Registry/Azure Container Registry APIs to fetch image vulnerability reports (Trivy/Inspector/Artifact Analysis).
- **Runtime telemetry:** extend SentinelOne mapping to container hosts; optionally integrate Falco or AWS GuardDuty EKS findings.

**Producer roadmap:**

| Producer | Scope | Inputs | Detection logic |
| --- | --- | --- | --- |
| `K8sIngressRceProducer` | NGINX ingress | Kubernetes API (Ingress class, annotations) + CVE feed | Identify vulnerable controller versions exposed via LoadBalancer/IP.
| `K8sPublicKubeletProducer` | Kubelet | Node daemonset config + port checks | Flag 10255/10250 exposed nodes where `authentication.anonymous.enabled=true`.
| `K8sPrivilegedPodProducer` | Workloads | Pod spec + RBAC data | Spot pods with `hostNetwork`, `privileged:true`, service account with cluster-admin.
| `ContainerImageCveProducer` | Images | Registry scan reports + deployment references | Emit findings when CVEs > threshold exist on internet-facing pods.

**Implementation notes:**

- Create shared Kubernetes client wrapper under `providers/kubernetes/client.py` with caching for large clusters.
- Normalise Kubernetes objects into `ResourceEntity` (`k8s.cluster`, `k8s.namespace`, `k8s.pod`).
- Producers go under `findings/producers/kubernetes/` and reuse helper utilities for evaluating pod specs.

### 4.3 Secrets, API Keys, and Storage Exposure

**Representative controls:** numerous entries around buckets with cleartext OpenAI/Okta keys, public storage accounts, validated exposure of SSH keys.

**Telemetry needed:**

- **Storage configuration:**
  - Extend AWS S3 collector to ingest bucket policies/ACLs (already partially done) plus object-level inventory via S3 Inventory or Macie exports.
  - Build collectors for Azure Blob, GCP Cloud Storage, OCI buckets.
- **Secret scanning:**
  - Expand repository telemetry (currently Pydantic `SecretsScanResult`) to scan containers, bucket objects (using Amazon Macie / Google DLP or custom scanners), and CI logs.
  - Pull secret detection results from tools like GitGuardian, TruffleHog into `telemetry/services.process_repository`.
- **API key validation:** integrate with provider APIs to verify whether leaked keys are valid (e.g. call OpenAI `GET /models`, Okta `/api/v1/users` with key limited scope in isolated worker).

**Producer roadmap:**

| Producer | Input | Logic |
| --- | --- | --- |
| `BucketCleartextKeyProducer` | Storage object scans + bucket ACLs | Emit when credentials detected and bucket is public or cross-account accessible. |
| `RepoSecretKeyProducer` | Repository telemetry secrets scan | Map secret types (OpenAI, Okta, cloud) to Graph Controls and confirm key validity using provider-specific probes. |
| `StorageWriteAccessProducer` | Bucket policies + Access Analyzer output | Detect buckets allowing anonymous write (required for AI training poisoning controls). |

**Implementation notes:**

- Introduce `analysis/secrets/catalog.py` enumerating regexes + validation handlers.
- Update `telemetry/services.process_repository` to invoke validation routines asynchronously, storing evidence in `FindingEntity.evidence`.
- For bucket object scanning, schedule asynchronous jobs via `tasks/` to iterate through target prefixes using provider SDKs.

### 4.4 Identity & Access Management Hygiene

**Representative controls:** Okta users with suspicious logins, Azure AD users without MFA, service accounts assumable by all, Cognito identity pools without restrictions.

**Telemetry needed:**

- **IdP audit logs:** Okta System Log API, Azure AD sign-in logs (via Microsoft Graph `auditLogs/signIns`), AWS CloudTrail for Cognito, Google Workspace Admin reports.
- **IAM relationship graphs:** reuse `collectors._collect_iam_edges` but extend to cover Azure role assignments, GCP IAM bindings, Okta group memberships, AWS IAM Access Analyzer findings.
- **Behavior analytics:** central store for login anomalies (unfamiliar IPs, device fingerprinting) using `telemetry/HostEvent`.

**Producer roadmap:**

| Producer | Scope | Inputs | Logic |
| --- | --- | --- | --- |
| `AzureUserMfaProducer` | Entra ID users | Graph user properties + sign-in logs | Flag admin users with `strongAuthenticationMethods` empty. |
| `OktaSuspiciousLoginProducer` | Okta users | System log events + risk signals | Emit when login risk level high for accounts with lateral movement privileges. |
| `AwsServiceAccountAssumableProducer` | IAM roles | IAM policy graph + Access Analyzer results | Detect roles assumable by all principals or external accounts with sensitive data access. |
| `CognitoAnonymousImpersonationProducer` | Cognito pools | Pool configuration + CloudTrail events | Surface pools allowing unauthenticated role escalation. |

**Implementation notes:**

- Build IdP collectors under `providers/azure_ad/`, `providers/okta/` (extend), `providers/aws/cognito.py`.
- Normalise audit events into a unified model (extend `telemetry/schemas.SecurityEvent`).
- Producers should join identity telemetry with privilege context from `IamPermissionEntity`.

### 4.5 CI/CD, Runners, and Supply Chain

**Representative controls:** “Code repository with branch protection disabled builds privileged container”, “Publicly exposed runner with cryptominer”, “CodeBuild project allowing public triggers”.

**Telemetry needed:**

- **CI platform APIs:**
  - GitHub: extend provider to fetch Actions runner groups, workflow permissions, OIDC trust policies.
  - GitLab/CircleCI/Env0/Spacelift/Terraform Cloud: create lightweight REST clients to list projects, runners, OIDC bindings.
- **Build environment telemetry:** integrate with SentinelOne + runtime telemetry to tag self-hosted runners (hostnames, process metadata).
- **Artifact provenance:** collect build logs, SBOMs, and publish to `telemetry.RepositoryTelemetry` for dependency vulnerability evaluation.

**Producer roadmap:**

| Producer | Scope | Inputs | Logic |
| --- | --- | --- | --- |
| `GithubRunnerExposureProducer` | Self-hosted runners | GitHub REST v3 + host telemetry | Flag runners on public subnets lacking hardening (SSH password auth, weak creds).
| `CodeBuildPublicTriggerProducer` | AWS CodeBuild | CodeBuild `ListProjects`, `BatchGetProjects` + IAM policies | Identify projects with `sourceAuth` exposing public webhooks.
| `CiOidcMisconfigProducer` | Multi-platform | Platform OIDC configs + IaC definitions | Ensure trust policies restrict audiences/subjects per Graph Control list.

**Implementation notes:**

- Extend `providers/github/provider.py` to surface runner metadata (REST endpoint `/orgs/{org}/actions/runners`).
- Normalise runner hosts into `ResourceEntity` (e.g., `ci.runner`).
- Join with SentinelOne telemetry by `host_id` to cross-check malware findings.

### 4.6 AI/ML Artifact and Data Protection

**Representative controls:** exposures around Vertex AI, Bedrock, model buckets, AI training datasets, fine-tuned model leakage.

**Telemetry needed:**

- **Service-specific APIs:**
  - AWS Bedrock: `ListModelCustomizationJobs`, `GetModelInvocationLoggingConfiguration`, associated S3 buckets.
  - GCP Vertex AI: `projects.locations.datasets`, `ModelService`, AutoML dataset listings.
  - Azure OpenAI + ML service workspace metadata.
- **Storage posture:** capture bucket ACLs, encryption keys, cross-account access as in section 4.3.
- **Model registry events:** integrate with existing `telemetry` pipeline to store metadata (model versions, training inputs, access control lists).

**Producer roadmap:**

| Producer | Scope | Inputs | Logic |
| --- | --- | --- | --- |
| `BedrockModelExposureProducer` | AWS Bedrock | Bedrock job metadata + S3 bucket configs | Flag jobs with public/writeable training buckets or exposed API keys.
| `VertexDatasetExposureProducer` | GCP Vertex | Dataset resource listing + bucket ACLs | Detect publicly readable datasets or keys accessible to all users.
| `MlModelSecretLeakProducer` | Multi-cloud | Model registries + secret scans | Emit findings when model artifacts contain API keys or are stored in public registries.

**Implementation notes:**

- Create dedicated clients under `providers/aws/bedrock.py`, `providers/gcp/vertex.py` leveraging official SDKs.
- Extend evidence schema to capture model identifiers (`evidence["model_id"]`, `evidence["training_bucket"]`).

### 4.7 Service Accounts, Lateral Movement, and Cross-Account Access

**Representative controls:** “Service account can be assumed by all users”, “Bucket accessible by service account assumed by everyone”, “User/service account with lateral movement finding to admin”.

**Telemetry needed:**

- **IAM graph:** unify edges across AWS/GCP/Azure/Okta as noted earlier, but also ingest Access Analyzer (AWS), IAM Analyzer (GCP), Azure Privileged Identity Management.
- **Runtime correlation:** combine host/network telemetry to detect actual lateral movement attempts (SentinelOne events, CloudTrail `AssumeRole`, Azure Sign-in logs).
- **Risk scoring:** track service account usage frequency, secrets distribution (CI pipelines).

**Producer roadmap:**

| Producer | Scope | Inputs | Logic |
| --- | --- | --- | --- |
| `ServiceAccountOpenAssumeProducer` | Multi-cloud | IAM policies + Access Analyzer | Identify principals with `Principal="*"` on assume role/service account bindings plus sensitive resource access. |
| `LateralMovementRuntimeProducer` | Runtime events | CloudTrail, SentinelOne, Azure Sign-in logs | Correlate suspicious sequences (credential access + privileged role assumption). |

**Implementation notes:**

- Implement IAM graph queries using the existing `analysis` layer or extend `attack_path` module to compute reachability.
- Producers should enrich findings with path evidence (sequence of edges) for auditability.

### 4.8 Malware, Botnets, and Ransomware Indicators

**Representative controls:** mentions of DreamBus, Gobruteforcer, LABRAT, Androxgh0st, Mimic ransomware, destructive malware campaigns.

**Telemetry needed:**

- **EDR integrations:** extend beyond SentinelOne (already partly integrated) to support CrowdStrike, Defender for Endpoint via modular ingestion classes.
- **Threat intel feeds:** maintain mapping of malware names to process hashes, domains, network IoCs.
- **Runtime context:** join host events to cloud identity & asset metadata (instance IDs, runner labels).

**Producer roadmap:**

| Producer | Scope | Inputs | Logic |
| --- | --- | --- | --- |
| `SentinelOneMalwareProducer` | Endpoint devices | SentinelOne activity feed (`integrations/sentinelone.py`) | Emit when malware classification matches Graph Control entries and host is cloud workload or runner with sensitive access. |
| `RuntimeCnCProducer` | Cloud workloads | Host network telemetry + threat feed | Detect C2 communication attempts on sensitive workloads. |

**Implementation notes:**

- Extend `telemetry/services.process_runtime` to classify events using a threat intel cache.
- Producers should tag findings with malware family, detection source, and impacted resources for cross-referencing Graph Controls.

## 5. Cross-Cutting Platform Enhancements

1. **Unified Vulnerability Knowledge Base:** create `analysis/vuln_catalog.py` that ingests NVD, CISA KEV, vendor advisories, mapping them to software package fingerprints and Graph Control IDs. Producers reuse this to decide severity.
2. **Asset Graph Normalisation:** expand schema in `core/models` to cover new resource types (containers, pods, AI jobs, CI runners) so producers have consistent keys.
3. **Credential Validation Sandbox:** implement isolated workers (possibly AWS Lambda) for safely validating leaked API keys without risking misuse.
4. **Evidence Enrichment:** update `FindingEntity.evidence` conventions to include `graph_control_id`, `provider`, `data_sources` for traceability.
5. **Test Harnesses:** add unit fixtures under `tests_unit/findings/` for each new producer plus integration tests using mocked provider clients.

## 6. Implementation Roadmap

### Phase 0 – Foundation (Weeks 1-2)

- Stand up vulnerability catalog service and secret validation sandbox.
- Define new resource schemas and migrations for containers, runners, ML artifacts.
- Add Azure provider skeleton and extend GCP provider to cover firewall + IAM bindings.

### Phase 1 – Quick Wins (Weeks 3-6)

- Ship producers covering: AWS public VM CVEs (Inspector), S3 secrets exposure, GitHub runner exposure, Azure/M365 MFA gaps.
- Integrate SentinelOne malware producer leveraging existing ingestion.
- Add initial Kubernetes provider to at least detect public kubelet and privileged pods.

### Phase 2 – Advanced Cloud & AI Posture (Weeks 7-12)

- Implement AI/ML protection producers (Bedrock/Vertex).
- Expand container image CVE detections via registry scan ingestion.
- Roll out CI/CD OIDC misconfiguration checks across GitHub, GitLab, Terraform Cloud.

### Phase 3 – Behavioural & Lateral Movement Analytics (Weeks 13+)

- Build runtime correlation pipeline for lateral movement + credential misuse.
- Integrate additional IdP audit streams (Okta risk scores, Azure Identity Protection).
- Deliver cross-provider service account exposure producers with attack-path enrichment.

## 7. Summary of Required Systems & Data Sources

| System / API | Purpose | Graph Control themes served |
| --- | --- | --- |
| AWS APIs (EC2, ELB, IAM, Inspector, Access Analyzer, Bedrock, CodeBuild, S3) | Asset inventory, vulnerability & secret posture, CI/CD exposure, AI training protection | Public compute, secrets, AI/ML, CI/CD, service account |
| Azure Resource Manager & Microsoft Graph (Compute, NSG, Entra ID, Defender, Azure ML) | VM exposure, identity MFA, AI workspace posture | Public compute, identity, AI/ML |
| GCP (Compute Engine, SCC, IAM, Vertex AI, Artifact Registry) | Cloud exposure, CVEs, AI datasets | Public compute, AI/ML |
| Kubernetes API + managed control plane APIs (EKS/GKE/AKS) | Workload privilege analysis, ingress exposure | Container/Kubernetes |
| Container registries (ECR, GCR, ACR) & vulnerability scanners (Inspector, Trivy) | Image CVE detection | Container runtime |
| IdP audit logs (Okta, Azure AD, Cognito, Google Workspace) | MFA, suspicious logins, service account risk | Identity |
| CI/CD platforms (GitHub, GitLab, CircleCI, Env0, Spacelift, Terraform Cloud, CodeBuild) | Runner exposure, OIDC trust relationships | CI/CD |
| SentinelOne (existing), plus optional CrowdStrike/Defender EDR | Malware detection, runtime compromise | Malware/ransomware |
| Secret scanning services (TruffleHog, GitGuardian, Macie, DLP) | API key discovery & validation | Secrets |
| Threat intel feeds (CISA KEV, AbuseCH, VirusTotal) | Malware & CVE prioritisation | CVE/malware |

## 8. Next Steps

1. Confirm priority ordering with security operations stakeholders to ensure the roadmap aligns with audit/compliance deadlines.
2. Spin up cross-functional working groups for each theme (cloud, identity, CI/CD, AI/ML) to parallelise implementation.
3. Begin extending the codebase as outlined, ensuring new producers include unit tests, CEL rule mappings, and sample evidence payloads for validation.
