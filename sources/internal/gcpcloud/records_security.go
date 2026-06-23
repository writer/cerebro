package gcpcloud

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
)

type BinaryAuthorizationPolicyRecord struct {
	Name                                   string                                      `json:"name"`
	Description                            string                                      `json:"description"`
	GlobalPolicyEvaluationMode             string                                      `json:"globalPolicyEvaluationMode"`
	AdmissionWhitelistPatterns             []BinaryAuthorizationWhitelistPattern       `json:"admissionWhitelistPatterns"`
	ClusterAdmissionRules                  map[string]BinaryAuthorizationAdmissionRule `json:"clusterAdmissionRules"`
	KubernetesNamespaceAdmissionRules      map[string]BinaryAuthorizationAdmissionRule `json:"kubernetesNamespaceAdmissionRules"`
	KubernetesServiceAccountAdmissionRules map[string]BinaryAuthorizationAdmissionRule `json:"kubernetesServiceAccountAdmissionRules"`
	IstioServiceIdentityAdmissionRules     map[string]BinaryAuthorizationAdmissionRule `json:"istioServiceIdentityAdmissionRules"`
	DefaultAdmissionRule                   BinaryAuthorizationAdmissionRule            `json:"defaultAdmissionRule"`
	UpdateTime                             string                                      `json:"updateTime"`
	Etag                                   string                                      `json:"etag"`
	Raw                                    json.RawMessage                             `json:"-"`
}

type BinaryAuthorizationAdmissionRule struct {
	EvaluationMode        string   `json:"evaluationMode"`
	EnforcementMode       string   `json:"enforcementMode"`
	RequireAttestationsBy []string `json:"requireAttestationsBy"`
}

type BinaryAuthorizationWhitelistPattern struct {
	NamePattern string `json:"namePattern"`
}

type BinaryAuthorizationAttestorRecord struct {
	Name                 string                                  `json:"name"`
	Description          string                                  `json:"description"`
	UpdateTime           string                                  `json:"updateTime"`
	Etag                 string                                  `json:"etag"`
	UserOwnedGrafeasNote BinaryAuthorizationUserOwnedGrafeasNote `json:"userOwnedGrafeasNote"`
	Raw                  json.RawMessage                         `json:"-"`
}

type BinaryAuthorizationUserOwnedGrafeasNote struct {
	NoteReference                 string                                 `json:"noteReference"`
	PublicKeys                    []BinaryAuthorizationAttestorPublicKey `json:"publicKeys"`
	DelegationServiceAccountEmail string                                 `json:"delegationServiceAccountEmail"`
}

type BinaryAuthorizationAttestorPublicKey struct {
	Comment                  string                           `json:"comment"`
	ID                       string                           `json:"id"`
	AsciiArmoredPGPPublicKey string                           `json:"asciiArmoredPgpPublicKey"`
	PKIXPublicKey            BinaryAuthorizationPKIXPublicKey `json:"pkixPublicKey"`
}

type BinaryAuthorizationPKIXPublicKey struct {
	PublicKeyPEM       string `json:"publicKeyPem"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

type CloudIDSEndpointRecord struct {
	Name                   string              `json:"name"`
	CreateTime             string              `json:"createTime"`
	UpdateTime             string              `json:"updateTime"`
	Labels                 map[string]string   `json:"labels"`
	Network                string              `json:"network"`
	EndpointForwardingRule string              `json:"endpointForwardingRule"`
	EndpointIP             string              `json:"endpointIp"`
	Description            string              `json:"description"`
	Severity               string              `json:"severity"`
	ThreatExceptions       []string            `json:"threatExceptions"`
	State                  string              `json:"state"`
	TrafficLogs            bool                `json:"trafficLogs"`
	LoggingSinks           []LoggingSinkRecord `json:"-"`
	Raw                    json.RawMessage     `json:"-"`
}

type ContainerVulnerabilityRecord struct {
	Name          string                           `json:"name"`
	ResourceURI   string                           `json:"resourceUri"`
	NoteName      string                           `json:"noteName"`
	Kind          string                           `json:"kind"`
	Remediation   string                           `json:"remediation"`
	CreateTime    string                           `json:"createTime"`
	UpdateTime    string                           `json:"updateTime"`
	Vulnerability ContainerVulnerabilityOccurrence `json:"vulnerability"`
	Raw           json.RawMessage                  `json:"-"`
}

type ContainerVulnerabilityOccurrence struct {
	Type              string                               `json:"type"`
	Severity          string                               `json:"severity"`
	EffectiveSeverity string                               `json:"effectiveSeverity"`
	CVSSScore         float64                              `json:"cvssScore"`
	CVSSVersion       string                               `json:"cvssVersion"`
	ShortDescription  string                               `json:"shortDescription"`
	LongDescription   string                               `json:"longDescription"`
	PackageIssue      []ContainerVulnerabilityPackageIssue `json:"packageIssue"`
	RelatedURLs       []ContainerVulnerabilityRelatedURL   `json:"relatedUrls"`
}

type ContainerVulnerabilityPackageIssue struct {
	AffectedCPEURI    string                               `json:"affectedCpeUri"`
	AffectedPackage   string                               `json:"affectedPackage"`
	AffectedVersion   ContainerVulnerabilityVersion        `json:"affectedVersion"`
	FixedCPEURI       string                               `json:"fixedCpeUri"`
	FixedPackage      string                               `json:"fixedPackage"`
	FixedVersion      ContainerVulnerabilityVersion        `json:"fixedVersion"`
	FixAvailable      bool                                 `json:"fixAvailable"`
	PackageType       string                               `json:"packageType"`
	EffectiveSeverity string                               `json:"effectiveSeverity"`
	FileLocation      []ContainerVulnerabilityFileLocation `json:"fileLocation"`
}

type ContainerVulnerabilityVersion struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
	Kind     string `json:"kind"`
	FullName string `json:"fullName"`
}

type ContainerVulnerabilityFileLocation struct {
	FilePath string `json:"filePath"`
}

type ContainerVulnerabilityRelatedURL struct {
	URL   string `json:"url"`
	Label string `json:"label"`
}

type OrgPolicyRecord struct {
	Name       string          `json:"name"`
	Spec       OrgPolicySpec   `json:"spec"`
	DryRunSpec OrgPolicySpec   `json:"dryRunSpec"`
	Etag       string          `json:"etag"`
	Raw        json.RawMessage `json:"-"`
}

type OrgPolicySpec struct {
	Rules             []OrgPolicyRule `json:"rules"`
	InheritFromParent bool            `json:"inheritFromParent"`
	Reset             bool            `json:"reset"`
	Etag              string          `json:"etag"`
	UpdateTime        string          `json:"updateTime"`
}

type OrgPolicyRule struct {
	Values    OrgPolicyValues `json:"values"`
	AllowAll  bool            `json:"allowAll"`
	DenyAll   bool            `json:"denyAll"`
	Enforce   *bool           `json:"enforce"`
	Condition json.RawMessage `json:"condition"`
}

type OrgPolicyValues struct {
	AllowedValues []string `json:"allowedValues"`
	DeniedValues  []string `json:"deniedValues"`
}

type SecurityCenterFindingRecord struct {
	Finding  SecurityCenterFinding  `json:"finding"`
	Resource SecurityCenterResource `json:"resource"`
	Raw      json.RawMessage        `json:"-"`
}

type SecurityCenterFinding struct {
	Name             string                     `json:"name"`
	Parent           string                     `json:"parent"`
	ResourceName     string                     `json:"resourceName"`
	State            string                     `json:"state"`
	Category         string                     `json:"category"`
	ExternalURI      string                     `json:"externalUri"`
	Severity         string                     `json:"severity"`
	Mute             string                     `json:"mute"`
	FindingClass     string                     `json:"findingClass"`
	Description      string                     `json:"description"`
	NextSteps        string                     `json:"nextSteps"`
	EventTime        string                     `json:"eventTime"`
	CreateTime       string                     `json:"createTime"`
	CanonicalName    string                     `json:"canonicalName"`
	CloudDlpData     json.RawMessage            `json:"cloudDlpData"`
	SourceProperties map[string]json.RawMessage `json:"sourceProperties"`
	SecurityMarks    json.RawMessage            `json:"securityMarks"`
	Vulnerability    json.RawMessage            `json:"vulnerability"`
	MITREAttack      json.RawMessage            `json:"mitreAttack"`
}

type SecurityCenterResource struct {
	Name               string `json:"name"`
	DisplayName        string `json:"displayName"`
	Type               string `json:"type"`
	Service            string `json:"service"`
	Location           string `json:"location"`
	CloudProvider      string `json:"cloudProvider"`
	ProjectName        string `json:"projectName"`
	ProjectDisplayName string `json:"projectDisplayName"`
	Parent             string `json:"parent"`
	ParentDisplayName  string `json:"parentDisplayName"`
	Folders            []struct {
		ResourceFolder     string `json:"resourceFolder"`
		ResourceFolderName string `json:"resourceFolderDisplayName"`
	} `json:"folders"`
}

func CloudIDSEndpointEvent(settings Settings, record CloudIDSEndpointRecord) (*primitives.Event, error) {
	location := firstNonEmpty(locationFromResourceName(record.Name), settings.Location)
	resourceID := firstNonEmpty(record.Name, record.EndpointForwardingRule)
	resourceName := lastPathSegment(resourceID)
	endpointIP := record.EndpointIP
	logs := cloudIDSLogSinkSummary(record.LoggingSinks)
	attributes := cloudResourceAttributes(settings, "cloud_ids_endpoint", resourceID, resourceName, "cloud_ids_endpoint", location, record.Labels)
	attributes["description"] = record.Description
	attributes["zone"] = location
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["endpoint_forwarding_rule"] = lastPathSegment(record.EndpointForwardingRule)
	attributes["endpoint_forwarding_rule_url"] = record.EndpointForwardingRule
	attributes["endpoint_forwarding_rule_address"] = endpointIP
	attributes["endpoint_ip"] = endpointIP
	attributes["private_ip"] = endpointIP
	attributes["severity"] = record.Severity
	attributes["minimum_alert_severity"] = record.Severity
	attributes["state"] = record.State
	attributes["traffic_logs"] = boolString(record.TrafficLogs)
	attributes["threat_exceptions"] = strings.Join(record.ThreatExceptions, ",")
	attributes["threat_exceptions_count"] = strconv.Itoa(len(record.ThreatExceptions))
	attributes["threat_log_name"] = cloudIDSLogName(settings.ProjectID, "threat")
	attributes["traffic_log_name"] = cloudIDSLogName(settings.ProjectID, "traffic")
	attributes["threat_log_routed"] = boolString(logs.Threat)
	attributes["traffic_log_routed"] = boolString(logs.Traffic)
	attributes["log_sinks_count"] = strconv.Itoa(len(record.LoggingSinks))
	attributes["log_sink_names"] = strings.Join(logs.Names, ",")
	attributes["log_sink_destinations"] = strings.Join(logs.Destinations, ",")
	attributes["log_sink_destination_types"] = strings.Join(logs.DestinationTypes, ",")
	attributes["notification_configured"] = boolString(len(logs.NotificationDestinations) != 0)
	attributes["notification_destinations"] = strings.Join(logs.NotificationDestinations, ",")
	attributes["private_endpoint"] = boolString(endpointIP != "")
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"logging_sinks": record.LoggingSinks, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-ids-endpoint-"+resourceID, "gcp.cloud_ids_endpoint", "gcp/cloud_ids_endpoint/v1", payload, attributes)
}

func ContainerVulnerabilityEvent(settings Settings, record ContainerVulnerabilityRecord) (*primitives.Event, error) {
	issue := firstContainerPackageIssue(record.Vulnerability.PackageIssue)
	vulnerabilityID := vulnerabilityIDFromNote(record.NoteName)
	imageURI := record.ResourceURI
	fixedVersion := versionName(issue.FixedVersion)
	affectedVersion := versionName(issue.AffectedVersion)
	attributes := map[string]string{
		"cve_id":                 cveID(vulnerabilityID),
		"description":            firstNonEmpty(record.Vulnerability.ShortDescription, record.Vulnerability.LongDescription),
		"digest":                 artifactImageDigest(imageURI),
		"discovered_at":          record.CreateTime,
		"domain":                 settings.TenantID,
		"effective_severity":     firstNonEmpty(issue.EffectiveSeverity, record.Vulnerability.EffectiveSeverity),
		"family":                 "container_vulnerability",
		"fix_available":          boolString(issue.FixAvailable || fixedVersion != ""),
		"fixed_package":          issue.FixedPackage,
		"fixed_package_versions": fixedVersion,
		"fixed_version":          fixedVersion,
		"image_name":             containerImageName(imageURI),
		"image_registry":         containerImageRegistry(imageURI),
		"image_repository":       containerImageRepository(imageURI),
		"image_uri":              imageURI,
		"installed_version":      affectedVersion,
		"package":                issue.AffectedPackage,
		"package_name":           issue.AffectedPackage,
		"package_type":           issue.PackageType,
		"project_id":             settings.ProjectID,
		"registry":               containerImageRegistry(imageURI),
		"remediation":            record.Remediation,
		"repository":             containerImageRepository(imageURI),
		"resource_id":            imageURI,
		"resource_name":          containerImageName(imageURI),
		"resource_provider":      "gcp",
		"resource_type":          "container_image",
		"resource_uri":           imageURI,
		"scanner":                "artifact_analysis",
		"severity":               firstNonEmpty(issue.EffectiveSeverity, record.Vulnerability.EffectiveSeverity, record.Vulnerability.Severity),
		"source_provider":        "gcp",
		"status":                 "active",
		"updated_at":             record.UpdateTime,
		"version":                affectedVersion,
		"vulnerability_id":       vulnerabilityID,
		"vulnerability_source":   "gcp_artifact_analysis",
		"vulnerability_type":     "container",
	}
	if record.Vulnerability.CVSSScore != 0 {
		attributes["cvss_score"] = strconv.FormatFloat(record.Vulnerability.CVSSScore, 'f', -1, 64)
	}
	attributes["cvss_version"] = record.Vulnerability.CVSSVersion
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	idParts := []string{record.Name, imageURI, vulnerabilityID, issue.AffectedPackage, affectedVersion}
	return sourceEvent(settings, "gcp-container-vulnerability-"+strings.Join(idParts, "-"), "gcp.container_vulnerability", "gcp/container_vulnerability/v1", payload, attributes)
}

func OrgPolicyEvent(settings Settings, record OrgPolicyRecord) (*primitives.Event, error) {
	constraint := orgPolicyConstraint(record.Name)
	allowedValues, deniedValues := orgPolicyRuleValues(record.Spec.Rules)
	resourceID := firstNonEmpty(record.Name, settings.ProjectID+"/policies/"+constraint)
	attributes := cloudResourceAttributes(settings, "org_policy", resourceID, constraint, "org_policy", "global", nil)
	attributes["constraint"] = constraint
	attributes["etag"] = firstNonEmpty(record.Spec.Etag, record.Etag)
	attributes["inherit_from_parent"] = boolString(record.Spec.InheritFromParent)
	attributes["enforced"] = boolString(orgPolicyEnforced(record))
	attributes["policy_name"] = record.Name
	attributes["reset"] = boolString(record.Spec.Reset)
	attributes["rules_count"] = strconv.Itoa(len(record.Spec.Rules))
	attributes["allowed_values"] = strings.Join(allowedValues, ",")
	attributes["denied_values"] = strings.Join(deniedValues, ",")
	attributes["updated_at"] = record.Spec.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-org-policy-"+resourceID, "gcp.org_policy", "gcp/org_policy/v1", payload, attributes)
}

func BinaryAuthorizationPolicyEvent(settings Settings, record BinaryAuthorizationPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.Name, "projects/"+settings.ProjectID+"/policy")
	defaultRule := record.DefaultAdmissionRule
	clusterKeys, clusterRequired := binaryAuthorizationRuleSummary(record.ClusterAdmissionRules)
	namespaceKeys, namespaceRequired := binaryAuthorizationRuleSummary(record.KubernetesNamespaceAdmissionRules)
	serviceAccountKeys, serviceAccountRequired := binaryAuthorizationRuleSummary(record.KubernetesServiceAccountAdmissionRules)
	istioKeys, istioRequired := binaryAuthorizationRuleSummary(record.IstioServiceIdentityAdmissionRules)
	requiredAttestors := uniqueSortedStrings(append(append(append(append([]string{}, defaultRule.RequireAttestationsBy...), clusterRequired...), namespaceRequired...), append(serviceAccountRequired, istioRequired...)...))
	attributes := cloudResourceAttributes(settings, "binary_authorization_policy", resourceID, lastPathSegment(resourceID), "binary_authorization_policy", "global", nil)
	attributes["admission_whitelist_patterns"] = strings.Join(binaryAuthorizationWhitelistPatterns(record.AdmissionWhitelistPatterns), ",")
	attributes["admission_whitelist_patterns_count"] = strconv.Itoa(len(record.AdmissionWhitelistPatterns))
	attributes["cluster_admission_rule_keys"] = strings.Join(clusterKeys, ",")
	attributes["cluster_admission_rules_count"] = strconv.Itoa(len(record.ClusterAdmissionRules))
	attributes["default_enforcement_mode"] = defaultRule.EnforcementMode
	attributes["default_evaluation_mode"] = defaultRule.EvaluationMode
	attributes["description"] = record.Description
	attributes["etag"] = record.Etag
	attributes["global_policy_evaluation_mode"] = record.GlobalPolicyEvaluationMode
	attributes["istio_service_identity_admission_rule_keys"] = strings.Join(istioKeys, ",")
	attributes["istio_service_identity_admission_rules_count"] = strconv.Itoa(len(record.IstioServiceIdentityAdmissionRules))
	attributes["kubernetes_namespace_admission_rule_keys"] = strings.Join(namespaceKeys, ",")
	attributes["kubernetes_namespace_admission_rules_count"] = strconv.Itoa(len(record.KubernetesNamespaceAdmissionRules))
	attributes["kubernetes_service_account_admission_rule_keys"] = strings.Join(serviceAccountKeys, ",")
	attributes["kubernetes_service_account_admission_rules_count"] = strconv.Itoa(len(record.KubernetesServiceAccountAdmissionRules))
	attributes["require_attestations_by"] = strings.Join(requiredAttestors, ",")
	attributes["require_attestations_by_count"] = strconv.Itoa(len(requiredAttestors))
	attributes["requires_attestation"] = boolString(strings.EqualFold(defaultRule.EvaluationMode, "REQUIRE_ATTESTATION") || len(requiredAttestors) != 0)
	attributes["status"] = firstNonEmpty(defaultRule.EnforcementMode, record.GlobalPolicyEvaluationMode)
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-binary-authorization-policy-"+resourceID, "gcp.binary_authorization_policy", "gcp/binary_authorization_policy/v1", payload, attributes)
}

func BinaryAuthorizationAttestorEvent(settings Settings, record BinaryAuthorizationAttestorRecord) (*primitives.Event, error) {
	note := record.UserOwnedGrafeasNote
	pgpCount, pkixCount := binaryAuthorizationPublicKeyCounts(note.PublicKeys)
	keyIDs := binaryAuthorizationPublicKeyIDs(note.PublicKeys)
	resourceID := firstNonEmpty(record.Name, "projects/"+settings.ProjectID+"/attestors/"+record.Description)
	attributes := cloudResourceAttributes(settings, "binary_authorization_attestor", resourceID, firstNonEmpty(record.Description, lastPathSegment(resourceID)), "binary_authorization_attestor", "global", nil)
	attributes["attestor_id"] = lastPathSegment(resourceID)
	attributes["delegation_service_account_email"] = note.DelegationServiceAccountEmail
	attributes["description"] = record.Description
	attributes["etag"] = record.Etag
	attributes["note_reference"] = note.NoteReference
	attributes["public_key_ids"] = strings.Join(keyIDs, ",")
	attributes["public_keys_count"] = strconv.Itoa(len(note.PublicKeys))
	attributes["pgp_public_keys_count"] = strconv.Itoa(pgpCount)
	attributes["pkix_public_keys_count"] = strconv.Itoa(pkixCount)
	attributes["status"] = "NO_KEYS"
	if len(note.PublicKeys) != 0 {
		attributes["status"] = "ACTIVE"
	}
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-binary-authorization-attestor-"+resourceID, "gcp.binary_authorization_attestor", "gcp/binary_authorization_attestor/v1", payload, attributes)
}

func SecurityCenterFindingEvent(settings Settings, record SecurityCenterFindingRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.Finding.Name, record.Finding.CanonicalName, record.Finding.ResourceName, record.Resource.Name)
	affectedResourceID := firstNonEmpty(record.Finding.ResourceName, record.Resource.Name)
	location := firstNonEmpty(record.Resource.Location, locationFromResourceName(affectedResourceID), "global")
	attributes := cloudResourceAttributes(settings, "security_center_finding", resourceID, firstNonEmpty(record.Finding.Category, lastPathSegment(resourceID)), "security_center_finding", location, nil)
	attributes["affected_resource_id"] = affectedResourceID
	attributes["affected_resource_name"] = firstNonEmpty(record.Resource.DisplayName, lastPathSegment(affectedResourceID))
	attributes["affected_resource_type"] = record.Resource.Type
	attributes["category"] = record.Finding.Category
	attributes["cloud_provider"] = record.Resource.CloudProvider
	attributes["created_at"] = record.Finding.CreateTime
	attributes["description"] = record.Finding.Description
	attributes["event_time"] = record.Finding.EventTime
	attributes["external_uri"] = record.Finding.ExternalURI
	attributes["finding_class"] = record.Finding.FindingClass
	attributes["finding_name"] = record.Finding.Name
	attributes["mute"] = record.Finding.Mute
	attributes["muted"] = boolString(strings.EqualFold(record.Finding.Mute, "MUTED"))
	attributes["next_steps"] = record.Finding.NextSteps
	attributes["parent"] = record.Finding.Parent
	attributes["project_name"] = record.Resource.ProjectName
	attributes["resource_service"] = record.Resource.Service
	attributes["severity"] = record.Finding.Severity
	attributes["source_provider"] = "gcp_security_command_center"
	attributes["state"] = record.Finding.State
	attributes["status"] = record.Finding.State
	attributes["source_properties_count"] = strconv.Itoa(len(record.Finding.SourceProperties))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEventAt(settings, "gcp-security-center-finding-"+resourceID, "gcp.security_center_finding", "gcp/security_center_finding/v1", payload, attributes, securityCenterFindingOccurredAt(record))
}

func securityCenterFindingOccurredAt(record SecurityCenterFindingRecord) time.Time {
	for _, value := range []string{record.Finding.EventTime, record.Finding.CreateTime} {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value)); err == nil {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}

type cloudIDSLoggingSummary struct {
	Names                    []string
	Destinations             []string
	DestinationTypes         []string
	NotificationDestinations []string
	Threat                   bool
	Traffic                  bool
}

func AttachCloudIDSLoggingSinks(records []CloudIDSEndpointRecord, sinks []LoggingSinkRecord) {
	for index := range records {
		records[index].LoggingSinks = cloudIDSLoggingSinks(records[index], sinks)
	}
}

func cloudIDSLoggingSinks(record CloudIDSEndpointRecord, sinks []LoggingSinkRecord) []LoggingSinkRecord {
	matched := make([]LoggingSinkRecord, 0)
	endpointName := strings.ToLower(lastPathSegment(record.Name))
	for _, sink := range sinks {
		if sink.Disabled || !cloudIDSFilterMatches(sink.Filter, endpointName) {
			continue
		}
		matched = append(matched, sink)
	}
	return matched
}

func cloudIDSLogSinkSummary(sinks []LoggingSinkRecord) cloudIDSLoggingSummary {
	summary := cloudIDSLoggingSummary{}
	for _, sink := range sinks {
		destinationType := loggingSinkDestinationType(sink.Destination)
		summary.Names = appendUnique(summary.Names, sink.Name)
		summary.Destinations = appendUnique(summary.Destinations, sink.Destination)
		summary.DestinationTypes = appendUnique(summary.DestinationTypes, destinationType)
		if destinationType == "pubsub" {
			summary.NotificationDestinations = appendUnique(summary.NotificationDestinations, sink.Destination)
		}
		filter := strings.ToLower(strings.TrimSpace(sink.Filter))
		if filter == "" {
			summary.Threat = true
			summary.Traffic = true
			continue
		}
		genericIDS := strings.Contains(filter, "ids.googleapis.com/endpoint") || strings.Contains(filter, "ids_googleapis_com_endpoint")
		summary.Threat = summary.Threat || genericIDS || strings.Contains(filter, "ids.googleapis.com%2fthreat") || strings.Contains(filter, "ids.googleapis.com/threat")
		summary.Traffic = summary.Traffic || genericIDS || strings.Contains(filter, "ids.googleapis.com%2ftraffic") || strings.Contains(filter, "ids.googleapis.com/traffic")
	}
	return summary
}

func cloudIDSFilterMatches(filter string, endpointName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(filter))
	if normalized == "" {
		return true
	}
	if endpointName != "" && strings.Contains(normalized, "resource.labels.id") && !cloudIDSResourceIDFilterMatches(normalized, endpointName) {
		return false
	}
	return strings.Contains(normalized, "ids.googleapis.com%2f") ||
		strings.Contains(normalized, "ids.googleapis.com/") ||
		strings.Contains(normalized, "ids.googleapis.com/endpoint") ||
		strings.Contains(normalized, "ids_googleapis_com_endpoint")
}

func cloudIDSResourceIDFilterMatches(normalized string, endpointName string) bool {
	matches := cloudIDSResourceLabelIDFilterRE.FindAllStringSubmatch(normalized, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if len(match) > 1 && strings.Trim(match[1], `"'`) == endpointName {
			return true
		}
	}
	return false
}

func cloudIDSLogName(projectID string, logID string) string {
	return "projects/" + projectID + "/logs/ids.googleapis.com%2F" + logID
}

func orgPolicyConstraints(policies []OrgPolicyRecord) []string {
	constraints := make([]string, 0, len(policies))
	for _, policy := range policies {
		constraints = appendUnique(constraints, orgPolicyConstraint(policy.Name))
	}
	return constraints
}

func orgPolicyRuleValues(rules []OrgPolicyRule) ([]string, []string) {
	allowed := []string{}
	denied := []string{}
	for _, rule := range rules {
		for _, value := range rule.Values.AllowedValues {
			allowed = appendUnique(allowed, value)
		}
		for _, value := range rule.Values.DeniedValues {
			denied = appendUnique(denied, value)
		}
	}
	return allowed, denied
}

func binaryAuthorizationRuleSummary(rules map[string]BinaryAuthorizationAdmissionRule) ([]string, []string) {
	keys := make([]string, 0, len(rules))
	required := []string{}
	for key, rule := range rules {
		keys = append(keys, key)
		for _, attestor := range rule.RequireAttestationsBy {
			required = appendUnique(required, attestor)
		}
	}
	sort.Strings(keys)
	sort.Strings(required)
	return keys, required
}

func binaryAuthorizationWhitelistPatterns(patterns []BinaryAuthorizationWhitelistPattern) []string {
	names := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		names = appendUnique(names, pattern.NamePattern)
	}
	sort.Strings(names)
	return names
}

func binaryAuthorizationPublicKeyCounts(keys []BinaryAuthorizationAttestorPublicKey) (int, int) {
	pgpCount := 0
	pkixCount := 0
	for _, key := range keys {
		if key.AsciiArmoredPGPPublicKey != "" {
			pgpCount++
		}
		if key.PKIXPublicKey.PublicKeyPEM != "" || key.PKIXPublicKey.SignatureAlgorithm != "" {
			pkixCount++
		}
	}
	return pgpCount, pkixCount
}

func binaryAuthorizationPublicKeyIDs(keys []BinaryAuthorizationAttestorPublicKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = appendUnique(ids, key.ID)
	}
	sort.Strings(ids)
	return ids
}

func enforcedOrgPolicyConstraints(policies []OrgPolicyRecord) []string {
	constraints := make([]string, 0, len(policies))
	for _, policy := range policies {
		if orgPolicyEnforced(policy) {
			constraints = appendUnique(constraints, orgPolicyConstraint(policy.Name))
		}
	}
	return constraints
}

func orgPolicyConstraint(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for index, part := range parts {
		if part == "policies" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return lastPathSegment(name)
}

func orgPolicyEnforced(policy OrgPolicyRecord) bool {
	for _, rule := range policy.Spec.Rules {
		if rule.Enforce != nil && *rule.Enforce {
			return true
		}
		if rule.DenyAll || len(rule.Values.DeniedValues) != 0 {
			return true
		}
	}
	return false
}

func firstContainerPackageIssue(issues []ContainerVulnerabilityPackageIssue) ContainerVulnerabilityPackageIssue {
	if len(issues) == 0 {
		return ContainerVulnerabilityPackageIssue{}
	}
	return issues[0]
}

func vulnerabilityIDFromNote(noteName string) string {
	value := lastPathSegment(noteName)
	if value == "" {
		return strings.TrimSpace(noteName)
	}
	return value
}

func versionName(version ContainerVulnerabilityVersion) string {
	return firstNonEmpty(version.FullName, version.Name, version.Revision)
}

func cveID(value string) string {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if strings.HasPrefix(upper, "CVE-") {
		return upper
	}
	return ""
}

func containerImageRegistry(imageURI string) string {
	parts := strings.Split(strings.TrimSpace(imageURI), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func containerImageRepository(imageURI string) string {
	withoutDigest := imageWithoutDigest(imageURI)
	parts := strings.Split(strings.Trim(withoutDigest, "/"), "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".pkg.dev") {
		return strings.Join(parts[1:3], "/")
	}
	if len(parts) >= 2 {
		return strings.Join(parts[1:len(parts)-1], "/")
	}
	return ""
}

func containerImageName(imageURI string) string {
	return lastPathSegment(imageWithoutDigest(imageURI))
}

func imageWithoutDigest(imageURI string) string {
	if index := strings.LastIndex(imageURI, "@"); index >= 0 {
		return imageURI[:index]
	}
	return imageURI
}
