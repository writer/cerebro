package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/proto"
)

const (
	cloudEffectiveAdminPermissionRuleID = "cloud-effective-admin-permission"
	cloudPrivilegePathGrantedRuleID     = "cloud-privilege-path-granted"
	cloudPublicResourceExposureRuleID   = "cloud-public-resource-exposure"
)

type cloudSignalPredicate func(*cerebrov1.EventEnvelope, map[string]string) bool

type cloudSignalConfig struct {
	definition RuleDefinition
	sourceIDs  []string
	eventKinds []string
	predicate  cloudSignalPredicate
}

type cloudSignalRule struct {
	config cloudSignalConfig
}

func newCloudSignalRule(config cloudSignalConfig) Rule {
	if len(config.eventKinds) != 0 {
		config.definition.EventKinds = append([]string(nil), config.eventKinds...)
	}
	return &cloudSignalRule{config: config}
}

func newCloudSignalRules() []Rule {
	capabilities := builtinCloudCapabilities
	sourceIDs := capabilities.SourceIDs()
	return []Rule{
		newCloudSignalRule(cloudSignalConfig{
			definition: cloudRuleDefinition(
				cloudEffectiveAdminPermissionRuleID,
				"Cloud Effective Admin Permission",
				"Detect effective cloud permissions that grant admin-equivalent actions.",
				"HIGH",
				"finding.cloud_effective_admin_permission",
				[]string{"cloud", "ciem", "least-privilege", "attack.t1098"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(cloudCapabilityEffectivePermission),
			predicate:  matchesCloudEffectiveAdminPermission,
		}),
		newCloudSignalRule(cloudSignalConfig{
			definition: cloudRuleDefinition(
				cloudPublicResourceExposureRuleID,
				"Cloud Public Resource Exposure",
				"Detect cloud resources with public internet exposure.",
				"HIGH",
				"finding.cloud_public_resource_exposure",
				[]string{"cloud", "exposure", "public", "attack.t1190"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(cloudCapabilityResourceExposure),
			predicate:  matchesCloudPublicExposure,
		}),
		newCloudSignalRule(cloudSignalConfig{
			definition: cloudRuleDefinition(
				cloudPrivilegePathGrantedRuleID,
				"Cloud Privilege Path Granted",
				"Detect cloud trust, impersonation, and application role paths that expand access.",
				"HIGH",
				"finding.cloud_privilege_path_granted",
				[]string{"cloud", "privilege-escalation", "identity", "attack.t1098"},
			),
			sourceIDs:  sourceIDs,
			eventKinds: capabilities.EventKinds(cloudCapabilityPrivilegePath),
			predicate:  matchesCloudPrivilegePath,
		}),
	}
}

func cloudRuleDefinition(id string, name string, description string, severity string, outputKind string, tags []string) RuleDefinition {
	return RuleDefinition{
		ID:                 id,
		Name:               name,
		Description:        description,
		SourceID:           "cloud",
		OutputKind:         outputKind,
		Severity:           severity,
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               tags,
		FalsePositives:     []string{"Approved exposure or trust path during a documented change window."},
		Runbook:            "Review the exposed resource or trust path, linked principals, scope, and adjacent identity findings.",
		RequiredAttributes: []string{"family"},
		FingerprintFields:  []string{"event_id"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"},
		},
	}
}

func (r *cloudSignalRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.config.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *cloudSignalRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	sourceID := strings.TrimSpace(runtime.GetSourceId())
	for _, candidate := range r.config.sourceIDs {
		if strings.EqualFold(sourceID, candidate) {
			return true
		}
	}
	return false
}

func (r *cloudSignalRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || event == nil {
		return nil, nil
	}
	if !r.SupportsRuntime(runtime) || !identityKindAllowed(event.GetKind(), r.config.eventKinds) {
		return nil, nil
	}
	attributes := eventAttributes(event)
	if r.config.predicate == nil || !r.config.predicate(event, attributes) {
		return nil, nil
	}
	record, err := r.buildFinding(ctx, runtime, event)
	if err != nil {
		return nil, err
	}
	return []*ports.FindingRecord{record}, nil
}

func (r *cloudSignalRule) buildFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	eventAttrs := eventAttributes(event)
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"can_reach", "can_assume", "can_impersonate", "can_perform", "assigned_to", "can_admin"},
		CollectAllLinkURNs: true,
		ActorFallbacks:     []string{eventAttrs["subject_email"], eventAttrs["subject_name"], eventAttrs["principal_id"], eventAttrs["actor_email"]},
		ResourceFallbacks:  []string{eventAttrs["resource_name"], eventAttrs["resource_id"], eventAttrs["target_name"], eventAttrs["target_id"]},
		SkipFallbackEntity: func(entity *ports.ProjectedEntity) bool {
			if entity == nil {
				return true
			}
			return strings.HasPrefix(entity.EntityType, "identifier.") || strings.HasSuffix(entity.EntityType, ".org")
		},
	})
	if err != nil {
		return nil, err
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	attributes := cloudFindingAttributes(event, runtime, r.config, projectedContext)
	fingerprint := hashFindingFingerprint(r.config.definition.ID, event.GetId(), projectedContext.PrimaryResourceURN, compoundRiskAction(&ports.FindingRecord{Attributes: attributes}))
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(event.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            r.config.definition.ID,
		Title:             r.config.definition.Name,
		Severity:          r.config.definition.Severity,
		Status:            r.config.definition.Status,
		Summary:           cloudFindingSummary(attributes, projectedContext),
		ResourceURNs:      projectedContext.ResourceURNs,
		EventIDs:          []string{strings.TrimSpace(event.GetId())},
		ObservedPolicyIDs: githubObservedPolicyIDs(firstNonEmpty(attributes["policy_id"], attributes["resource_id"], attributes["target_id"])),
		PolicyID:          firstNonEmpty(attributes["policy_id"], attributes["resource_id"], attributes["target_id"]),
		PolicyName:        firstNonEmpty(attributes["resource_label"], attributes["resource_name"], attributes["target_name"], attributes["resource_id"]),
		CheckID:           r.config.definition.ID,
		CheckName:         r.config.definition.Name,
		ControlRefs:       cloneFindingControlRefs(r.config.definition.ControlRefs),
		Attributes:        attributes,
		FirstObservedAt:   observedAt,
		LastObservedAt:    observedAt,
	}, nil
}

func cloudFindingAttributes(event *cerebrov1.EventEnvelope, runtime *cerebrov1.SourceRuntime, config cloudSignalConfig, context findingProjectionContext) map[string]string {
	eventAttrs := eventAttributes(event)
	attributes := map[string]string{
		"action":               firstNonEmpty(eventAttrs["relationship"], eventAttrs["exposure_type"], eventAttrs["event_type"], eventAttrs["family"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"family":               strings.TrimSpace(eventAttrs["family"]),
		"primary_actor_urn":    context.PrimaryActorURN,
		"primary_resource_urn": context.PrimaryResourceURN,
		"resource_id":          firstNonEmpty(eventAttrs["resource_id"], eventAttrs["target_id"], eventAttrs["role_id"]),
		"resource_label":       context.ResourceLabel,
		"resource_type":        firstNonEmpty(eventAttrs["resource_type"], eventAttrs["target_type"], eventAttrs["family"]),
		"source_family":        strings.TrimSpace(event.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	for key, value := range eventAttrs {
		if _, exists := attributes[key]; !exists {
			attributes[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range config.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func cloudFindingSummary(attributes map[string]string, context findingProjectionContext) string {
	resource := firstNonEmpty(context.ResourceLabel, attributes["resource_name"], attributes["target_name"], attributes["resource_id"], "cloud resource")
	action := firstNonEmpty(attributes["action"], attributes["family"], "cloud signal")
	return fmt.Sprintf("%s has %s", resource, action)
}

func matchesCloudPublicExposure(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	return findingAttributeBool(attributes, "internet_exposed", "external_exposure", "public") || strings.Contains(identityAction(attributes), "public_network_ingress")
}

func matchesCloudPrivilegePath(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	return strings.TrimSpace(attributes["path_type"]) != "" || strings.TrimSpace(attributes["relationship"]) != "" || strings.TrimSpace(attributes["target_id"]) != ""
}

func matchesCloudEffectiveAdminPermission(_ *cerebrov1.EventEnvelope, attributes map[string]string) bool {
	if !strings.EqualFold(firstNonEmpty(attributes["effect"], "allow"), "allow") {
		return false
	}
	if findingAttributeBool(attributes, "is_admin", "privileged", "admin") {
		return true
	}
	value := strings.ToLower(firstNonEmpty(attributes["permission"], attributes["actions"], attributes["role_name"], attributes["role_id"], attributes["privilege_level"]))
	return containsAny(value,
		"*",
		"administratoraccess",
		"owner",
		"contributor",
		"iam.serviceaccounts.actas",
		"iam.serviceaccounts.getaccesstoken",
		"iam.serviceaccounttokencreator",
		"microsoft.authorization/roleassignments/write",
		"secretsmanager",
		"keyvault",
		"kms",
	)
}
