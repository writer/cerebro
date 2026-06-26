package graphquery

import (
	"sort"
	"strings"
)

const (
	InventorySurfaceAsset     = "asset"
	InventorySurfaceComponent = "component"
	InventorySurfaceSignal    = "signal"
	InventorySurfaceAlias     = "alias"
	InventorySurfaceRawRecord = "raw_record"
	InventorySurfaceAll       = "all"
)

type inventorySurfaceFilter struct {
	Surface  string
	Exact    []string
	Prefixes []string
	Suffixes []string
}

func NormalizeInventorySurface(surface string) string {
	switch strings.ToLower(strings.TrimSpace(surface)) {
	case "":
		return InventorySurfaceAll
	case InventorySurfaceAsset:
		return InventorySurfaceAsset
	case InventorySurfaceComponent:
		return InventorySurfaceComponent
	case InventorySurfaceSignal:
		return InventorySurfaceSignal
	case InventorySurfaceAlias:
		return InventorySurfaceAlias
	case InventorySurfaceRawRecord, "raw":
		return InventorySurfaceRawRecord
	case InventorySurfaceAll:
		return InventorySurfaceAll
	default:
		return InventorySurfaceAsset
	}
}

func InventorySurfaceForEntityType(entityType string) string {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	switch {
	case entityType == "":
		return InventorySurfaceAsset
	case inventorySurfaceMatches(entityType, inventorySurfaceRules(InventorySurfaceAlias)):
		return InventorySurfaceAlias
	case inventorySurfaceMatches(entityType, inventorySurfaceRules(InventorySurfaceRawRecord)):
		return InventorySurfaceRawRecord
	case inventorySurfaceMatches(entityType, inventorySurfaceRules(InventorySurfaceComponent)):
		return InventorySurfaceComponent
	case inventorySurfaceMatches(entityType, inventorySurfaceRules(InventorySurfaceSignal)):
		return InventorySurfaceSignal
	default:
		return InventorySurfaceAsset
	}
}

func inventorySurfaceRules(surface string) inventorySurfaceFilter {
	switch NormalizeInventorySurface(surface) {
	case InventorySurfaceAlias:
		return inventorySurfaceFilter{
			Surface:  InventorySurfaceAlias,
			Exact:    []string{"endpoint.identifier", "external.ref", "external_ref", "vendor.alias"},
			Prefixes: []string{"identifier.", "identity."},
		}
	case InventorySurfaceRawRecord:
		return inventorySurfaceFilter{
			Surface: InventorySurfaceRawRecord,
			Exact: []string{
				"aws.resource",
				"azure.resource",
				"gcp.audited.resource",
				"gcp.resource",
				"github.resource",
				"okta.resource",
			},
		}
	case InventorySurfaceComponent:
		return inventorySurfaceFilter{
			Surface: InventorySurfaceComponent,
			Exact: []string{
				"asset.tag",
				"aws.aws::dynamodb::table",
				"aws.aws::ec2::networkinterface",
				"aws.aws::ec2::securitygroup",
				"aws.aws::ec2::subnet",
				"aws.aws::ec2::volume",
				"aws.aws::ec2::vpc",
				"aws.aws::ecs::task",
				"aws.aws::ecs::taskdefinition",
				"aws.aws::elasticloadbalancingv2::listener",
				"aws.aws::elasticloadbalancingv2::targetgroup",
				"aws.aws::events::rule",
				"aws.aws::kms::alias",
				"aws.aws::kms::key",
				"aws.aws::logs::loggroup",
				"aws.awsec2networkinterface",
				"aws.awsec2securitygroup",
				"aws.awsec2subnet",
				"aws.awsec2volume",
				"aws.awsec2vpc",
				"aws.awsecstask",
				"aws.awsecstaskdefinition",
				"aws.ecs.task",
				"aws.ecs.task_definition",
				"aws.ebs.snapshot",
				"aws.eks.nodegroup",
				"aws.eks.pod_identity_association",
				"container.image_digest",
				"data.classification",
				"evidence.cas.pointer",
				"gcp.artifact_registry_image",
				"gcp.artifactregistry.googleapis.com.dockerimage",
				"gcp.artifactregistry.googleapis.com.mavenartifact",
				"gcp.artifactregistry.googleapis.com.npmpackage",
				"gcp.artifactregistry.googleapis.com.pythonpackage",
				"github.dependency",
				"github.dependency_manifest",
				"github.org_installation",
				"kubernetes.config_map",
				"kubernetes.cron_job",
				"kubernetes.daemon_set",
				"kubernetes.deployment",
				"kubernetes.endpoint",
				"kubernetes.ingress",
				"kubernetes.job",
				"kubernetes.namespace",
				"kubernetes.persistent_volume",
				"kubernetes.persistent_volume_claim",
				"kubernetes.pod",
				"kubernetes.pod_disruption_budget",
				"kubernetes.replica_set",
				"kubernetes.secret",
				"kubernetes.stateful_set",
				"kubernetes.storage_class",
				"kubernetes.validating_webhook_configuration",
				"kubernetes.mutating_webhook_configuration",
				"okta.authenticator",
				"okta.network_zone",
				"okta.policy_rule",
				"security.category",
				"sentinelone.group",
				"sentinelone.installed_application",
				"sentinelone.site",
			},
			Prefixes: []string{
				"aws.awselasticloadbalancingv2",
				"aws.awskms",
				"aws.awslogs",
				"gcp.artifactregistry.googleapis.com.",
				"gcp.compute.googleapis.com.disk.",
				"gcp.container.googleapis.com.nodepool.",
			},
		}
	case InventorySurfaceSignal:
		return inventorySurfaceFilter{
			Surface: InventorySurfaceSignal,
			Exact: []string{
				"action",
				"audit.event",
				"audit.target",
				"archetype.finding",
				"aws.action",
				"aws.context",
				"aws.guardduty.detector",
				"aws.public_principal",
				"aws.securityhub.finding",
				"claim",
				"contact",
				"cosmo.alert",
				"decision",
				"github.credential",
				"github.dependabot_alert",
				"github.pull_request",
				"github.secret_scanning_alert",
				"github.security_advisory",
				"kolide.issue",
				"okta.threat_insight",
				"openai.project_spend_alert",
				"openai.spend_alert",
				"outcome",
				"panopticon.alert",
				"panopticon.asset",
				"panopticon.case",
				"panopticon.ioc",
				"runtime.evidence",
				"runtime_evidence",
				"sdk.integration_posture",
				"security.finding",
				"sentinelone.activity",
				"sentinelone.exclusion",
				"sentinelone.threat",
				"twilio.secret",
				"vulnview.dns_alert_type",
			},
			Prefixes: []string{
				"aurelius.",
				"cosmo.",
				"panopticon.",
				"sentinelone.threat.",
				"vulnview.",
			},
		}
	default:
		return inventorySurfaceFilter{Surface: InventorySurfaceAsset}
	}
}

func inventorySurfaceMatches(entityType string, filter inventorySurfaceFilter) bool {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	if entityType == "" {
		return false
	}
	for _, exact := range filter.Exact {
		if entityType == exact {
			return true
		}
	}
	for _, prefix := range filter.Prefixes {
		if strings.HasPrefix(entityType, prefix) {
			return true
		}
	}
	for _, suffix := range filter.Suffixes {
		if strings.HasSuffix(entityType, suffix) {
			return true
		}
	}
	return false
}

func inventorySurfaceNonAssetRules() inventorySurfaceFilter {
	combined := inventorySurfaceFilter{Surface: InventorySurfaceAsset}
	for _, surface := range []string{InventorySurfaceComponent, InventorySurfaceSignal, InventorySurfaceAlias, InventorySurfaceRawRecord} {
		rules := inventorySurfaceRules(surface)
		combined.Exact = append(combined.Exact, rules.Exact...)
		combined.Prefixes = append(combined.Prefixes, rules.Prefixes...)
		combined.Suffixes = append(combined.Suffixes, rules.Suffixes...)
	}
	combined.Exact = uniqueSortedInventoryStrings(combined.Exact)
	combined.Prefixes = uniqueSortedInventoryStrings(combined.Prefixes)
	combined.Suffixes = uniqueSortedInventoryStrings(combined.Suffixes)
	return combined
}

func inventorySurfaceParams(surface string) (string, map[string]any) {
	surface = NormalizeInventorySurface(surface)
	switch surface {
	case InventorySurfaceAll:
		return "", map[string]any{}
	case InventorySurfaceAsset:
		rules := inventorySurfaceNonAssetRules()
		return `
  AND NOT e.entity_type IN $surface_excluded_entity_types
  AND none(prefix IN $surface_excluded_prefixes WHERE e.entity_type STARTS WITH prefix)
  AND none(suffix IN $surface_excluded_suffixes WHERE e.entity_type ENDS WITH suffix)`, map[string]any{
				"surface_excluded_entity_types": rules.Exact,
				"surface_excluded_prefixes":     rules.Prefixes,
				"surface_excluded_suffixes":     rules.Suffixes,
			}
	default:
		rules := inventorySurfaceRules(surface)
		return `
  AND (e.entity_type IN $surface_included_entity_types
    OR any(prefix IN $surface_included_prefixes WHERE e.entity_type STARTS WITH prefix)
    OR any(suffix IN $surface_included_suffixes WHERE e.entity_type ENDS WITH suffix))`, map[string]any{
				"surface_included_entity_types": rules.Exact,
				"surface_included_prefixes":     rules.Prefixes,
				"surface_included_suffixes":     rules.Suffixes,
			}
	}
}

func uniqueSortedInventoryStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
