package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphpaths"
	"github.com/writer/cerebro/internal/ports"
)

var (
	_ GraphRule           = (*cloudPublicExposurePrivilegedPrincipalRule)(nil)
	_ ScopedStaleResolver = (*cloudPublicExposurePrivilegedPrincipalRule)(nil)
)

const (
	cloudPublicExposurePrivilegedPrincipalRuleID   = "cloud-public-exposure-privileged-principal"
	cloudPublicExposurePrivilegedPrincipalKind     = "finding.cloud_public_exposure_privileged_principal"
	cloudPublicExposurePrivilegedPrincipalRowLimit = 250
	// cloudPublicExposurePrivilegedPrincipalPerAccountCap bounds the exposure and
	// proof-path sample per cloud account. Without it broad accounts can return a
	// very large number of exposure-to-principal paths before ORDER BY/LIMIT.
	// Capping keeps a deterministic, lexicographically ordered representative
	// sample.
	//
	// When the cap actually drops data the query emits graph_rule_truncated=true
	// so the service marks the evaluation truncated and skips stale-finding
	// auto-resolution; otherwise capping a large account below the row limit would
	// silently close still-active findings for the dropped combinations.
	cloudPublicExposurePrivilegedPrincipalPerAccountCap = 50
)

type cloudPublicExposurePrivilegedPrincipalRule struct {
	definition RuleDefinition
}

func newCloudPublicExposurePrivilegedPrincipalRule() Rule {
	capabilities := builtinCloudCapabilities
	return &cloudPublicExposurePrivilegedPrincipalRule{
		definition: RuleDefinition{
			ID:          cloudPublicExposurePrivilegedPrincipalRuleID,
			Name:        "Cloud Public Exposure With Privileged Principal",
			Description: "Detect cloud accounts where public reachability and admin-equivalent permissions intersect.",
			SourceID:    "cloud",
			EventKinds:  capabilities.EventKinds(cloudCapabilityEffectivePermission, cloudCapabilityPrivilegePath, cloudCapabilityResourceExposure),
			OutputKind:  cloudPublicExposurePrivilegedPrincipalKind,
			Severity:    "CRITICAL",
			Status:      findingStatusOpen,
			Maturity:    "test",
			Tags:        []string{"cloud", "attack-path", "public-exposure", "privilege-escalation", "attack.t1190", "attack.t1098"},
			References:  []string{"https://www.cisecurity.org/benchmark/amazon_web_services", "https://attack.mitre.org/techniques/T1190/", "https://attack.mitre.org/techniques/T1098/"},
			FalsePositives: []string{
				"Approved public endpoint in an account where privileged access is intentionally restricted by compensating controls not yet modeled in the graph.",
				"Transient deployment or bootstrap permissions during a documented maintenance window.",
			},
			Runbook: "Review the public endpoint/resource and privileged principal in the same cloud account. Remove public ingress where unnecessary, reduce the principal permission scope, and document approved exceptions.",
			FingerprintFields: []string{
				"cloud_account_urn",
				"exposed_resource_urn",
				"principal_urn",
				"permission_urn",
			},
			ControlRefs: []ports.FindingControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.6"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"},
			},
			Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
		},
	}
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return proto.Clone(r.definition.RuleSpec()).(*cerebrov1.RuleSpec)
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	sourceID := strings.TrimSpace(runtime.GetSourceId())
	supportedSource := false
	for _, candidate := range builtinCloudCapabilities.SourceIDs() {
		if strings.EqualFold(sourceID, candidate) {
			supportedSource = true
			break
		}
	}
	if !supportedSource {
		return false
	}
	return runtimeMayEmitEventKind(runtime, r.definition.EventKinds)
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) QueryFor(runtime *cerebrov1.SourceRuntime) ports.CypherQueryRequest {
	if runtime == nil || strings.TrimSpace(runtime.GetTenantId()) == "" {
		return ports.CypherQueryRequest{}
	}
	return ports.CypherQueryRequest{
		Query: fmt.Sprintf(`MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type IN ['aws.public_principal', 'gcp.public_principal', 'azure.public_principal']
WITH account, public, reach, exposed
ORDER BY exposed.label, exposed.urn
WITH account, collect(DISTINCT {
       public: public,
       reach: reach,
       exposed: exposed,
       public_urn: public.urn,
       public_entity_type: public.entity_type,
       public_label: public.label,
       exposed_urn: exposed.urn,
       exposed_entity_type: exposed.entity_type,
       exposed_label: exposed.label,
       reach_relation: reach.relation
     }) AS all_exposures
WITH account, size(all_exposures) > $exposure_cap AS exposures_capped, all_exposures[0..$exposure_cap] AS exposures
WHERE size(exposures) > 0
UNWIND exposures AS exposure
WITH account, exposures_capped, exposure, exposure.exposed AS exposed
MATCH proof_path = (exposed)-[:RELATION*1..4]-(principal:Entity {tenant_id: $tenant_id})
WHERE all(node IN nodes(proof_path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(proof_path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $traversal_relations)
  AND %s
MATCH (principal)-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account)
WHERE access.relation IN ['can_admin', 'can_perform', 'can_assume', 'can_impersonate']
  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
  )
WITH account, exposures_capped, exposure, principal, access, permission, proof_path
ORDER BY length(proof_path), principal.label, principal.urn, permission.label, permission.urn
WITH account, exposures_capped, exposure, principal, access, permission, head(collect(proof_path)) AS proof_path
ORDER BY exposure.exposed_label, exposure.exposed_urn, principal.label, principal.urn, permission.label, permission.urn
WITH account, exposures_capped, collect({
       exposure: exposure,
       principal: principal,
       access: access,
       permission: permission,
       proof_path: proof_path
     }) AS all_paths
WITH account, (exposures_capped OR size(all_paths) > $path_cap) AS account_capped, all_paths[0..$path_cap] AS paths
WHERE size(paths) > 0
UNWIND paths AS path
WITH account, account_capped, path.exposure AS exposure, path.principal AS principal, path.access AS access, path.permission AS permission, path.proof_path AS proof_path
RETURN exposure.public_urn AS public_urn,
       exposure.public_entity_type AS public_entity_type,
       exposure.public_label AS public_label,
       exposure.exposed_urn AS exposed_urn,
       exposure.exposed_entity_type AS exposed_entity_type,
       exposure.exposed_label AS exposed_label,
       account.urn AS account_urn,
       account.label AS account_label,
       principal.urn AS principal_urn,
       principal.entity_type AS principal_entity_type,
       principal.label AS principal_label,
       permission.urn AS permission_urn,
       permission.entity_type AS permission_entity_type,
       permission.label AS permission_label,
       exposure.reach_relation AS reach_relation,
       access.relation AS access_relation,
       coalesce(access.attributes_json, '') AS access_attributes_json,
       [rel IN relationships(proof_path) | rel.relation] AS relation_chain,
       [idx IN range(0, length(proof_path) - 1) | {
         from_urn: nodes(proof_path)[idx].urn,
         from_label: nodes(proof_path)[idx].label,
         from_entity_type: nodes(proof_path)[idx].entity_type,
         relation: relationships(proof_path)[idx].relation,
         to_urn: nodes(proof_path)[idx + 1].urn,
         to_label: nodes(proof_path)[idx + 1].label,
         to_entity_type: nodes(proof_path)[idx + 1].entity_type,
         direction: CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END,
         attributes_json: coalesce(relationships(proof_path)[idx].attributes_json, '')
       }] AS traversal_edges,
       account_capped AS graph_rule_truncated
ORDER BY account_label, exposed_label, principal_label, permission_label
LIMIT $row_limit`, graphpaths.CloudExposurePrivilegeTraversalDirectionPredicate),
		Params: map[string]any{
			"tenant_id":           strings.TrimSpace(runtime.GetTenantId()),
			"row_limit":           int64(cloudPublicExposurePrivilegedPrincipalRowLimit),
			"exposure_cap":        int64(cloudPublicExposurePrivilegedPrincipalPerAccountCap),
			"path_cap":            int64(cloudPublicExposurePrivilegedPrincipalPerAccountCap),
			"traversal_relations": graphpaths.CloudExposurePrivilegeTraversalRelations(),
		},
		RowLimit: cloudPublicExposurePrivilegedPrincipalRowLimit,
	}
}

// StaleResolutionScopeAttribute groups stale-finding resolution by cloud account.
// The per-account cap can drop exposure-to-principal proof paths for some
// accounts while leaving others fully represented, so resolution must only touch
// accounts that came back complete.
func (r *cloudPublicExposurePrivilegedPrincipalRule) StaleResolutionScopeAttribute() string {
	return "cloud_account_urn"
}

// IncompleteStaleResolutionScopes returns the set of account URNs whose rows were
// capped this evaluation (graph_rule_truncated=true). account_capped is computed at
// the account grouping level, so every row of a capped account carries the flag.
// Findings for these accounts must stay open; findings for any other account are
// safe to resolve once they no longer match.
func (r *cloudPublicExposurePrivilegedPrincipalRule) IncompleteStaleResolutionScopes(rows []ports.CypherRow) map[string]struct{} {
	incomplete := make(map[string]struct{})
	for _, row := range rows {
		if !cypherValueTruthy(row.Values[graphRuleTruncationColumn]) {
			continue
		}
		if account := cypherRowString(row, "account_urn"); account != "" {
			incomplete[account] = struct{}{}
		}
	}
	return incomplete
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) EvaluateRows(_ context.Context, runtime *cerebrov1.SourceRuntime, rows []ports.CypherRow) ([]*ports.FindingRecord, error) {
	if r == nil || runtime == nil || len(rows) == 0 {
		return nil, nil
	}
	findings := make([]*ports.FindingRecord, 0, len(rows))
	now := time.Now().UTC()
	for _, row := range rows {
		finding := r.buildFinding(runtime, row, now)
		if finding != nil {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (r *cloudPublicExposurePrivilegedPrincipalRule) buildFinding(runtime *cerebrov1.SourceRuntime, row ports.CypherRow, now time.Time) *ports.FindingRecord {
	accountURN := cypherRowString(row, "account_urn")
	exposedURN := cypherRowString(row, "exposed_urn")
	principalURN := cypherRowString(row, "principal_urn")
	permissionURN := cypherRowString(row, "permission_urn")
	if accountURN == "" || exposedURN == "" || principalURN == "" || permissionURN == "" {
		return nil
	}
	relationChain := cloudAttackPathRelationChain(row)
	if !cloudAttackPathTraversalProofMatches(row, relationChain) {
		return nil
	}
	traversalPaths := cloudAttackPathTraversalEvidencePaths(row)
	if len(traversalPaths) == 0 {
		return nil
	}
	accountLabel := cypherRowString(row, "account_label")
	exposedLabel := cypherRowString(row, "exposed_label")
	principalLabel := cypherRowString(row, "principal_label")
	permissionLabel := cypherRowString(row, "permission_label")
	attributes := map[string]string{
		"access_relation":       cypherRowString(row, "access_relation"),
		"cloud_account_label":   accountLabel,
		"cloud_account_urn":     accountURN,
		"exposed_resource_type": cypherRowString(row, "exposed_entity_type"),
		"exposed_resource_urn":  exposedURN,
		"permission_type":       cypherRowString(row, "permission_entity_type"),
		"permission_urn":        permissionURN,
		"principal_type":        cypherRowString(row, "principal_entity_type"),
		"principal_urn":         principalURN,
		"public_principal_urn":  cypherRowString(row, "public_urn"),
		"reach_relation":        cypherRowString(row, "reach_relation"),
		"source_runtime_id":     strings.TrimSpace(runtime.GetId()),
		"traversal_depth":       fmt.Sprintf("%d", len(relationChain)),
		"traversal_relations":   strings.Join(relationChain, ","),
	}
	for key, value := range r.definition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	fingerprint := hashFindingFingerprint(r.definition.ID, accountURN, exposedURN, principalURN, permissionURN)
	summary := fmt.Sprintf("Publicly reachable cloud resource %s reaches privileged principal %s via %s", firstNonEmpty(exposedLabel, exposedURN), firstNonEmpty(principalLabel, principalURN), firstNonEmpty(permissionLabel, permissionURN))
	evidencePaths := []*cerebrov1.GraphEvidencePath{
		newGraphEvidencePath(cypherRowString(row, "public_urn"), cypherRowString(row, "public_label"), cypherRowString(row, "public_entity_type"), cypherRowString(row, "reach_relation"), exposedURN, exposedLabel, cypherRowString(row, "exposed_entity_type"), nil),
	}
	evidencePaths = append(evidencePaths, traversalPaths...)
	evidencePaths = append(evidencePaths, newGraphEvidencePath(principalURN, principalLabel, cypherRowString(row, "principal_entity_type"), cypherRowString(row, "access_relation"), permissionURN, permissionLabel, cypherRowString(row, "permission_entity_type"), edgeStringAttributes(cypherRowString(row, "access_attributes_json"))))
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("cloud_attack_path", map[string]string{
			"account":    firstNonEmpty(accountLabel, accountURN),
			"permission": firstNonEmpty(permissionLabel, permissionURN),
			"principal":  firstNonEmpty(principalLabel, principalURN),
			"resource":   firstNonEmpty(exposedLabel, exposedURN),
			"relations":  strings.Join(relationChain, ","),
		}, evidencePaths...),
	}
	resourceURNs := cloudAttackPathResourceURNs(row, exposedURN, principalURN, permissionURN, accountURN)
	return &ports.FindingRecord{
		ID:                fingerprint,
		Fingerprint:       fingerprint,
		TenantID:          strings.TrimSpace(runtime.GetTenantId()),
		RuntimeID:         strings.TrimSpace(runtime.GetId()),
		RuleID:            r.definition.ID,
		Title:             r.definition.Name,
		Severity:          r.definition.Severity,
		Status:            r.definition.Status,
		Summary:           summary,
		ResourceURNs:      resourceURNs,
		ObservedPolicyIDs: []string{permissionURN},
		PolicyID:          permissionURN,
		PolicyName:        firstNonEmpty(permissionLabel, permissionURN),
		CheckID:           r.definition.ID,
		CheckName:         r.definition.Name,
		ControlRefs:       cloneFindingControlRefs(r.definition.ControlRefs),
		GraphEvidenceRows: graphRows,
		Attributes:        attributes,
		FirstObservedAt:   now,
		LastObservedAt:    now,
	}
}

func cloudAttackPathRelationChain(row ports.CypherRow) []string {
	items := cypherRowList(row, "relation_chain")
	if len(items) == 0 {
		return nil
	}
	relations := make([]string, 0, len(items))
	for _, item := range items {
		relation := ""
		switch typed := item.(type) {
		case string:
			relation = strings.TrimSpace(typed)
		case fmt.Stringer:
			relation = strings.TrimSpace(typed.String())
		default:
			relation = strings.TrimSpace(fmt.Sprintf("%v", typed))
		}
		if relation != "" {
			relations = append(relations, relation)
		}
	}
	return relations
}

func cloudAttackPathTraversalProofMatches(row ports.CypherRow, relationChain []string) bool {
	items := cypherRowList(row, "traversal_edges")
	if len(relationChain) == 0 || len(items) != len(relationChain) {
		return false
	}
	for idx, item := range items {
		relation := cypherListMapString(item, "relation")
		if relation == "" || relation != strings.TrimSpace(relationChain[idx]) {
			return false
		}
		if cypherListMapString(item, "from_urn") == "" || cypherListMapString(item, "to_urn") == "" {
			return false
		}
		if !graphpaths.CloudExposurePrivilegeTraversalAllowsStep(relation, cypherListMapString(item, "direction")) {
			return false
		}
	}
	return true
}

func cloudAttackPathTraversalEvidencePaths(row ports.CypherRow) []*cerebrov1.GraphEvidencePath {
	items := cypherRowList(row, "traversal_edges")
	if len(items) == 0 {
		return nil
	}
	paths := make([]*cerebrov1.GraphEvidencePath, 0, len(items))
	for _, item := range items {
		fromURN := cypherListMapString(item, "from_urn")
		toURN := cypherListMapString(item, "to_urn")
		relation := cypherListMapString(item, "relation")
		if fromURN == "" || toURN == "" || relation == "" {
			continue
		}
		attributes := edgeStringAttributes(cypherListMapString(item, "attributes_json"))
		if direction := cypherListMapString(item, "direction"); direction != "" {
			if attributes == nil {
				attributes = map[string]string{}
			}
			attributes["traversal_direction"] = direction
		}
		paths = append(paths, newGraphEvidencePath(
			fromURN,
			cypherListMapString(item, "from_label"),
			cypherListMapString(item, "from_entity_type"),
			relation,
			toURN,
			cypherListMapString(item, "to_label"),
			cypherListMapString(item, "to_entity_type"),
			attributes,
		))
	}
	return paths
}

func cloudAttackPathResourceURNs(row ports.CypherRow, exposedURN string, principalURN string, permissionURN string, accountURN string) []string {
	resourceURNs := []string{exposedURN}
	for _, item := range cypherRowList(row, "traversal_edges") {
		resourceURNs = append(resourceURNs, cypherListMapString(item, "from_urn"), cypherListMapString(item, "to_urn"))
	}
	resourceURNs = append(resourceURNs, principalURN, permissionURN, accountURN)
	return deduplicateStrings(resourceURNs)
}
