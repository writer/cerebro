package workloadscan

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
)

const credentialPivotDepth = 3

type credentialPivotTarget struct {
	node           *graph.Node
	viaPrincipalID string
	reason         string
}

func materializeSecretPivots(g *graph.Graph, workloadNode, scanNode *graph.Node, secrets map[string]secretAggregate, writeMeta graph.WriteMetadata, now time.Time) GraphMaterializationResult {
	result := GraphMaterializationResult{}
	if g == nil || workloadNode == nil || scanNode == nil || len(secrets) == 0 {
		return result
	}

	secretIDs := make([]string, 0, len(secrets))
	for id := range secrets {
		secretIDs = append(secretIDs, id)
	}
	sort.Strings(secretIDs)

	for _, id := range secretIDs {
		secret := secrets[id].record
		matchFingerprint := normalizeSecretMatchFingerprint(secret.Match)
		secretNode := buildDiscoveredSecretNode(secret, workloadNode, writeMeta)
		g.AddNode(secretNode)
		result.SecretNodesUpserted++

		if addEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(scanNode.ID, secretNode.ID, graph.EdgeKindTargets),
			Source:     scanNode.ID,
			Target:     secretNode.ID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneWorkloadAnyMap(writeMeta.PropertyMap()),
			Risk:       secretNode.Risk,
		}) {
			result.ScanSecretEdges++
		}

		artifactTargets, pivotTargets := resolveCredentialTargets(g, secret)
		for _, target := range artifactTargets {
			if target == nil {
				continue
			}
			props := cloneWorkloadAnyMap(writeMeta.PropertyMap())
			props["credential_type"] = secret.Type
			props["credential_finding_id"] = secret.ID
			props["match_fingerprint"] = matchFingerprint
			if addEdgeIfMissing(g, &graph.Edge{
				ID:         edgeID(secretNode.ID, target.ID, graph.EdgeKindTargets),
				Source:     secretNode.ID,
				Target:     target.ID,
				Kind:       graph.EdgeKindTargets,
				Effect:     graph.EdgeEffectAllow,
				Properties: props,
				Risk:       target.Risk,
			}) {
				result.SecretTargetEdges++
			}
		}

		for _, target := range pivotTargets {
			if target.node == nil {
				continue
			}
			props := cloneWorkloadAnyMap(writeMeta.PropertyMap())
			props["credential_type"] = secret.Type
			props["credential_finding_id"] = secret.ID
			props["match_fingerprint"] = matchFingerprint
			props["secret_node_id"] = secretNode.ID
			if target.viaPrincipalID != "" {
				props["via_principal_id"] = target.viaPrincipalID
			}
			if strings.TrimSpace(target.reason) != "" {
				props["resolution_reason"] = target.reason
			}
			if addEdgeIfMissing(g, &graph.Edge{
				ID:         credentialPivotEdgeID(workloadNode.ID, target.node.ID, secret.ID, target.viaPrincipalID),
				Source:     workloadNode.ID,
				Target:     target.node.ID,
				Kind:       graph.EdgeKindHasCredentialFor,
				Effect:     graph.EdgeEffectAllow,
				Properties: props,
				Risk:       maxRiskLevel(secretNode.Risk, target.node.Risk),
			}) {
				result.CredentialPivotEdges++
			}
		}
	}

	return result
}

func buildDiscoveredSecretNode(secret filesystemanalyzer.SecretFinding, workloadNode *graph.Node, metadata graph.WriteMetadata) *graph.Node {
	properties := map[string]any{
		"finding_id":         strings.TrimSpace(secret.ID),
		"secret_type":        strings.TrimSpace(secret.Type),
		"severity":           strings.TrimSpace(secret.Severity),
		"match_fingerprint":  normalizeSecretMatchFingerprint(secret.Match),
		"path":               strings.TrimSpace(secret.Path),
		"line":               secret.Line,
		"description":        strings.TrimSpace(secret.Description),
		"workload_target_id": workloadNode.ID,
	}
	if refs := secretReferenceMaps(secret.References); len(refs) > 0 {
		properties["references"] = refs
	}
	metadata.ApplyTo(properties)
	return &graph.Node{
		ID:         discoveredSecretNodeID(workloadNode.ID, secret),
		Kind:       graph.NodeKindSecret,
		Name:       discoveredSecretName(secret),
		Provider:   workloadNode.Provider,
		Account:    workloadNode.Account,
		Region:     workloadNode.Region,
		Risk:       severityToRisk(secret.Severity, false),
		Properties: properties,
	}
}

func normalizeSecretMatchFingerprint(match string) string {
	match = strings.TrimSpace(match)
	if match == "" {
		return ""
	}
	if match == "<redacted>" || match == "private_key" || strings.HasPrefix(match, "sha256:") {
		return match
	}
	sum := sha256.Sum256([]byte(match))
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func resolveCredentialTargets(g *graph.Graph, secret filesystemanalyzer.SecretFinding) ([]*graph.Node, []credentialPivotTarget) {
	var artifactTargets []*graph.Node
	var pivotTargets []credentialPivotTarget
	seenArtifact := make(map[string]struct{})
	seenPivot := make(map[string]struct{})

	for _, ref := range secret.References {
		switch {
		case strings.EqualFold(ref.Kind, "cloud_identity") && strings.EqualFold(ref.Provider, "aws"):
			principal := findNodeWithAccessKey(g, "aws", ref.Identifier)
			if principal == nil {
				continue
			}
			if _, ok := seenArtifact[principal.ID]; !ok {
				seenArtifact[principal.ID] = struct{}{}
				artifactTargets = append(artifactTargets, principal)
			}
			addPrincipalPivotTargets(g, principal, "aws_access_key", seenPivot, &pivotTargets)
		case strings.EqualFold(ref.Kind, "cloud_identity") && strings.EqualFold(ref.Provider, "gcp"):
			principal := findGCPServiceAccountByEmail(g, ref.Identifier)
			if principal == nil {
				continue
			}
			if _, ok := seenArtifact[principal.ID]; !ok {
				seenArtifact[principal.ID] = struct{}{}
				artifactTargets = append(artifactTargets, principal)
			}
			addPrincipalPivotTargets(g, principal, "gcp_service_account_key", seenPivot, &pivotTargets)
		case strings.EqualFold(ref.Kind, "database"):
			target := findDatabaseByReference(g, ref)
			if target == nil {
				continue
			}
			if _, ok := seenArtifact[target.ID]; !ok {
				seenArtifact[target.ID] = struct{}{}
				artifactTargets = append(artifactTargets, target)
			}
			if _, ok := seenPivot[target.ID]; !ok {
				seenPivot[target.ID] = struct{}{}
				pivotTargets = append(pivotTargets, credentialPivotTarget{
					node:   target,
					reason: "database_connection_string",
				})
			}
		}
	}

	return artifactTargets, pivotTargets
}

func addPrincipalPivotTargets(g *graph.Graph, principal *graph.Node, reason string, seen map[string]struct{}, out *[]credentialPivotTarget) {
	if g == nil || principal == nil {
		return
	}
	blast := graph.BlastRadius(g, principal.ID, credentialPivotDepth)
	for _, reachable := range blast.ReachableNodes {
		if reachable == nil || reachable.Node == nil {
			continue
		}
		if _, ok := seen[reachable.Node.ID]; ok {
			continue
		}
		seen[reachable.Node.ID] = struct{}{}
		*out = append(*out, credentialPivotTarget{
			node:           reachable.Node,
			viaPrincipalID: principal.ID,
			reason:         reason,
		})
	}
	if len(blast.ReachableNodes) == 0 {
		if _, ok := seen[principal.ID]; ok {
			return
		}
		seen[principal.ID] = struct{}{}
		*out = append(*out, credentialPivotTarget{
			node:           principal,
			viaPrincipalID: principal.ID,
			reason:         reason,
		})
	}
}

func findNodeWithAccessKey(g *graph.Graph, provider, accessKeyID string) *graph.Node {
	accessKeyID = strings.TrimSpace(accessKeyID)
	if g == nil || accessKeyID == "" {
		return nil
	}
	for _, node := range g.GetAllNodes() {
		if node == nil || node.Provider != provider || !node.IsIdentity() {
			continue
		}
		if accessKeyListContains(node.Properties["access_keys"], accessKeyID) {
			return node
		}
	}
	return nil
}

func findGCPServiceAccountByEmail(g *graph.Graph, email string) *graph.Node {
	email = strings.ToLower(strings.TrimSpace(email))
	if g == nil || email == "" {
		return nil
	}
	for _, node := range g.GetNodesByKind(graph.NodeKindServiceAccount) {
		if node == nil || node.Provider != "gcp" {
			continue
		}
		candidate := strings.ToLower(strings.TrimSpace(readString(node.Properties, "email")))
		if candidate == "" {
			candidate = strings.ToLower(strings.TrimSpace(node.Name))
		}
		if candidate == email {
			return node
		}
	}
	return nil
}

func findDatabaseByReference(g *graph.Graph, ref filesystemanalyzer.SecretReference) *graph.Node {
	host := normalizeReferenceHost(ref.Host)
	if g == nil || host == "" {
		return nil
	}
	hostLabel := host
	if idx := strings.IndexByte(hostLabel, '.'); idx > 0 {
		hostLabel = hostLabel[:idx]
	}

	for _, node := range g.GetNodesByKind(graph.NodeKindDatabase) {
		if node == nil {
			continue
		}
		if databaseNodeMatches(node, host, hostLabel, ref.Database) {
			return node
		}
	}
	return nil
}

func databaseNodeMatches(node *graph.Node, host, hostLabel, database string) bool {
	candidates := []string{
		strings.ToLower(strings.TrimSpace(node.Name)),
		strings.ToLower(strings.TrimSpace(readString(node.Properties, "server"))),
		strings.ToLower(strings.TrimSpace(readString(node.Properties, "endpoint"))),
		strings.ToLower(strings.TrimSpace(readString(node.Properties, "host"))),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if candidate == host || candidate == hostLabel || strings.HasPrefix(host, candidate+".") {
			return true
		}
	}
	ipAddresses := strings.ToLower(strings.TrimSpace(readString(node.Properties, "ip_addresses")))
	if ipAddresses != "" && strings.Contains(ipAddresses, host) {
		return true
	}
	if database != "" && strings.EqualFold(strings.TrimSpace(node.Name), database) {
		return true
	}
	return false
}

func accessKeyListContains(value any, accessKeyID string) bool {
	for _, candidate := range toAnySlice(value) {
		if strings.EqualFold(strings.TrimSpace(fmt.Sprint(candidate)), accessKeyID) {
			return true
		}
	}
	return false
}

func toAnySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []string:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func normalizeReferenceHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func discoveredSecretNodeID(workloadID string, secret filesystemanalyzer.SecretFinding) string {
	return fmt.Sprintf("secret:discovered:%s:%s", slugify(workloadID), slugify(secret.ID))
}

func discoveredSecretName(secret filesystemanalyzer.SecretFinding) string {
	label := strings.TrimSpace(secret.Type)
	if label == "" {
		label = "secret"
	}
	if strings.TrimSpace(secret.Path) == "" {
		return label
	}
	if secret.Line > 0 {
		return fmt.Sprintf("%s %s:%d", label, secret.Path, secret.Line)
	}
	return fmt.Sprintf("%s %s", label, secret.Path)
}

func credentialPivotEdgeID(sourceID, targetID, findingID, viaPrincipalID string) string {
	builder := strings.Builder{}
	builder.WriteString(sourceID)
	builder.WriteString(":")
	builder.WriteString(targetID)
	builder.WriteString(":")
	builder.WriteString(findingID)
	if strings.TrimSpace(viaPrincipalID) != "" {
		builder.WriteString(":")
		builder.WriteString(viaPrincipalID)
	}
	return "edge:" + slugify(builder.String()) + ":" + slugify(string(graph.EdgeKindHasCredentialFor))
}

func secretReferenceMaps(refs []filesystemanalyzer.SecretReference) []any {
	if len(refs) == 0 {
		return nil
	}
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		entry := map[string]any{
			"kind": ref.Kind,
		}
		if ref.Provider != "" {
			entry["provider"] = ref.Provider
		}
		if ref.Identifier != "" {
			entry["identifier"] = ref.Identifier
		}
		if ref.Host != "" {
			entry["host"] = ref.Host
		}
		if ref.Port > 0 {
			entry["port"] = strconv.Itoa(ref.Port)
		}
		if ref.Database != "" {
			entry["database"] = ref.Database
		}
		if len(ref.Attributes) > 0 {
			attributes := make(map[string]any, len(ref.Attributes))
			for key, value := range ref.Attributes {
				attributes[key] = value
			}
			entry["attributes"] = attributes
		}
		out = append(out, entry)
	}
	return out
}

func maxRiskLevel(left, right graph.RiskLevel) graph.RiskLevel {
	if riskRank(right) > riskRank(left) {
		return right
	}
	return left
}

func riskRank(level graph.RiskLevel) int {
	switch level {
	case graph.RiskCritical:
		return 4
	case graph.RiskHigh:
		return 3
	case graph.RiskMedium:
		return 2
	case graph.RiskLow:
		return 1
	default:
		return 0
	}
}
