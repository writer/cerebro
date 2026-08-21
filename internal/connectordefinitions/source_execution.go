package connectordefinitions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const SourceExecutionPlanV1MaxResponseBytes uint64 = 8 << 20

var ErrInvalidSourceExecutionPlan = errors.New("invalid source execution plan")

// CompileSourceExecutionPlanV1 compiles one validated connector family into a
// credential-free provider execution contract. Runtime code consumes only the
// returned protobuf and never reads connector YAML.
func CompileSourceExecutionPlanV1(definition Definition, familyID string) (*cerebrov1.SourceExecutionPlanV1, error) {
	sourceID := strings.TrimSpace(definition.SourceID)
	familyID = strings.TrimSpace(familyID)
	if sourceID == "" || familyID == "" {
		return nil, fmt.Errorf("%w: source and family are required", ErrInvalidSourceExecutionPlan)
	}
	if definition.Auth.Model != "bearer_token" || !definition.Auth.RequiresReferences {
		return nil, fmt.Errorf("%w: bearer auth must require references", ErrInvalidSourceExecutionPlan)
	}
	if len(definition.Auth.CredentialFields) != 1 {
		return nil, fmt.Errorf("%w: exactly one credential reference is required", ErrInvalidSourceExecutionPlan)
	}
	credential := definition.Auth.CredentialFields[0]
	if !credential.ReferenceOnly || !credential.Required || !credential.Secret {
		return nil, fmt.Errorf("%w: bearer credential must be required, secret, and reference-only", ErrInvalidSourceExecutionPlan)
	}
	if definition.Transport == nil {
		return nil, fmt.Errorf("%w: public provider origin is required", ErrInvalidSourceExecutionPlan)
	}
	origin, err := url.Parse(strings.TrimSpace(definition.Transport.BaseURL))
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, fmt.Errorf("%w: provider origin must be an HTTPS origin", ErrInvalidSourceExecutionPlan)
	}
	origin.Path = ""

	var family *ResourceFamily
	for index := range definition.ResourceFamilies {
		if definition.ResourceFamilies[index].ID == familyID {
			family = &definition.ResourceFamilies[index]
			break
		}
	}
	if family == nil {
		return nil, fmt.Errorf("%w: family %q is not defined", ErrInvalidSourceExecutionPlan, familyID)
	}
	kernel, registered := registeredSourceExecutionKernel(sourceID, familyID)
	if family.Read == nil || !registered || family.Read.ProviderKernel != kernel.providerKernel || origin.String() != kernel.origin || family.Method != kernel.method || family.Path != kernel.path || family.RecordSelector != kernel.recordSelector || family.IDField != kernel.idField || family.Read.SingletonFallbackID != kernel.singletonFallbackID {
		return nil, fmt.Errorf("%w: source family is not bound to a registered provider kernel", ErrInvalidSourceExecutionPlan)
	}
	if family.Method != "GET" || !family.Singleton || family.Pagination == nil || strings.TrimSpace(family.Pagination.Type) != "none" {
		return nil, fmt.Errorf("%w: first-party execution requires singleton GET with no cursor", ErrInvalidSourceExecutionPlan)
	}
	if family.Path == "" || !strings.HasPrefix(family.Path, "/") || strings.ContainsAny(family.Path, "?#") {
		return nil, fmt.Errorf("%w: family path is invalid", ErrInvalidSourceExecutionPlan)
	}
	if family.RecordSelector != "$" || family.Read.ProviderKernel == "" || family.Read.SingletonFallbackID == "" || family.IDField == "" {
		return nil, fmt.Errorf("%w: provider kernel, root selector, id field, and singleton fallback are required", ErrInvalidSourceExecutionPlan)
	}
	expectedKind := sourceID + "." + familyID
	if family.Event.Kind != expectedKind || strings.TrimSpace(family.Event.SchemaRef) == "" {
		return nil, fmt.Errorf("%w: event kind or schema does not match the family", ErrInvalidSourceExecutionPlan)
	}
	requiredAttributes := sortedUnique(family.Event.RequiredAttributes)
	for _, required := range []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"} {
		if !executionPlanContains(requiredAttributes, required) {
			return nil, fmt.Errorf("%w: event contract is missing %s", ErrInvalidSourceExecutionPlan, required)
		}
	}
	plan := &cerebrov1.SourceExecutionPlanV1{
		PlanId:                "source-plan-v1:" + sourceID + ":" + familyID,
		SourceId:              sourceID,
		FamilyId:              familyID,
		ProviderKernel:        family.Read.ProviderKernel,
		Method:                family.Method,
		Origin:                origin.String(),
		Path:                  family.Path,
		RecordSelector:        family.RecordSelector,
		IdField:               family.IDField,
		SingletonFallbackId:   family.Read.SingletonFallbackID,
		MaxResponseBytes:      SourceExecutionPlanV1MaxResponseBytes,
		EventKind:             family.Event.Kind,
		SchemaRef:             family.Event.SchemaRef,
		RequiredAttributes:    requiredAttributes,
		RequiredPayloadFields: sortedUnique(family.Event.RequiredPayloadFields),
	}
	digest, err := sourceExecutionPlanDigest(plan)
	if err != nil {
		return nil, err
	}
	plan.PlanDigestSha256 = digest
	return plan, nil
}

func sourceExecutionPlanDigest(plan *cerebrov1.SourceExecutionPlanV1) (string, error) {
	clone := proto.Clone(plan).(*cerebrov1.SourceExecutionPlanV1)
	clone.PlanDigestSha256 = ""
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("%w: encode plan: %w", ErrInvalidSourceExecutionPlan, err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func executionPlanContains(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}
