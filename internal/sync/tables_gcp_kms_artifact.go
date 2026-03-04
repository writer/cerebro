package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"

	assetapi "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpKMSKeyTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_kms_keys",
		Columns: []string{
			"project_id",
			"name",
			"location",
			"key_ring",
			"purpose",
			"protection_level",
			"next_rotation_time",
			"rotation_period",
			"create_time",
			"labels",
			"primary",
			"self_link",
			"resource_data",
		},
		Fetch: e.fetchGCPKMSKeys,
	}
}

func (e *GCPSyncEngine) gcpArtifactRegistryRepositoryTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_artifact_registry_repositories",
		Columns: []string{
			"project_id",
			"name",
			"location",
			"format",
			"mode",
			"description",
			"kms_key_name",
			"size_bytes",
			"create_time",
			"update_time",
			"labels",
			"iam_policy",
			"self_link",
			"resource_data",
		},
		Fetch: e.fetchGCPArtifactRegistryRepositories,
	}
}

func (e *GCPSyncEngine) gcpArtifactRegistryPackageTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_artifact_registry_packages",
		Columns: []string{
			"project_id",
			"name",
			"location",
			"repository",
			"create_time",
			"update_time",
			"annotations",
			"tags",
			"self_link",
			"resource_data",
		},
		Fetch: e.fetchGCPArtifactRegistryPackages,
	}
}

func (e *GCPSyncEngine) gcpArtifactRegistryVersionTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_artifact_registry_versions",
		Columns: []string{
			"project_id",
			"name",
			"location",
			"repository",
			"package",
			"create_time",
			"update_time",
			"related_tags",
			"description",
			"self_link",
			"resource_data",
		},
		Fetch: e.fetchGCPArtifactRegistryVersions,
	}
}

func (e *GCPSyncEngine) fetchGCPKMSKeys(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	resources, err := e.searchGCPResources(ctx, projectID, "cloudkms.googleapis.com/CryptoKey")
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(resources))
	for _, resource := range resources {
		if resource == nil {
			continue
		}

		selfLink := strings.TrimSpace(resource.Name)
		if selfLink == "" {
			continue
		}

		attrs := gcpAssetAttributes(resource)
		row := map[string]interface{}{
			"_cq_id":        selfLink,
			"project_id":    projectID,
			"name":          gcpResourceSegment(selfLink, "cryptoKeys"),
			"location":      resource.Location,
			"key_ring":      gcpResourceSegment(selfLink, "keyRings"),
			"labels":        resource.Labels,
			"self_link":     selfLink,
			"resource_data": attrs,
		}

		if row["name"] == "" {
			row["name"] = resource.DisplayName
		}
		if resource.CreateTime != nil {
			row["create_time"] = resource.CreateTime.AsTime()
		}
		if purpose := gcpAssetString(attrs, "purpose"); purpose != "" {
			row["purpose"] = purpose
		}
		if level := gcpAssetString(attrs, "versionTemplate.protectionLevel", "protectionLevel"); level != "" {
			row["protection_level"] = level
		}
		if next := gcpAssetString(attrs, "nextRotationTime", "next_rotation_time"); next != "" {
			row["next_rotation_time"] = next
		}
		if period := gcpAssetString(attrs, "rotationPeriod", "rotation_period"); period != "" {
			row["rotation_period"] = period
		}
		if primary := gcpAssetValue(attrs, "primary"); primary != nil {
			row["primary"] = primary
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPArtifactRegistryRepositories(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	resources, err := e.searchGCPResources(ctx, projectID, "artifactregistry.googleapis.com/Repository")
	if err != nil {
		return nil, err
	}

	iamPolicies, err := e.searchGCPIAMPolicies(ctx, projectID, "artifactregistry.googleapis.com/Repository")
	if err != nil {
		iamPolicies = nil
	}

	rows := make([]map[string]interface{}, 0, len(resources))
	for _, resource := range resources {
		if resource == nil {
			continue
		}

		selfLink := strings.TrimSpace(resource.Name)
		if selfLink == "" {
			continue
		}

		attrs := gcpAssetAttributes(resource)
		row := map[string]interface{}{
			"_cq_id":        selfLink,
			"project_id":    projectID,
			"name":          gcpResourceSegment(selfLink, "repositories"),
			"location":      resource.Location,
			"description":   firstNonEmpty(resource.Description, gcpAssetString(attrs, "description")),
			"labels":        resource.Labels,
			"self_link":     selfLink,
			"resource_data": attrs,
		}

		if row["name"] == "" {
			row["name"] = resource.DisplayName
		}
		if resource.CreateTime != nil {
			row["create_time"] = resource.CreateTime.AsTime()
		}
		if resource.UpdateTime != nil {
			row["update_time"] = resource.UpdateTime.AsTime()
		}
		if format := gcpAssetString(attrs, "format"); format != "" {
			row["format"] = format
		}
		if mode := gcpAssetString(attrs, "mode"); mode != "" {
			row["mode"] = mode
		}
		if kms := gcpAssetString(attrs, "kmsKeyName", "kms_key_name"); kms != "" {
			row["kms_key_name"] = kms
		}
		if size := gcpAssetValue(attrs, "sizeBytes", "size_bytes"); size != nil {
			row["size_bytes"] = size
		}
		if policy, ok := iamPolicies[normalizeGCPAssetName(selfLink)]; ok {
			row["iam_policy"] = policy
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPArtifactRegistryPackages(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	resources, err := e.searchGCPResources(ctx, projectID, "artifactregistry.googleapis.com/Package")
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(resources))
	for _, resource := range resources {
		if resource == nil {
			continue
		}

		selfLink := strings.TrimSpace(resource.Name)
		if selfLink == "" {
			continue
		}

		attrs := gcpAssetAttributes(resource)
		name := gcpResourceSegment(selfLink, "packages")
		row := map[string]interface{}{
			"_cq_id":        selfLink,
			"project_id":    projectID,
			"name":          firstNonEmpty(name, resource.DisplayName),
			"location":      resource.Location,
			"repository":    gcpResourceSegment(selfLink, "repositories"),
			"self_link":     selfLink,
			"resource_data": attrs,
		}

		if resource.CreateTime != nil {
			row["create_time"] = resource.CreateTime.AsTime()
		}
		if resource.UpdateTime != nil {
			row["update_time"] = resource.UpdateTime.AsTime()
		}
		if annotations := gcpAssetValue(attrs, "annotations"); annotations != nil {
			row["annotations"] = annotations
		}
		if tags := gcpAssetValue(attrs, "tags"); tags != nil {
			row["tags"] = tags
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPArtifactRegistryVersions(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	resources, err := e.searchGCPResources(ctx, projectID, "artifactregistry.googleapis.com/Version")
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(resources))
	for _, resource := range resources {
		if resource == nil {
			continue
		}

		selfLink := strings.TrimSpace(resource.Name)
		if selfLink == "" {
			continue
		}

		attrs := gcpAssetAttributes(resource)
		name := gcpResourceSegment(selfLink, "versions")
		row := map[string]interface{}{
			"_cq_id":        selfLink,
			"project_id":    projectID,
			"name":          firstNonEmpty(name, resource.DisplayName),
			"location":      resource.Location,
			"repository":    gcpResourceSegment(selfLink, "repositories"),
			"package":       gcpResourceSegment(selfLink, "packages"),
			"description":   firstNonEmpty(resource.Description, gcpAssetString(attrs, "description")),
			"self_link":     selfLink,
			"resource_data": attrs,
		}

		if resource.CreateTime != nil {
			row["create_time"] = resource.CreateTime.AsTime()
		}
		if resource.UpdateTime != nil {
			row["update_time"] = resource.UpdateTime.AsTime()
		}
		if relatedTags := gcpAssetValue(attrs, "relatedTags", "related_tags", "tags"); relatedTags != nil {
			row["related_tags"] = relatedTags
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) searchGCPResources(ctx context.Context, projectID, assetType string) ([]*assetpb.ResourceSearchResult, error) {
	client, err := assetapi.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &assetpb.SearchAllResourcesRequest{
		Scope:      fmt.Sprintf("projects/%s", projectID),
		AssetTypes: []string{assetType},
		PageSize:   500,
	}

	it := client.SearchAllResources(ctx, req)
	rows := make([]*assetpb.ResourceSearchResult, 0)
	for {
		resource, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("search resources for %s: %w", assetType, err)
		}
		rows = append(rows, resource)
	}

	return rows, nil
}

func (e *GCPSyncEngine) searchGCPIAMPolicies(ctx context.Context, projectID, assetType string) (map[string]map[string]interface{}, error) {
	client, err := assetapi.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &assetpb.SearchAllIamPoliciesRequest{
		Scope:      fmt.Sprintf("projects/%s", projectID),
		AssetTypes: []string{assetType},
		PageSize:   500,
	}

	it := client.SearchAllIamPolicies(ctx, req)
	rows := make(map[string]map[string]interface{})
	for {
		policyResult, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("search iam policies for %s: %w", assetType, err)
		}

		resourceName := normalizeGCPAssetName(policyResult.GetResource())
		if resourceName == "" {
			continue
		}

		policy := policyResult.GetPolicy()
		if policy == nil {
			continue
		}

		serialized := map[string]interface{}{
			"bindings": serializeGCPIAMBindings(policy.GetBindings()),
		}
		if policy.GetVersion() != 0 {
			serialized["version"] = policy.GetVersion()
		}

		rows[resourceName] = serialized
	}

	return rows, nil
}

func serializeGCPIAMBindings(bindings []*iampb.Binding) []map[string]interface{} {
	if len(bindings) == 0 {
		return nil
	}

	serialized := make([]map[string]interface{}, 0, len(bindings))
	for _, binding := range bindings {
		if binding == nil {
			continue
		}

		members := append([]string(nil), binding.GetMembers()...)
		entry := map[string]interface{}{
			"role":          binding.GetRole(),
			"members":       members,
			"members_count": len(members),
		}

		if condition := binding.GetCondition(); condition != nil {
			entry["condition"] = map[string]interface{}{
				"title":       condition.GetTitle(),
				"description": condition.GetDescription(),
				"expression":  condition.GetExpression(),
			}
		}

		serialized = append(serialized, entry)
	}

	if len(serialized) == 0 {
		return nil
	}

	return serialized
}

func normalizeGCPAssetName(resourceName string) string {
	resourceName = strings.TrimSpace(resourceName)
	resourceName = strings.TrimPrefix(resourceName, "//")
	return resourceName
}

func gcpAssetAttributes(resource *assetpb.ResourceSearchResult) map[string]interface{} {
	if resource == nil || resource.AdditionalAttributes == nil {
		return map[string]interface{}{}
	}
	attrs := resource.AdditionalAttributes.AsMap()
	if attrs == nil {
		return map[string]interface{}{}
	}
	return attrs
}

func gcpAssetValue(attrs map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if v, ok := attrs[key]; ok {
			return v
		}
		if strings.Contains(key, ".") {
			if v := gcpAssetNestedValue(attrs, strings.Split(key, ".")); v != nil {
				return v
			}
		}
	}
	return nil
}

func gcpAssetString(attrs map[string]interface{}, keys ...string) string {
	v := gcpAssetValue(attrs, keys...)
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func gcpAssetNestedValue(attrs map[string]interface{}, path []string) interface{} {
	if len(path) == 0 {
		return nil
	}
	cur := interface{}(attrs)
	for _, key := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		next, ok := m[key]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func gcpResourceSegment(resourceName, segment string) string {
	parts := strings.Split(resourceName, "/")
	for i, part := range parts {
		if part == segment && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
