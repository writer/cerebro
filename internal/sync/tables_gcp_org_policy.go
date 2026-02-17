package sync

import (
	"context"
	"strings"
)

func (e *GCPSyncEngine) gcpOrgPolicyTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_org_policies",
		Columns: []string{
			"project_id",
			"name",
			"constraint",
			"parent",
			"etag",
			"update_time",
			"spec",
			"dry_run_spec",
			"reset",
			"inherit_from_parent",
			"location",
			"self_link",
			"resource_data",
		},
		Fetch: e.fetchGCPOrgPolicies,
	}
}

func (e *GCPSyncEngine) fetchGCPOrgPolicies(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	resources, err := e.searchGCPResources(ctx, projectID, "orgpolicy.googleapis.com/Policy")
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
			"name":          gcpOrgPolicyName(selfLink, resource.DisplayName),
			"constraint":    gcpOrgPolicyConstraint(selfLink, attrs),
			"parent":        firstNonEmpty(resource.ParentFullResourceName, "projects/"+projectID),
			"location":      resource.Location,
			"self_link":     selfLink,
			"resource_data": attrs,
		}

		if etag := gcpAssetString(attrs, "etag"); etag != "" {
			row["etag"] = etag
		}
		if resource.UpdateTime != nil {
			row["update_time"] = resource.UpdateTime.AsTime()
		} else if updateTime := gcpAssetString(attrs, "updateTime", "update_time"); updateTime != "" {
			row["update_time"] = updateTime
		}
		if spec := gcpAssetValue(attrs, "spec"); spec != nil {
			row["spec"] = spec
		}
		if dryRunSpec := gcpAssetValue(attrs, "dryRunSpec", "dry_run_spec"); dryRunSpec != nil {
			row["dry_run_spec"] = dryRunSpec
		}
		if reset := gcpAssetValue(attrs, "spec.reset", "reset"); reset != nil {
			row["reset"] = reset
		}
		if inherit := gcpAssetValue(attrs, "spec.inheritFromParent", "inheritFromParent"); inherit != nil {
			row["inherit_from_parent"] = inherit
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func gcpOrgPolicyName(selfLink, displayName string) string {
	if name := gcpResourceSegment(selfLink, "policies"); name != "" {
		return name
	}
	if strings.TrimSpace(displayName) != "" {
		return strings.TrimSpace(displayName)
	}
	return strings.TrimSpace(selfLink)
}

func gcpOrgPolicyConstraint(selfLink string, attrs map[string]interface{}) string {
	if constraint := gcpAssetString(attrs, "constraint", "spec.constraint"); constraint != "" {
		return constraint
	}

	if segment := gcpResourceSegment(selfLink, "constraints"); segment != "" {
		return "constraints/" + segment
	}

	if policyName := gcpResourceSegment(selfLink, "policies"); policyName != "" {
		if strings.HasPrefix(policyName, "constraints/") {
			return policyName
		}
		return "constraints/" + policyName
	}

	return ""
}
