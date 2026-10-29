package cloudidentitysource

import (
	"context"
	"regexp"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// gcpRoleResourceNamePattern matches a predefined ("roles/x") or custom
// ("projects/p/roles/x", "organizations/o/roles/x") IAM role resource name.
var gcpRoleResourceNamePattern = regexp.MustCompile(`^(roles/[A-Za-z0-9._]+|projects/[^/]+/roles/[A-Za-z0-9._]+|organizations/[0-9]+/roles/[A-Za-z0-9._]+)$`)

// gcpRoleEffectivePermissions returns the permissions one binding to role
// actually grants. A resolved role that is deleted or disabled grants
// nothing: when a custom role is deleted, "any role bindings that refer to
// the role remain in your allow policies, but they have no effect"
// (https://docs.cloud.google.com/iam/docs/creating-custom-roles#delete-custom-role),
// the same documented no-effect behavior DISABLED already has. Returning
// role.IncludedPermissions as-is for a deleted role would report it as live
// supported excess it does not actually grant, so both Define and ancestor
// Trust binding classification (gcpAncestorBindingCapable) treat it as
// known-empty rather than its stale IncludedPermissions.
func gcpRoleEffectivePermissions(role gcpRole) []string {
	if role.Deleted || role.Stage == "DISABLED" {
		return nil
	}
	return role.IncludedPermissions
}

// Define resolves every requested GCP role live via the IAM roles.get
// endpoints (predefined and custom, including roles defined outside the
// principal's own project), and always includes the maintained, explicitly
// cited static method-reference table as Operations, since GCP has no live
// endpoint mapping API methods to required permissions.
func (r *gcpReader) Define(ctx context.Context, req ci.DefinitionRequest) (ci.Definitions, error) {
	now := r.now().UTC()
	var roles []ci.RoleDefinition
	var gaps []ci.Gap
	complete := true
	seen := map[string]bool{}
	for _, raw := range req.GCPRoles {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if !gcpRoleResourceNamePattern.MatchString(name) {
			gaps = append(gaps, ci.Gap{Code: "gcp_role_identifier_invalid", Scope: name, Message: `GCP role must be "roles/x", "projects/p/roles/x", or "organizations/o/roles/x"`})
			complete = false
			continue
		}
		role, roleGaps := r.client.getRole(ctx, name)
		if len(roleGaps) > 0 {
			gaps = append(gaps, gcpGapsToCore(name, roleGaps)...)
			complete = false
			continue
		}
		if role.Deleted {
			// A binding to a deleted custom role grants nothing: "any role
			// bindings that refer to the role remain in your allow
			// policies, but they have no effect" (IAM docs). Reporting its
			// stale IncludedPermissions here would let assessment treat
			// them as live excess the principal does not actually have.
			gaps = append(gaps, ci.Gap{Code: "gcp_role_deleted", Scope: name, Message: "role is deleted; bindings to it grant no access, reporting zero permissions"})
		}
		if role.Stage == "DISABLED" {
			// A binding to a DISABLED custom role grants nothing: IAM
			// treats the role as inactive. Reporting its included
			// permissions here would let assessment treat those
			// permissions as live excess the principal does not actually
			// have.
			gaps = append(gaps, ci.Gap{Code: "gcp_role_disabled", Scope: name, Message: "role stage is DISABLED; bindings to it grant no access, reporting zero permissions"})
		}
		permissions := gcpRoleEffectivePermissions(role)
		roles = append(roles, ci.RoleDefinition{
			Name:        role.Name,
			Permissions: permissions,
			References: []ci.Reference{{
				API:        gcpGetRoleReference,
				Scope:      role.Name,
				ObservedAt: now,
				Digest:     ci.Digest(role),
			}},
		})
	}
	operations := gcpMethodReferenceOperations()
	// Definitions.Digest is left empty: definitionsDigestConsistent treats an
	// empty digest as consistent (never flagged), and the canonical digest
	// over the full merged Actions/Operations/Roles/Policies shape is
	// computed once by MergeDefinitions when this result is combined with
	// the AWS reader's Definitions — recomputing a partial digest here (over
	// only Roles+Operations, unsorted) would not match that canonical form.
	return ci.Definitions{
		Operations: operations,
		Roles:      roles,
		Complete:   complete,
		Gaps:       gaps,
	}, nil
}
