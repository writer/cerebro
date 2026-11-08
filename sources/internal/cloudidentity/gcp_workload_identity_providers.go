package cloudidentitysource

import (
	"context"
	"strings"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// gcpPoolRef names one Workload Identity pool by project number + pool id
// -- pool identity is never reduced to a short pool id, per Contract A.6.
type gcpPoolRef struct {
	ProjectNumber string
	PoolID        string
}

// gcpCollectCustomPoolReferences scans selfID (the principal's own id, if
// it is itself a custom-pool principal) plus every member of each supplied
// Trust/Grant set for a reference to a custom (non-GKE) Workload Identity
// pool, returning the distinct pools referenced, per Contract A.2: "every
// custom pool ... referenced by the principal's own ID or by any member of
// its Declared.Trust or Observed.Trust".
func gcpCollectCustomPoolReferences(selfID string, trustSets ...[]ci.Grant) []gcpPoolRef {
	seen := map[gcpPoolRef]bool{}
	var out []gcpPoolRef
	add := func(member string) {
		projectNumber, poolID, ok := gcpCustomPoolReferenceFromMember(member)
		if !ok {
			return
		}
		ref := gcpPoolRef{ProjectNumber: projectNumber, PoolID: poolID}
		if seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	add(selfID)
	for _, grants := range trustSets {
		for _, grant := range grants {
			for _, member := range grant.Members {
				add(member)
			}
		}
	}
	return out
}

// gcpWorkloadIdentityProviderObservations lists, for every custom
// (non-GKE) Workload Identity pool referenced by selfID or any member of
// the supplied Declared/Observed trust sets, every live provider of that
// pool (projects.locations.workloadIdentityPools.providers.list; required
// permission iam.workloadIdentityPoolProviders.list on the pool's owning
// project, e.g. via roles/iam.workloadIdentityPoolViewer), per Contract
// A.1-3. A pool whose providers cannot be listed gets gap
// cloud_identity.gcp.workload_identity_provider_unreadable scoped to the
// pool's own resource name, with no provider entries for that pool --
// never a scan-wide failure.
func (r *gcpReader) gcpWorkloadIdentityProviderObservations(ctx context.Context, selfID string, now time.Time, trustSets ...[]ci.Grant) ([]ci.GCPWorkloadIdentityPoolProvider, []ci.Gap) {
	refs := gcpCollectCustomPoolReferences(selfID, trustSets...)
	if len(refs) == 0 {
		return nil, nil
	}
	var out []ci.GCPWorkloadIdentityPoolProvider
	var gaps []ci.Gap
	for _, ref := range refs {
		records, clientGaps, complete := r.client.listWorkloadIdentityPoolProviders(ctx, ref.ProjectNumber, ref.PoolID)
		scope := gcpCustomPoolResourceName(ref.ProjectNumber, ref.PoolID)
		if !complete {
			message := "workload identity pool providers could not be fully listed"
			if len(clientGaps) > 0 {
				message = clientGaps[0].Message
			}
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.gcp.workload_identity_provider_unreadable", Scope: scope, Message: message})
			continue
		}
		for _, record := range records {
			provider, ok := gcpWorkloadIdentityPoolProviderFromRecord(record, ref.ProjectNumber, ref.PoolID, scope, now)
			if !ok {
				continue
			}
			out = append(out, provider)
		}
	}
	return out, gaps
}

// gcpWorkloadIdentityPoolProviderFromRecord converts one live REST provider
// record into the core evidence shape. A record whose name does not carry
// a parseable "/providers/<id>" suffix is skipped rather than reported
// with a fabricated provider id.
func gcpWorkloadIdentityPoolProviderFromRecord(record gcpWorkloadIdentityPoolProviderRecord, projectNumber string, poolID string, scope string, now time.Time) (ci.GCPWorkloadIdentityPoolProvider, bool) {
	providerID := gcpWorkloadIdentityProviderIDFromName(record.Name)
	if providerID == "" {
		return ci.GCPWorkloadIdentityPoolProvider{}, false
	}
	issuer := ""
	if record.OIDC != nil {
		issuer = record.OIDC.IssuerURI
	}
	var condition *ci.Condition
	if expression := strings.TrimSpace(record.AttributeCondition); expression != "" {
		condition = &ci.Condition{Expression: expression}
	}
	return ci.GCPWorkloadIdentityPoolProvider{
		Name:               record.Name,
		ProjectNumber:      projectNumber,
		PoolID:             poolID,
		ProviderID:         providerID,
		State:              record.State,
		Disabled:           record.Disabled,
		Issuer:             issuer,
		AttributeMapping:   record.AttributeMapping,
		AttributeCondition: condition,
		ObservedAt:         now,
		References:         []ci.Reference{{API: gcpListWorkloadIdentityPoolProvidersReference, Scope: scope, ObservedAt: now}},
	}, true
}

// gcpWorkloadIdentityProviderIDFromName extracts the trailing "/providers/<id>"
// segment of a provider's full resource name.
func gcpWorkloadIdentityProviderIDFromName(name string) string {
	const marker = "/providers/"
	idx := strings.LastIndex(name, marker)
	if idx < 0 {
		return ""
	}
	id := name[idx+len(marker):]
	if id == "" {
		return ""
	}
	return id
}
