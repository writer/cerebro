package cloudidentity

import (
	"fmt"
	"sort"
	"strings"
)

// AssessSharing determines whether a single cloud principal is shared across
// multiple distinct logical applications/services, as opposed to replicas
// or differing workload Kinds belonging to the same logical service.
// Workload.Service (the Source CDK's ServiceMapping grouping key) is the
// stable grouping key; replicas and differing Kinds sharing one Service
// value never count as separate sharing participants.
//
// Only consumers positively linked by observed (live) Trust (see
// linkedConsumers) count toward sharing: a merely-inventoried consumer whose
// trust linkage is unconfirmed could be an unrelated workload the cloud
// side never actually admits, so it neither contributes to a Supported
// finding nor is treated as absent for Clear — it blocks Clear with a
// cloudidentity.unverified_consumer_linkage gap instead. Excess never
// requires this linkage; unlinked consumers only ever add requirements
// there.
//
// Finding >=2 distinct named LINKED services is positive, monotonic
// evidence: it remains Supported even when the consumer inventory is not
// confirmed complete (more unknown consumers can only add to a sharing
// finding, never retract one already observed). Clear — no sharing —
// requires a confirmed-complete, fully classified inventory where every
// consumer is linked, since an unresolved or unlinked consumer could itself
// be the second distinct service.
func AssessSharing(e Evidence) Sharing {
	if isUnresolvedCloudPrincipal(e.Principal) {
		return Sharing{Status: Incomplete, Gaps: []Gap{{
			Code:    "cloudidentity.unresolved_principal",
			Scope:   e.Principal.ID,
			Message: "principal is an unresolved Kubernetes service-account placeholder, not a confirmed cloud principal; sharing cannot be assessed",
		}}}
	}
	if len(e.Consumers) == 0 {
		if e.ConsumerInventoryComplete {
			return Sharing{Status: Clear}
		}
		return Sharing{Status: Incomplete, Gaps: []Gap{{
			Code:    "cloudidentity.no_consumers",
			Scope:   e.Principal.ID,
			Message: "no consumer workloads were observed and the consumer inventory is not confirmed complete",
		}}}
	}

	linked := linkedConsumers(e)

	services := map[string]bool{}
	consumerIDs := map[string]bool{}
	unclassified := false
	allLinked := true
	var gaps []Gap
	for _, c := range e.Consumers {
		if !linked[c.ID] {
			allLinked = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.unverified_consumer_linkage",
				Scope:   c.ID,
				Message: fmt.Sprintf("consumer %q has no positively verified observed-trust linkage to this principal; it is excluded from sharing counts and blocks Clear", c.ID),
			})
			continue
		}
		if c.ID != "" {
			consumerIDs[c.ID] = true
		}
		service := strings.TrimSpace(c.Service)
		if service == "" {
			unclassified = true
			continue
		}
		services[service] = true
	}

	if unclassified {
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.unclassified_workload_service",
			Scope:   e.Principal.ID,
			Message: "one or more consumer workloads have no Service grouping; they cannot be confidently attributed to a logical application",
		})
	}
	if !e.ConsumerInventoryComplete {
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.incomplete_consumer_inventory",
			Scope:   e.Principal.ID,
			Message: "consumer inventory is not confirmed complete; additional distinct consumers could still be sharing this principal",
		})
	}

	// Clear additionally requires the observed trust surface itself to be
	// complete and fully reconciled: positive linkage alone (allLinked)
	// only proves the consumers it names, never that no unreviewed trust
	// member could admit someone else, nor that every GCP role it depends
	// on is actually known.
	trustCoverageOK, trustGaps := assessTrustCoverage(e)
	gaps = append(gaps, trustGaps...)
	trustRolesResolved, trustRoleGaps := gcpObservedTrustRolesResolved(e)
	gaps = append(gaps, trustRoleGaps...)

	serviceList := make([]string, 0, len(services))
	for s := range services {
		serviceList = append(serviceList, s)
	}
	sort.Strings(serviceList)
	consumerIDList := make([]string, 0, len(consumerIDs))
	for id := range consumerIDs {
		consumerIDList = append(consumerIDList, id)
	}
	sort.Strings(consumerIDList)

	switch {
	case len(serviceList) >= 2:
		return Sharing{Status: Supported, Services: serviceList, ConsumerIDs: consumerIDList, Gaps: gaps}
	case len(serviceList) == 1:
		if e.ConsumerInventoryComplete && !unclassified && allLinked && e.Observed.Complete && trustCoverageOK && trustRolesResolved {
			return Sharing{Status: Clear, Services: serviceList, ConsumerIDs: consumerIDList, Gaps: gaps}
		}
		return Sharing{Status: Incomplete, Services: serviceList, ConsumerIDs: consumerIDList, Gaps: gaps}
	default:
		// Every consumer workload was unclassified or unlinked.
		return Sharing{Status: Incomplete, ConsumerIDs: consumerIDList, Gaps: gaps}
	}
}
