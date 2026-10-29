package cloudidentity

import (
	"fmt"
	"strings"
)

// manifestInventoryMatchService finds the applicable ServiceMapping for
// image deployed by the controller named workload. A mapping is applicable
// only when one of its ImagePrefixes covers image and it is either
// unqualified (Workloads empty) or lists workload by name. Among applicable
// mappings, the longest matching prefix wins; at equal prefix length a
// workload-qualified mapping beats an unqualified one (so a shared base
// image, e.g. a shared Envoy sidecar, can be split into distinct logical
// services per controller without the unqualified catch-all mapping
// silently absorbing all of them). If, after that qualification
// preference, more than one distinct Service remains tied, the result is
// ambiguous: matched is false and ambiguous is true, never a guessed
// winner. matched is false and ambiguous is false when no mapping applies
// at all; the returned ServiceMapping is then the zero value (Service ==
// ""), never a name invented from the workload itself -- fabricating a
// per-object "service" identity would let two genuinely-unrelated-but-
// unmapped workloads both get distinct non-empty Service strings, which
// downstream sharing evaluation treats as proof of >=2 distinct services
// sharing a credential. An empty Service never counts as a distinct
// service.
func manifestInventoryMatchService(image, workload string, services []ServiceMapping) (mapping ServiceMapping, matched bool, ambiguous bool) {
	type candidate struct {
		svc       ServiceMapping
		prefixLen int
		qualified bool
	}
	var candidates []candidate
	for _, svc := range services {
		if !manifestInventoryServiceAppliesToWorkload(svc, workload) {
			continue
		}
		best := -1
		for _, prefix := range svc.ImagePrefixes {
			if prefix == "" || !strings.HasPrefix(image, prefix) {
				continue
			}
			if len(prefix) > best {
				best = len(prefix)
			}
		}
		if best < 0 {
			continue
		}
		candidates = append(candidates, candidate{svc: svc, prefixLen: best, qualified: len(svc.Workloads) > 0})
	}
	if len(candidates) == 0 {
		return ServiceMapping{}, false, false
	}
	bestLen := -1
	for _, c := range candidates {
		if c.prefixLen > bestLen {
			bestLen = c.prefixLen
		}
	}
	tied := make([]candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.prefixLen == bestLen {
			tied = append(tied, c)
		}
	}
	anyQualified := false
	for _, c := range tied {
		if c.qualified {
			anyQualified = true
			break
		}
	}
	if anyQualified {
		qualifiedOnly := tied[:0]
		for _, c := range tied {
			if c.qualified {
				qualifiedOnly = append(qualifiedOnly, c)
			}
		}
		tied = qualifiedOnly
	}
	distinct := make(map[string]ServiceMapping, len(tied))
	for _, c := range tied {
		distinct[c.svc.Service] = c.svc
	}
	if len(distinct) > 1 {
		return ServiceMapping{}, false, true
	}
	return tied[0].svc, true, false
}

// manifestInventoryServiceAppliesToWorkload reports whether svc's Workloads
// qualifier (if any) admits the controller named workload. An unqualified
// mapping (no Workloads listed) applies to every workload.
func manifestInventoryServiceAppliesToWorkload(svc ServiceMapping, workload string) bool {
	if len(svc.Workloads) == 0 {
		return true
	}
	for _, w := range svc.Workloads {
		if w == workload {
			return true
		}
	}
	return false
}

// manifestInventoryWorkloadID builds a stable, unique identifier for one
// container's inventoried identity so replicas are represented once while
// distinct containers (sidecars, init containers) in the same pod template
// remain distinct entries.
func manifestInventoryWorkloadID(cluster, namespace, kind, name, containerClass, container string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s:%s", cluster, namespace, kind, name, containerClass, container)
}
