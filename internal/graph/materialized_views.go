package graph

import (
	"sort"
	"time"
)

const (
	defaultBlastRadiusTopNLimit = 10
	maxBlastRadiusTopNLimit     = 100
	defaultBlastRadiusTopNDepth = 3
)

type blastRadiusTopNCacheKey struct {
	limit    int
	maxDepth int
}

type cachedBlastRadiusTopN struct {
	version uint64
	view    *BlastRadiusTopNView
}

// BlastRadiusTopNEntry summarizes one principal in the materialized blast-radius leaderboard.
type BlastRadiusTopNEntry struct {
	PrincipalID      string      `json:"principal_id"`
	PrincipalName    string      `json:"principal_name"`
	PrincipalKind    NodeKind    `json:"principal_kind"`
	Account          string      `json:"account,omitempty"`
	ReachableCount   int         `json:"reachable_count"`
	AccountsReached  int         `json:"accounts_reached"`
	CrossAccountRisk bool        `json:"cross_account_risk"`
	RiskSummary      RiskSummary `json:"risk_summary"`
}

// BlastRadiusTopNView is a materialized leaderboard of principals with the widest blast radius.
type BlastRadiusTopNView struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Version     uint64                 `json:"version"`
	Limit       int                    `json:"limit"`
	MaxDepth    int                    `json:"max_depth"`
	Entries     []BlastRadiusTopNEntry `json:"entries,omitempty"`
}

// BlastRadiusTopN materializes a ranked blast-radius leaderboard and caches it for the current graph version.
func BlastRadiusTopN(g *Graph, limit, maxDepth int) *BlastRadiusTopNView {
	limit = normalizeBlastRadiusTopNLimit(limit)
	maxDepth = normalizeBlastRadiusTopNDepth(maxDepth)

	if g == nil {
		return &BlastRadiusTopNView{
			GeneratedAt: temporalNowUTC(),
			Limit:       limit,
			MaxDepth:    maxDepth,
		}
	}

	if cached, ok := g.getBlastRadiusTopNFromCache(limit, maxDepth); ok {
		return cached
	}

	version := g.currentBlastRadiusCacheVersion()
	principals := blastRadiusTopNCandidates(g)
	view := buildBlastRadiusTopNView(g, principals, limit, maxDepth, version)
	g.putBlastRadiusTopNInCache(limit, maxDepth, version, view)
	return cloneBlastRadiusTopNView(view)
}

func normalizeBlastRadiusTopNLimit(limit int) int {
	if limit <= 0 {
		return defaultBlastRadiusTopNLimit
	}
	if limit > maxBlastRadiusTopNLimit {
		return maxBlastRadiusTopNLimit
	}
	return limit
}

func normalizeBlastRadiusTopNDepth(maxDepth int) int {
	if maxDepth <= 0 {
		return defaultBlastRadiusTopNDepth
	}
	return maxDepth
}

func blastRadiusTopNCandidates(g *Graph) []*Node {
	nodes := g.GetAllNodes()
	principals := make([]*Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || !node.IsIdentity() {
			continue
		}
		principals = append(principals, node)
	}
	sort.Slice(principals, func(i, j int) bool {
		return principals[i].ID < principals[j].ID
	})
	return principals
}

func buildBlastRadiusTopNView(g *Graph, principals []*Node, limit, maxDepth int, version uint64) *BlastRadiusTopNView {
	entries := parallelProcessOrdered(principals, func(principal *Node) []BlastRadiusTopNEntry {
		if principal == nil {
			return nil
		}
		result := BlastRadius(g, principal.ID, maxDepth)
		if result == nil || result.TotalCount == 0 {
			return nil
		}
		return []BlastRadiusTopNEntry{{
			PrincipalID:      principal.ID,
			PrincipalName:    firstNonEmpty(principal.Name, result.PrincipalName),
			PrincipalKind:    principal.Kind,
			Account:          principal.Account,
			ReachableCount:   result.TotalCount,
			AccountsReached:  result.AccountsReached,
			CrossAccountRisk: result.CrossAccountRisk,
			RiskSummary:      result.RiskSummary,
		}}
	})

	sort.Slice(entries, func(i, j int) bool {
		left := entries[i]
		right := entries[j]
		switch {
		case left.ReachableCount != right.ReachableCount:
			return left.ReachableCount > right.ReachableCount
		case left.RiskSummary.Critical != right.RiskSummary.Critical:
			return left.RiskSummary.Critical > right.RiskSummary.Critical
		case left.RiskSummary.High != right.RiskSummary.High:
			return left.RiskSummary.High > right.RiskSummary.High
		case left.AccountsReached != right.AccountsReached:
			return left.AccountsReached > right.AccountsReached
		case left.PrincipalName != right.PrincipalName:
			return left.PrincipalName < right.PrincipalName
		default:
			return left.PrincipalID < right.PrincipalID
		}
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}

	return &BlastRadiusTopNView{
		GeneratedAt: temporalNowUTC(),
		Version:     version,
		Limit:       limit,
		MaxDepth:    maxDepth,
		Entries:     entries,
	}
}

func (g *Graph) getBlastRadiusTopNFromCache(limit, maxDepth int) (*BlastRadiusTopNView, bool) {
	version := g.currentBlastRadiusCacheVersion()
	raw, ok := g.blastRadiusTopNCache.Load(blastRadiusTopNCacheKey{limit: limit, maxDepth: maxDepth})
	if !ok {
		return nil, false
	}

	cached, ok := raw.(*cachedBlastRadiusTopN)
	if !ok || cached == nil || cached.view == nil {
		g.blastRadiusTopNCache.Delete(blastRadiusTopNCacheKey{limit: limit, maxDepth: maxDepth})
		return nil, false
	}
	if cached.version != version {
		g.blastRadiusTopNCache.Delete(blastRadiusTopNCacheKey{limit: limit, maxDepth: maxDepth})
		return nil, false
	}
	return cloneBlastRadiusTopNView(cached.view), true
}

func (g *Graph) putBlastRadiusTopNInCache(limit, maxDepth int, version uint64, view *BlastRadiusTopNView) {
	if view == nil || version != g.currentBlastRadiusCacheVersion() {
		return
	}

	key := blastRadiusTopNCacheKey{limit: limit, maxDepth: maxDepth}
	g.blastRadiusTopNCacheWriteMu.Lock()
	defer g.blastRadiusTopNCacheWriteMu.Unlock()

	if version != g.currentBlastRadiusCacheVersion() {
		return
	}
	g.blastRadiusTopNCache.Store(key, &cachedBlastRadiusTopN{
		version: version,
		view:    cloneBlastRadiusTopNView(view),
	})
}

func cloneBlastRadiusTopNView(view *BlastRadiusTopNView) *BlastRadiusTopNView {
	if view == nil {
		return nil
	}
	cloned := *view
	cloned.Entries = append([]BlastRadiusTopNEntry(nil), view.Entries...)
	return &cloned
}
