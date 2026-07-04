package oktafreshness

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	sourceID                 = "okta"
	userFamily               = "user"
	userFreshnessKind        = "okta_user_latest_record"
	userFreshnessResourceNil = "empty"
	userFreshnessMaxSkips    = 24
	userFreshnessMaxAge      = 24 * time.Hour
)

type Scope struct {
	Domain string
	Filter string
	Q      string
	Search string
}

func NewScope(domain string, filter string, q string, search string) Scope {
	return Scope{Domain: domain, Filter: filter, Q: q, Search: search}
}

type User struct {
	ID        string
	Status    string
	UpdatedAt time.Time
	URN       sourcecdk.URN
}

type LatestUserFunc func(context.Context, string, string, int) (User, bool, error)

func UserReadOptions() sourcecdk.FamilyFreshnessReadOptions {
	return sourcecdk.FamilyFreshnessReadOptions{
		Confidence:     sourcecdk.FamilyFreshnessConfidenceHeuristic,
		MaxSkipCount:   userFreshnessMaxSkips,
		MaxSkipAge:     userFreshnessMaxAge,
		ProbeErrorMode: sourcecdk.FamilyFreshnessProbeErrorFailOpen,
	}
}

func ProbeLatestUser(ctx context.Context, checkpoint *cerebrov1.SourceCheckpoint, scope Scope, list LatestUserFunc) (sourcecdk.ChangeProbe, error) {
	user, ok, err := list(ctx, "lastUpdated", "desc", 1)
	if err != nil {
		return sourcecdk.ChangeProbe{}, err
	}
	change := sourcecdk.FamilyFreshnessChangeProbe(sourceID, userFamily, checkpoint, latestUserProbe(scope, user, ok, time.Now().UTC()))
	if ok {
		if id := strings.TrimSpace(user.ID); id != "" {
			change.ChangedResourceIDs = []string{id}
		}
		if strings.TrimSpace(user.URN.String()) != "" {
			change.ChangedURNs = []sourcecdk.URN{user.URN}
		}
	}
	return change, nil
}

func latestUserProbe(scope Scope, user User, ok bool, observedAt time.Time) sourcecdk.FamilyFreshnessProbe {
	resourceID := userFreshnessResourceNil
	updatedAt := time.Time{}
	hashParts := scope.hashParts(userFreshnessKind, resourceID, "empty")
	if ok {
		if id := strings.TrimSpace(user.ID); id != "" {
			resourceID = id
		}
		updatedAt = user.UpdatedAt
		hashParts = scope.hashParts(userFreshnessKind, resourceID, updatedAt.Format(time.RFC3339Nano), user.Status)
	}
	return sourcecdk.FamilyFreshnessProbe{
		Kind:       userFreshnessKind,
		ResourceID: resourceID,
		ObservedAt: observedAt,
		UpdatedAt:  updatedAt,
		Hash:       sourcecdk.FamilyFreshnessHash(hashParts...),
		Confidence: sourcecdk.FamilyFreshnessConfidenceHeuristic,
	}
}

func (s Scope) hashParts(parts ...string) []string {
	scoped := []string{strings.TrimSpace(s.Domain), strings.TrimSpace(s.Filter), strings.TrimSpace(s.Q), strings.TrimSpace(s.Search)}
	return append(scoped, parts...)
}
