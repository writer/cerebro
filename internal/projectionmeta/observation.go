package projectionmeta

import (
	"strconv"
	"strings"
	"time"
)

// Observation-ordering attributes of projected graph objects. Every writer
// that merges two observations of one object (the graph store, and graph
// ingest when it coalesces a page before writing) orders them through
// CompareObservations, so the two can never disagree about which
// observation is newer.
const (
	// AttributeObservedAt is the RFC3339 time of the observation an
	// object's time-coupled attributes describe.
	AttributeObservedAt = "at"
	// AttributeObservationPrecedence opts an entity into strict precedence
	// when set to ObservationPrecedenceStrict: an older incoming observation
	// then changes nothing on the stored entity, attributes and projection
	// metadata alike.
	AttributeObservationPrecedence = "observation_precedence"
	ObservationPrecedenceStrict    = "strict"
	// AttributeObservationVersion is a producer-assigned base-10 version
	// that increases with every write of one strict-precedence entity. It
	// orders observations whose producer timestamps need not follow commit
	// order, for example when a producer stamps its update time before a
	// conditional write that commits after a concurrent writer's.
	AttributeObservationVersion = "observation_version"
)

// ObservationOrder places an incoming observation relative to the stored
// observation of the same graph object.
type ObservationOrder int

const (
	// ObservationUnordered covers equal, absent, or unparseable ordering
	// attributes; merges then fall back to last-write-wins.
	ObservationUnordered ObservationOrder = iota
	// ObservationOlder means the incoming observation predates the stored one.
	ObservationOlder
	// ObservationNewer means the incoming observation supersedes the stored one.
	ObservationNewer
)

// CompareObservations orders incoming against existing. A strict-precedence
// entity whose stored observation carries an observation_version is ordered
// by version first: a higher incoming version is newer and a lower one
// older regardless of `at`, and an incoming observation without a version
// is older (present beats missing). Every other case is ordered by `at`: a
// later incoming time is newer, and an earlier or missing one is older
// while the stored time is set.
func CompareObservations(existing, incoming map[string]string) ObservationOrder {
	if strictObservationPrecedence(existing, incoming) {
		if order, decided := compareObservationVersions(existing, incoming); decided {
			return order
		}
	}
	return compareObservedAt(existing, incoming)
}

// StaleStrictObservation reports whether incoming is an older observation
// of a strict-precedence entity, which must leave the stored entity
// untouched.
func StaleStrictObservation(existing, incoming map[string]string) bool {
	return strictObservationPrecedence(existing, incoming) && CompareObservations(existing, incoming) == ObservationOlder
}

func strictObservationPrecedence(existing, incoming map[string]string) bool {
	return strings.TrimSpace(existing[AttributeObservationPrecedence]) == ObservationPrecedenceStrict ||
		strings.TrimSpace(incoming[AttributeObservationPrecedence]) == ObservationPrecedenceStrict
}

// compareObservationVersions decides only when the stored version parses
// and the incoming one is missing or parses to a different value; equal or
// unparseable versions defer to `at`.
func compareObservationVersions(existing, incoming map[string]string) (ObservationOrder, bool) {
	stored, ok := observationVersion(existing)
	if !ok {
		return ObservationUnordered, false
	}
	if strings.TrimSpace(incoming[AttributeObservationVersion]) == "" {
		return ObservationOlder, true
	}
	next, ok := observationVersion(incoming)
	switch {
	case !ok || next == stored:
		return ObservationUnordered, false
	case next < stored:
		return ObservationOlder, true
	default:
		return ObservationNewer, true
	}
}

func observationVersion(attributes map[string]string) (uint64, bool) {
	version, err := strconv.ParseUint(strings.TrimSpace(attributes[AttributeObservationVersion]), 10, 64)
	return version, err == nil
}

func compareObservedAt(existing, incoming map[string]string) ObservationOrder {
	existingAt := strings.TrimSpace(existing[AttributeObservedAt])
	if existingAt == "" {
		return ObservationUnordered
	}
	incomingAt := strings.TrimSpace(incoming[AttributeObservedAt])
	if incomingAt == "" {
		return ObservationOlder
	}
	existingTime, existingErr := time.Parse(time.RFC3339, existingAt)
	incomingTime, incomingErr := time.Parse(time.RFC3339, incomingAt)
	switch {
	case existingErr != nil || incomingErr != nil:
		return ObservationUnordered
	case incomingTime.Before(existingTime):
		return ObservationOlder
	case incomingTime.After(existingTime):
		return ObservationNewer
	default:
		return ObservationUnordered
	}
}
