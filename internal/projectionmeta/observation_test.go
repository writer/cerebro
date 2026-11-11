package projectionmeta

import "testing"

func TestCompareObservations(t *testing.T) {
	strict := func(version, at string) map[string]string {
		return map[string]string{
			AttributeObservationPrecedence: ObservationPrecedenceStrict,
			AttributeObservationVersion:    version,
			AttributeObservedAt:            at,
		}
	}
	for _, tc := range []struct {
		name     string
		existing map[string]string
		incoming map[string]string
		want     ObservationOrder
	}{
		{name: "later at is newer", existing: map[string]string{"at": "2026-11-02T09:00:00Z"}, incoming: map[string]string{"at": "2026-11-02T10:00:00Z"}, want: ObservationNewer},
		{name: "earlier at is older", existing: map[string]string{"at": "2026-11-02T10:00:00Z"}, incoming: map[string]string{"at": "2026-11-02T09:00:00Z"}, want: ObservationOlder},
		{name: "sub-second at orders", existing: map[string]string{"at": "2026-11-02T10:00:00.100000Z"}, incoming: map[string]string{"at": "2026-11-02T10:00:00.200000Z"}, want: ObservationNewer},
		{name: "missing incoming at is older", existing: map[string]string{"at": "2026-11-02T10:00:00Z"}, incoming: map[string]string{}, want: ObservationOlder},
		{name: "missing stored at is unordered", existing: map[string]string{}, incoming: map[string]string{"at": "2026-11-02T10:00:00Z"}, want: ObservationUnordered},
		{name: "unparseable at is unordered", existing: map[string]string{"at": "yesterday"}, incoming: map[string]string{"at": "2026-11-02T10:00:00Z"}, want: ObservationUnordered},
		{name: "strict higher version beats an earlier at", existing: strict("2", "2026-11-02T10:00:01Z"), incoming: strict("3", "2026-11-02T10:00:00Z"), want: ObservationNewer},
		{name: "strict lower version loses to an earlier stored at", existing: strict("3", "2026-11-02T10:00:00Z"), incoming: strict("2", "2026-11-02T10:00:01Z"), want: ObservationOlder},
		{name: "strict missing incoming version is older", existing: strict("3", "2026-11-02T10:00:00Z"), incoming: strict("", "2026-11-02T11:00:00Z"), want: ObservationOlder},
		{name: "strict equal versions defer to at", existing: strict("3", "2026-11-02T10:00:00Z"), incoming: strict("3", "2026-11-02T10:01:00Z"), want: ObservationNewer},
		{name: "strict unparseable incoming version defers to at", existing: strict("3", "2026-11-02T10:00:00Z"), incoming: strict("v2", "2026-11-02T09:00:00Z"), want: ObservationOlder},
		{name: "strict unversioned stored entity orders by at", existing: strict("", "2026-11-02T10:00:00Z"), incoming: strict("2", "2026-11-02T09:00:00Z"), want: ObservationOlder},
		{
			name:     "versions are ignored without strict precedence",
			existing: map[string]string{AttributeObservationVersion: "2", "at": "2026-11-02T10:00:01Z"},
			incoming: map[string]string{AttributeObservationVersion: "3", "at": "2026-11-02T10:00:00Z"},
			want:     ObservationOlder,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareObservations(tc.existing, tc.incoming); got != tc.want {
				t.Fatalf("CompareObservations() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStaleStrictObservation(t *testing.T) {
	older := map[string]string{"at": "2026-11-02T09:00:00Z"}
	newer := map[string]string{"at": "2026-11-02T10:00:00Z"}
	strict := func(attributes map[string]string) map[string]string {
		return map[string]string{"at": attributes["at"], AttributeObservationPrecedence: ObservationPrecedenceStrict}
	}
	if !StaleStrictObservation(strict(newer), strict(older)) {
		t.Fatal("an older strict observation must be stale")
	}
	if !StaleStrictObservation(newer, strict(older)) {
		t.Fatal("an incoming strict opt-in must apply to a stored entity that predates it")
	}
	if StaleStrictObservation(newer, older) {
		t.Fatal("an older observation without strict precedence must still merge")
	}
	if StaleStrictObservation(strict(older), strict(newer)) || StaleStrictObservation(strict(newer), strict(newer)) {
		t.Fatal("a newer or equal strict observation must not be stale")
	}
}
