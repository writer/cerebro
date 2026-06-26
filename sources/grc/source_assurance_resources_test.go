package grc

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestReadAssuranceResourceFamiliesAsCanonicalGRCEvents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true

	cases := []struct {
		family string
		kind   string
		attrs  map[string]string
	}{
		{
			family: familyRegulatoryNotification,
			kind:   "grc.regulatory_notification",
			attrs: map[string]string{
				"notification_id":   "notification-1",
				"incident_id":       "incident-1",
				"notification_type": "initial",
				"control_ids":       "dora-art-19",
			},
		},
		{
			family: familyRecoveryObjective,
			kind:   "grc.recovery_objective",
			attrs: map[string]string{
				"recovery_objective_id": "objective-1",
				"service_id":            "payments-api",
				"business_process":      "Payment Processing",
				"rto_minutes":           "60",
			},
		},
		{
			family: familyAuthorizationPackage,
			kind:   "grc.authorization_package",
			attrs: map[string]string{
				"authorization_package_id": "ato-1",
				"framework":                "FedRAMP Rev. 5",
				"impact_level":             "Moderate",
				"system_id":                "writer-cloud",
			},
		},
		{
			family: familyPOAMItem,
			kind:   "grc.poam_item",
			attrs: map[string]string{
				"poam_item_id": "poam-1",
				"finding_id":   "finding-1",
				"risk_rating":  "high",
				"target_id":    "aws-prod",
			},
		},
		{
			family: familyTrainingAttestation,
			kind:   "grc.training_attestation",
			attrs: map[string]string{
				"attestation_id": "attestation-1",
				"person_id":      "person-1",
				"user_id":        "user-1",
				"completed_at":   "2026-06-01T00:00:00Z",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), testConfig(server.URL, tc.family), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tc.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tc.family, len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("event.Kind = %q, want %s", event.Kind, tc.kind)
			}
			for key, want := range tc.attrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("event.Attributes[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}
