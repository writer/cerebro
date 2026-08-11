package aiegresspolicy

import (
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateAllowsExactApprovedDestination(t *testing.T) {
	input := policyInput()
	decision, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	if decision.GetAction() != cerebrov1.AIEgressAction_AI_EGRESS_ACTION_ALLOW ||
		decision.GetReason() != cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_APPROVED_DESTINATION ||
		decision.GetMatchedEntryId() != "approved-api" || decision.GetCanonicalHostname() != "api.example.test" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestEvaluateFailsClosed(t *testing.T) {
	tests := map[string]struct {
		mutate func(*cerebrov1.AIEgressPolicyInput)
		reason cerebrov1.AIEgressDecisionReason
	}{
		"unavailable registry": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) { input.Registry = nil },
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_UNAVAILABLE,
		},
		"stale registry": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) {
				input.EvaluatedAt = timestamppb.New(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))
			},
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_STALE,
		},
		"not yet published registry": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) {
				input.EvaluatedAt = timestamppb.New(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC))
			},
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_STALE,
		},
		"disabled registry": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) {
				input.Registry.Mode = cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_DISABLED
			},
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_DISABLED,
		},
		"disabled enforcement": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) { input.EnforcementEnabled = false },
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_ENFORCEMENT_DISABLED,
		},
		"unapproved destination": {
			mutate: func(input *cerebrov1.AIEgressPolicyInput) { input.Destination.Hostname = "other.example.test" },
			reason: cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_DESTINATION_NOT_APPROVED,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			input := policyInput()
			test.mutate(input)
			decision, err := Evaluate(input)
			if err != nil {
				t.Fatal(err)
			}
			if decision.GetAction() != cerebrov1.AIEgressAction_AI_EGRESS_ACTION_BLOCK || decision.GetReason() != test.reason {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestEvaluateAuditModeNeverRepresentsUnapprovedAsAllowed(t *testing.T) {
	input := policyInput()
	input.Registry.Mode = cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_AUDIT
	input.Destination.Port = 8443
	decision, err := Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}
	if decision.GetAction() != cerebrov1.AIEgressAction_AI_EGRESS_ACTION_AUDIT || decision.GetReason() != cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_PORT_NOT_APPROVED {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestEvaluateRejectsAllowByDefaultAndWildcardHostnames(t *testing.T) {
	input := policyInput()
	input.Registry.DefaultAction = cerebrov1.AIEgressAction_AI_EGRESS_ACTION_ALLOW
	_, err := Evaluate(input)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v", err)
	}
	input = policyInput()
	input.Registry.Entries[0].ExactHostnames = []string{"*.example.test"}
	_, err = Evaluate(input)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v", err)
	}
}

func TestEvaluateRejectsIncompleteEnforcementIdentity(t *testing.T) {
	tests := map[string]func(*cerebrov1.AIEgressPolicyInput){
		"missing tenant":  func(input *cerebrov1.AIEgressPolicyInput) { input.TenantId = "" },
		"missing subject": func(input *cerebrov1.AIEgressPolicyInput) { input.SubjectRef = nil },
		"missing port":    func(input *cerebrov1.AIEgressPolicyInput) { input.Destination.Port = 0 },
		"unspecified transport": func(input *cerebrov1.AIEgressPolicyInput) {
			input.Destination.Transport = cerebrov1.AIEgressTransport_AI_EGRESS_TRANSPORT_UNSPECIFIED
		},
		"unspecified enforcement": func(input *cerebrov1.AIEgressPolicyInput) {
			input.EnforcementLayer = cerebrov1.AIEgressEnforcementLayer_AI_EGRESS_ENFORCEMENT_LAYER_UNSPECIFIED
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := policyInput()
			mutate(input)
			_, err := Evaluate(input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func policyInput() *cerebrov1.AIEgressPolicyInput {
	evaluatedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	return &cerebrov1.AIEgressPolicyInput{
		TenantId:           "tenant",
		SubjectRef:         &cerebrov1.ResourceRef{Kind: "device", Id: "urn:cerebro:tenant:device:one"},
		ActorRef:           &cerebrov1.ResourceRef{Kind: "identity", Id: "urn:cerebro:tenant:identity:one"},
		Destination:        &cerebrov1.AIEgressDestination{Hostname: "API.Example.Test.", Port: 443, Transport: cerebrov1.AIEgressTransport_AI_EGRESS_TRANSPORT_HTTPS},
		EvaluatedAt:        timestamppb.New(evaluatedAt),
		EnforcementLayer:   cerebrov1.AIEgressEnforcementLayer_AI_EGRESS_ENFORCEMENT_LAYER_HOST,
		EnforcementEnabled: true,
		Registry: &cerebrov1.AIEgressRegistrySnapshot{
			RegistryId:    "registry",
			Revision:      "revision-1",
			Digest:        "sha256:registry",
			Mode:          cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_ENFORCE,
			DefaultAction: cerebrov1.AIEgressAction_AI_EGRESS_ACTION_BLOCK,
			PublishedAt:   timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ValidUntil:    timestamppb.New(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)),
			Entries: []*cerebrov1.AIEgressRegistryEntry{{
				Id: "approved-api", ExactHostnames: []string{"api.example.test"}, Ports: []uint32{443},
				Transports: []cerebrov1.AIEgressTransport{cerebrov1.AIEgressTransport_AI_EGRESS_TRANSPORT_HTTPS}, Enabled: true,
			}},
		},
	}
}
