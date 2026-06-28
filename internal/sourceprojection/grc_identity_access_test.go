package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectGRCIntegrationTagsResourceKinds(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-integration-aws",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.integration",
		Attributes: map[string]string{
			"provider":       "vanta",
			"integration_id": "aws",
			"display_name":   "AWS",
			"resource_kinds": "AwsAccountMetadata,CloudTrail",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	sourceURN := "urn:cerebro:writer:source:vanta:integration:aws"
	accountMetadataURN := "urn:cerebro:writer:asset_tag:grc_resource_kind:awsaccountmetadata"
	cloudTrailURN := "urn:cerebro:writer:asset_tag:grc_resource_kind:cloudtrail"
	assertProjectedLink(t, state, sourceURN, relationTaggedAs, accountMetadataURN)
	assertProjectedLink(t, state, sourceURN, relationTaggedAs, cloudTrailURN)
}

func TestProjectGRCRiskScenarioOwnerDoesNotCreatePersonIdentityBridge(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-risk-risk-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.risk_scenario",
		Attributes: map[string]string{
			"provider":            "vanta",
			"risk_id":             "risk-1",
			"description":         "AI vendor risk",
			"owner":               "alice@writer.com",
			"policy_id":           "vendor-risk",
			"document_id":         "risk-register",
			"document_type":       "risk_register",
			"control_ids":         "VR-1",
			"residual_risk_level": "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	riskURN := "urn:cerebro:writer:claim:vanta:risk_scenario:risk-1"
	contactURN := "urn:cerebro:writer:contact:vanta:owner:alice@writer.com"
	policyURN := "urn:cerebro:writer:policy:vanta:policy:vendor-risk"
	documentURN := "urn:cerebro:writer:document:vanta:risk-register"
	controlURN := "urn:cerebro:writer:policy:vanta:control:VR-1"
	personURN := "urn:cerebro:writer:person:vanta:owner:alice@writer.com"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	assertProjectedLink(t, state, riskURN, relationAssignedTo, contactURN)
	assertProjectedLink(t, state, riskURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, riskURN, relationHasEvidence, documentURN)
	assertProjectedLink(t, state, riskURN, relationAssociatedWith, controlURN)
	if _, ok := state.entities[personURN]; ok {
		t.Fatalf("risk owner projected as GRC person: %#v", state.entities[personURN])
	}
	assertProjectedLinkMissing(t, state, contactURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, contactURN, relationAssociatedWith, identityURN)
}

func TestProjectGRCPersonIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-person-person-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.person",
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	if entity := state.entities[personURN]; entity == nil || entity.EntityType != "person" {
		t.Fatalf("person entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, personURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, personURN, relationSameActor, "urn:cerebro:writer:identity:email:alice@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:identity:email:alice@writer.com", relationSameActor, personURN)
}

func TestProjectGRCPersonAndUserSameActorByEmail(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "grc-person-person-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.person",
			Attributes: map[string]string{
				"provider":  "vanta",
				"person_id": "person-1",
				"email":     "alice@writer.com",
			},
		},
		{
			Id:       "grc-user-user-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.user",
			Attributes: map[string]string{
				"provider": "vanta",
				"user_id":  "user-1",
				"email":    "alice@writer.com",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	userURN := "urn:cerebro:writer:user:vanta:user-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	assertProjectedLink(t, state, personURN, relationSameActor, identityURN)
	assertProjectedLink(t, state, userURN, relationSameActor, identityURN)
	assertProjectedLink(t, state, identityURN, relationSameActor, personURN)
	assertProjectedLink(t, state, identityURN, relationSameActor, userURN)
}

func TestProjectGRCPersonStampsIdentifierLinksWithObservationTime(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	historicalEmploymentDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "grc-person-person-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.person",
		OccurredAt: timestamppb.New(historicalEmploymentDate),
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	link, ok := state.links[personURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", personURN, identityURN, state.links)
	}
	stamped, err := time.Parse(time.RFC3339, link.Attributes["at"])
	if err != nil {
		t.Fatalf("represents_identity at = %q is not RFC3339: %v", link.Attributes["at"], err)
	}
	if stamped.Equal(historicalEmploymentDate) {
		t.Fatalf("represents_identity at = %q, want projection observation time", link.Attributes["at"])
	}
	if stamped.Before(before.Add(-time.Second)) || stamped.After(after.Add(time.Second)) {
		t.Fatalf("represents_identity at = %v not within projection window [%v, %v]", stamped, before, after)
	}
}
