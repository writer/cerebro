package cerebroapi

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/sdk/go/cerebroapi/genproto/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClaimProtoRoundTripPreservesCerebroContract(t *testing.T) {
	observed := time.Date(2026, 6, 17, 4, 0, 1, 2, time.UTC).Format(time.RFC3339Nano)
	validFrom := time.Date(2026, 6, 17, 4, 0, 2, 3, time.UTC).Format(time.RFC3339Nano)
	validTo := time.Date(2026, 6, 17, 4, 0, 3, 4, time.UTC).Format(time.RFC3339Nano)
	claim := Claim{
		ID:         "claim-1",
		SubjectURN: "urn:cerebro:tenant-a:runtime:runtime-a:finding:finding-a",
		SubjectRef: EntityRef{
			URN:        "urn:cerebro:tenant-a:runtime:runtime-a:finding:finding-a",
			EntityType: "finding",
			Label:      "Finding A",
		},
		Predicate: "affects",
		ObjectURN: "urn:cerebro:tenant-a:runtime:runtime-a:asset:drive",
		ObjectRef: &EntityRef{
			URN:        "urn:cerebro:tenant-a:runtime:runtime-a:asset:drive",
			EntityType: "asset",
			Label:      "Drive",
		},
		ClaimType:     "relation",
		Status:        "asserted",
		SourceEventID: "evt-1",
		ObservedAt:    observed,
		ValidFrom:     validFrom,
		ValidTo:       validTo,
		Attributes: map[string]string{
			"source": "  aperio  ",
			"empty":  "  ",
		},
	}

	protoClaim := ClaimToProto(claim)
	if protoClaim.ProtoReflect().Descriptor().FullName() != "cerebro.v1.Claim" {
		t.Fatalf("proto claim descriptor = %s", protoClaim.ProtoReflect().Descriptor().FullName())
	}
	if protoClaim.GetSubjectRef().GetEntityType() != "finding" || protoClaim.GetObjectRef().GetLabel() != "Drive" {
		t.Fatalf("proto claim refs = %#v %#v", protoClaim.GetSubjectRef(), protoClaim.GetObjectRef())
	}
	if protoClaim.GetAttributes()["source"] != "aperio" {
		t.Fatalf("proto attributes = %#v", protoClaim.GetAttributes())
	}
	if _, ok := protoClaim.GetAttributes()["empty"]; ok {
		t.Fatalf("blank attribute value was retained: %#v", protoClaim.GetAttributes())
	}
	if protoClaim.GetObservedAt() == nil || protoClaim.GetValidFrom() == nil || protoClaim.GetValidTo() == nil {
		t.Fatalf("expected all claim timestamps: %#v", protoClaim)
	}

	roundTrip := ClaimFromProto(protoClaim)
	if roundTrip.SubjectURN != claim.SubjectURN ||
		roundTrip.SubjectRef.EntityType != "finding" ||
		roundTrip.ObjectRef == nil ||
		roundTrip.ObjectRef.URN != claim.ObjectURN ||
		roundTrip.ObservedAt != observed ||
		roundTrip.ValidFrom != validFrom ||
		roundTrip.ValidTo != validTo ||
		roundTrip.Attributes["source"] != "aperio" {
		t.Fatalf("round trip claim = %#v", roundTrip)
	}
}

func TestClaimFromProtoHandlesNilOptionalFields(t *testing.T) {
	claim := ClaimFromProto(&cerebrov1.Claim{
		SubjectUrn: "urn:cerebro:tenant-a:runtime:runtime-a:finding:finding-a",
		ObservedAt: timestamppb.New(
			time.Date(2026, 6, 17, 4, 0, 0, 0, time.FixedZone("offset", -7*60*60)),
		),
	})

	if claim.ObjectRef != nil {
		t.Fatalf("object ref = %#v, want nil", claim.ObjectRef)
	}
	if claim.ObservedAt != "2026-06-17T11:00:00Z" {
		t.Fatalf("observed at = %q", claim.ObservedAt)
	}
}

func TestEntityRefToProtoReturnsNilForEmptyRef(t *testing.T) {
	if ref := EntityRefToProto(EntityRef{}); ref != nil {
		t.Fatalf("empty entity ref = %#v, want nil", ref)
	}
	if ref := OptionalEntityRefToProto(nil); ref != nil {
		t.Fatalf("nil optional entity ref = %#v, want nil", ref)
	}
}

func TestClaimsProtoHelpersPreserveOrder(t *testing.T) {
	claims := []Claim{{ID: "claim-1"}, {ID: "claim-2"}}
	protoClaims := ClaimsToProto(claims)
	if len(protoClaims) != 2 || protoClaims[0].GetId() != "claim-1" || protoClaims[1].GetId() != "claim-2" {
		t.Fatalf("proto claims = %#v", protoClaims)
	}

	roundTrip := ClaimsFromProto(protoClaims)
	if len(roundTrip) != 2 || roundTrip[0].ID != "claim-1" || roundTrip[1].ID != "claim-2" {
		t.Fatalf("round trip claims = %#v", roundTrip)
	}
}
