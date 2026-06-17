package cerebroapi

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/sdk/go/cerebroapi/genproto/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WriteProtoClaimsRequest struct {
	RuntimeID       string
	Claims          []*cerebrov1.Claim
	ReplaceExisting bool
}

type ListProtoClaimsResponse struct {
	Claims []*cerebrov1.Claim
}

func (c *Client) ListProtoClaims(ctx context.Context, request ListClaimsRequest) (*ListProtoClaimsResponse, error) {
	response, err := c.ListClaims(ctx, request)
	if err != nil {
		return nil, err
	}
	return &ListProtoClaimsResponse{
		Claims: ClaimsToProto(response.Claims),
	}, nil
}

func (c *Client) WriteProtoClaims(ctx context.Context, request WriteProtoClaimsRequest) (*WriteClaimsResponse, error) {
	return c.WriteClaims(ctx, WriteClaimsRequest{
		RuntimeID:       request.RuntimeID,
		Claims:          ClaimsFromProto(request.Claims),
		ReplaceExisting: request.ReplaceExisting,
	})
}

func ClaimToProto(claim Claim) *cerebrov1.Claim {
	return &cerebrov1.Claim{
		Id:            claim.ID,
		SubjectUrn:    claim.SubjectURN,
		SubjectRef:    EntityRefToProto(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectUrn:     claim.ObjectURN,
		ObjectRef:     OptionalEntityRefToProto(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventId: claim.SourceEventID,
		ObservedAt:    timestampFromRFC3339(claim.ObservedAt),
		ValidFrom:     timestampFromRFC3339(claim.ValidFrom),
		ValidTo:       timestampFromRFC3339(claim.ValidTo),
		Attributes:    compactAttributes(claim.Attributes),
	}
}

func ClaimsToProto(claims []Claim) []*cerebrov1.Claim {
	out := make([]*cerebrov1.Claim, 0, len(claims))
	for _, claim := range claims {
		out = append(out, ClaimToProto(claim))
	}
	return out
}

func ClaimFromProto(claim *cerebrov1.Claim) Claim {
	if claim == nil {
		return Claim{}
	}
	return Claim{
		ID:            claim.GetId(),
		SubjectURN:    claim.GetSubjectUrn(),
		SubjectRef:    EntityRefFromProto(claim.GetSubjectRef()),
		Predicate:     claim.GetPredicate(),
		ObjectURN:     claim.GetObjectUrn(),
		ObjectRef:     OptionalEntityRefFromProto(claim.GetObjectRef()),
		ObjectValue:   claim.GetObjectValue(),
		ClaimType:     claim.GetClaimType(),
		Status:        claim.GetStatus(),
		SourceEventID: claim.GetSourceEventId(),
		ObservedAt:    timestampToRFC3339(claim.GetObservedAt()),
		ValidFrom:     timestampToRFC3339(claim.GetValidFrom()),
		ValidTo:       timestampToRFC3339(claim.GetValidTo()),
		Attributes:    copyAttributes(claim.GetAttributes()),
	}
}

func ClaimsFromProto(claims []*cerebrov1.Claim) []Claim {
	out := make([]Claim, 0, len(claims))
	for _, claim := range claims {
		out = append(out, ClaimFromProto(claim))
	}
	return out
}

func EntityRefToProto(ref EntityRef) *cerebrov1.EntityRef {
	if strings.TrimSpace(ref.URN) == "" &&
		strings.TrimSpace(ref.EntityType) == "" &&
		strings.TrimSpace(ref.Label) == "" {
		return nil
	}
	return &cerebrov1.EntityRef{
		Urn:        ref.URN,
		EntityType: ref.EntityType,
		Label:      ref.Label,
	}
}

func OptionalEntityRefToProto(ref *EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return EntityRefToProto(*ref)
}

func EntityRefFromProto(ref *cerebrov1.EntityRef) EntityRef {
	if ref == nil {
		return EntityRef{}
	}
	return EntityRef{
		URN:        ref.GetUrn(),
		EntityType: ref.GetEntityType(),
		Label:      ref.GetLabel(),
	}
}

func OptionalEntityRefFromProto(ref *cerebrov1.EntityRef) *EntityRef {
	if ref == nil {
		return nil
	}
	converted := EntityRefFromProto(ref)
	return &converted
}

func timestampFromRFC3339(value string) *timestamppb.Timestamp {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err != nil {
		return nil
	}
	return timestamppb.New(parsed)
}

func timestampToRFC3339(value *timestamppb.Timestamp) string {
	if value == nil || value.CheckValid() != nil {
		return ""
	}
	return value.AsTime().UTC().Format(time.RFC3339Nano)
}

func compactAttributes(attributes map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attributes {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out[key] = trimmed
		}
	}
	return out
}

func copyAttributes(attributes map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attributes {
		out[key] = value
	}
	return out
}
