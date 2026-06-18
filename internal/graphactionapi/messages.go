package graphactionapi

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findingapi"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func InputFromRequest(request *cerebrov1.ExecuteGraphActionRequest) graphactions.Input {
	if request == nil {
		return graphactions.Input{}
	}
	return graphactions.Input{
		FindingID:      request.GetFindingId(),
		Action:         request.GetAction(),
		Target:         request.GetTarget(),
		Reason:         request.GetReason(),
		TicketURL:      request.GetTicketUrl(),
		IdempotencyKey: request.GetIdempotencyKey(),
	}
}

// ResponseMessage converts a graph action result into the public proto response.
func ResponseMessage(result *graphactions.Result, finding *cerebrov1.Finding) *cerebrov1.ExecuteGraphActionResponse {
	if result == nil {
		return &cerebrov1.ExecuteGraphActionResponse{}
	}
	return &cerebrov1.ExecuteGraphActionResponse{
		Finding:     finding,
		Action:      ActionMessage(result.Action),
		Target:      result.Target,
		ExternalRef: ExternalRefMessage(result.ExternalRef),
	}
}

// ActionMessage converts the domain action envelope into the public proto action.
func ActionMessage(action *graphactions.GraphAction) *cerebrov1.GraphAction {
	if action == nil {
		return nil
	}
	return &cerebrov1.GraphAction{
		Id:                   action.ID,
		Action:               action.Action,
		Provider:             action.Provider,
		Status:               action.Status,
		Target:               action.Target,
		ExternalId:           action.ExternalID,
		ExternalUrl:          action.ExternalURL,
		ExternalStatus:       action.ExternalStatus,
		ExternalStatusReason: action.ExternalStatusReason,
		Reason:               action.Reason,
		Source:               action.Source,
		TicketUrl:            action.TicketURL,
		IdempotencyKey:       action.IdempotencyKey,
		ActorType:            action.ActorType,
		ActorSubject:         action.ActorSubject,
		CreatedAt:            unixTimestamp(action.CreatedAtUnix),
		UpdatedAt:            unixTimestamp(action.UpdatedAtUnix),
		CompletedAt:          unixTimestamp(action.CompletedAtUnix),
		LastError:            action.LastError,
		Metadata:             action.Metadata,
	}
}

func ExternalRefMessage(ref ports.FindingExternalRef) *cerebrov1.FindingExternalRef {
	refs := findingapi.ExternalRefMessages([]ports.FindingExternalRef{ref})
	if len(refs) == 0 {
		return nil
	}
	return refs[0]
}

func unixTimestamp(seconds int64) *timestamppb.Timestamp {
	if seconds <= 0 {
		return nil
	}
	return timestamppb.New(time.Unix(seconds, 0).UTC())
}
