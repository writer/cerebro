package graphingest

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
)

// RunMessages maps durable ingest runs to their API representation.
func RunMessages(runs []graphstore.IngestRun) []*cerebrov1.GraphIngestRun {
	messages := make([]*cerebrov1.GraphIngestRun, 0, len(runs))
	for _, run := range runs {
		messages = append(messages, RunMessage(run))
	}
	return messages
}

// RunMessage maps one durable ingest run to its API representation.
func RunMessage(run graphstore.IngestRun) *cerebrov1.GraphIngestRun {
	return &cerebrov1.GraphIngestRun{
		Id: run.ID, RuntimeId: run.RuntimeID, SourceId: run.SourceID, TenantId: run.TenantID,
		CheckpointId: run.CheckpointID, CheckpointCursor: run.CheckpointCursor, CheckpointComplete: run.CheckpointCompleteValue(),
		Status: run.Status, Trigger: run.Trigger, PagesRead: run.PagesRead, EventsRead: run.EventsRead,
		EntitiesProjected: run.EntitiesProjected, LinksProjected: run.LinksProjected,
		GraphNodesBefore: run.GraphNodesBefore, GraphLinksBefore: run.GraphLinksBefore,
		GraphNodesAfter: run.GraphNodesAfter, GraphLinksAfter: run.GraphLinksAfter,
		StartedAt: run.StartedAt, FinishedAt: run.FinishedAt, Error: run.Error,
	}
}
