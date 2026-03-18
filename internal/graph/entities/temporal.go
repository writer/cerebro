package entities

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

type (
	EntityTimeReconstruction = graph.EntityTimeReconstruction
	EntityTimeRecord         = graph.EntityTimeRecord
	EntityPropertyDiff       = graph.EntityPropertyDiff
	EntityTimeDiffRecord     = graph.EntityTimeDiffRecord
)

func GetEntityRecordAtTime(g *graph.Graph, id string, asOf, recordedAt time.Time) (EntityTimeRecord, bool) {
	return graph.GetEntityRecordAtTime(g, id, asOf, recordedAt)
}

func GetEntityTimeDiff(g *graph.Graph, id string, from, to, recordedAt time.Time) (EntityTimeDiffRecord, bool) {
	return graph.GetEntityTimeDiff(g, id, from, to, recordedAt)
}
