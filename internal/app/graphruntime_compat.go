package app

import appgraphruntime "github.com/writer/cerebro/internal/app/graphruntime"

type GraphBuildState = appgraphruntime.GraphBuildState

const (
	GraphBuildNotStarted = appgraphruntime.GraphBuildNotStarted
	GraphBuildBuilding   = appgraphruntime.GraphBuildBuilding
	GraphBuildSuccess    = appgraphruntime.GraphBuildSuccess
	GraphBuildFailed     = appgraphruntime.GraphBuildFailed
)

type GraphBuildSnapshot = appgraphruntime.GraphBuildSnapshot
type RetentionStatus = appgraphruntime.RetentionStatus
type GraphFreshnessBreach = appgraphruntime.GraphFreshnessBreach
type GraphFreshnessStatus = appgraphruntime.GraphFreshnessStatus
