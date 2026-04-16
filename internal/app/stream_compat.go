package app

import appstream "github.com/writer/cerebro/internal/app/stream"

var (
	cloudEventType                  = appstream.CloudEventType
	parseTapType                    = appstream.ParseTapType
	parseTapInteractionType         = appstream.ParseTapInteractionType
	parseTapInteractionParticipants = appstream.ParseTapInteractionParticipants
	buildTapBusinessEventPlan       = appstream.BuildTapBusinessEventPlan
	buildTapInteractionEventPlan    = appstream.BuildTapInteractionEventPlan
	buildTapActivityEventPlan       = appstream.BuildTapActivityEventPlan
	deriveComputedFields            = appstream.DeriveComputedFields
	deriveTapActivityNodeKind       = appstream.DeriveTapActivityNodeKind
	inferTapActivityStatus          = appstream.InferTapActivityStatus
	extractBusinessEdges            = appstream.ExtractBusinessEdges
	isTapSchemaEventType            = appstream.IsTapSchemaEventType
	parseTapSchemaEntities          = appstream.ParseTapSchemaEntities
	parseTapSchemaIntegration       = appstream.ParseTapSchemaIntegration
	firstPresent                    = appstream.FirstPresent
	mapFromAny                      = appstream.MapFromAny
	parseTimeValue                  = appstream.ParseTimeValue
	anyToString                     = appstream.AnyToString
	toInt                           = appstream.ToInt
)
