package okta

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/oktaasset"
)

const familyThreatInsight = "threat_insight"

type threatInsightRecord struct {
	Action       string   `json:"action"`
	ExcludeZones []string `json:"excludeZones"`
	Created      string   `json:"created"`
	LastUpdated  string   `json:"lastUpdated"`
}

func (s *Source) threatInsightFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyThreatInsight,
		Check: func(ctx context.Context, settings settings) error {
			var record threatInsightRecord
			if err := s.getJSONWithRetry(ctx, settings, "/api/v1/threats/configuration", nil, &record, nil); err != nil {
				return wrapLookupError(oktaLabel("okta threat insight", settings), err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:threat_insight:config", settings.domain))
			if err != nil {
				return nil, err
			}
			return []sourcecdk.URN{urn}, nil
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			var record threatInsightRecord
			if err := s.getJSONWithRetry(ctx, settings, "/api/v1/threats/configuration", nil, &record, nil); err != nil {
				return sourcecdk.Pull{}, wrapLookupError(oktaLabel("okta threat insight", settings), err)
			}
			occurredAt := firstRecordTime(oktaasset.ParseTime(record.LastUpdated), oktaasset.ParseTime(record.Created))
			payload, err := json.Marshal(map[string]any{
				"domain":        settings.domain,
				"action":        record.Action,
				"exclude_zones": record.ExcludeZones,
			})
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("marshal okta threat insight payload: %w", err)
			}
			event := &primitives.Event{
				Id:         fmt.Sprintf("okta-threat-insight-%s-%d", settings.domain, occurredAt.UnixMilli()),
				TenantId:   settings.domain,
				SourceId:   "okta",
				Kind:       "okta.threat_insight",
				OccurredAt: timestamppb.New(occurredAt),
				SchemaRef:  "okta/threat_insight/v1",
				Payload:    payload,
				Attributes: map[string]string{
					"action":             record.Action,
					"domain":             settings.domain,
					"exclude_zone_count": fmt.Sprintf("%d", len(record.ExcludeZones)),
					"family":             familyThreatInsight,
					"resource_id":        "threat_insight_config",
					"resource_type":      "ThreatInsightConfiguration",
				},
			}
			return sourcecdk.Pull{
				Events: []*primitives.Event{event},
				Checkpoint: &cerebrov1.SourceCheckpoint{
					Watermark: event.OccurredAt,
				},
			}, nil
		},
	}
}
