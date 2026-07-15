package grcfindings

import (
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ConnectorItem struct {
	RuntimeID           string     `json:"runtime_id"`
	SourceID            string     `json:"source_id,omitempty"`
	TenantID            string     `json:"tenant_id,omitempty"`
	Status              string     `json:"status"`
	Freshness           string     `json:"freshness"`
	SyncLagSeconds      *int64     `json:"sync_lag_seconds,omitempty"`
	CheckpointWatermark *time.Time `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds *int64     `json:"watermark_lag_seconds,omitempty"`
	WatermarkFreshness  string     `json:"watermark_freshness,omitempty"`
	LastSyncedAt        *time.Time `json:"last_synced_at,omitempty"`
}

func ConnectorItems(runtimes []*cerebrov1.SourceRuntime) []ConnectorItem {
	items := make([]ConnectorItem, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		lastSyncedAt := protobufTime(runtime.GetLastSyncedAt())
		checkpointWatermark := protobufTime(runtime.GetCheckpoint().GetWatermark())
		items = append(items, ConnectorItem{
			RuntimeID:           runtime.GetId(),
			SourceID:            runtime.GetSourceId(),
			TenantID:            runtime.GetTenantId(),
			Status:              ConnectorStatus(lastSyncedAt),
			Freshness:           ConnectorFreshness(lastSyncedAt),
			SyncLagSeconds:      lagSeconds(lastSyncedAt),
			CheckpointWatermark: checkpointWatermark,
			WatermarkLagSeconds: lagSeconds(checkpointWatermark),
			WatermarkFreshness:  ConnectorFreshness(checkpointWatermark),
			LastSyncedAt:        lastSyncedAt,
		})
	}
	return items
}

func protobufTime(value *timestamppb.Timestamp) *time.Time {
	if value == nil || !value.IsValid() {
		return nil
	}
	result := value.AsTime().UTC()
	return &result
}

func lagSeconds(value *time.Time) *int64 {
	if value == nil {
		return nil
	}
	lag := time.Since(*value)
	if lag < 0 {
		lag = 0
	}
	seconds := int64(lag.Seconds())
	return &seconds
}
