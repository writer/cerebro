package aurelius

import (
	"encoding/json"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const cursorSource = "aurelius/s3-ndjson/v1"

type aureliusCursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	LastKey             string `json:"last_key,omitempty"`
	PartialKey          string `json:"partial_key,omitempty"`
	RecordOffset        int    `json:"record_offset,omitempty"`
	Watermark           string `json:"watermark,omitempty"`
}

func decodeCursor(cursor *cerebrov1.SourceCursor) aureliusCursor {
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return aureliusCursor{}
	}
	var decoded aureliusCursor
	if err := json.Unmarshal([]byte(opaque), &decoded); err == nil && decoded.Source == cursorSource {
		decoded.LastKey = strings.TrimSpace(decoded.LastKey)
		decoded.PartialKey = strings.TrimSpace(decoded.PartialKey)
		decoded.Watermark = strings.TrimSpace(decoded.Watermark)
		if decoded.PartialKey == "" || decoded.RecordOffset < 0 {
			decoded.RecordOffset = 0
		}
		return decoded
	}
	return aureliusCursor{LastKey: opaque}
}

func encodeCursor(cursor aureliusCursor) string {
	cursor.Source = cursorSource
	cursor.ResumableCheckpoint = true
	cursor.LastKey = strings.TrimSpace(cursor.LastKey)
	cursor.PartialKey = strings.TrimSpace(cursor.PartialKey)
	cursor.Watermark = strings.TrimSpace(cursor.Watermark)
	if cursor.PartialKey == "" || cursor.RecordOffset < 0 {
		cursor.RecordOffset = 0
	}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return cursor.LastKey
	}
	return string(raw)
}

func cursorWatermark(cursor aureliusCursor) time.Time {
	if cursor.Watermark == "" {
		return time.Time{}
	}
	value, err := time.Parse(time.RFC3339Nano, cursor.Watermark)
	if err != nil {
		return time.Time{}
	}
	return value.UTC()
}

func isArchiveKey(key string) bool {
	switch {
	case strings.HasSuffix(key, ".ndjson"):
		return true
	case strings.HasSuffix(key, ".ndjson.gz"):
		return true
	}
	return false
}
