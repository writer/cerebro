package awsvpcflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/runtime/adapters"
)

const SourceName = "aws_vpc_flow_logs"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type cloudWatchEnvelope struct {
	Owner       string               `json:"owner"`
	LogGroup    string               `json:"logGroup"`
	LogStream   string               `json:"logStream"`
	MessageType string               `json:"messageType"`
	LogEvents   []cloudWatchLogEvent `json:"logEvents"`
}

type cloudWatchLogEvent struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
}

func (Adapter) Source() string {
	return SourceName
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if observations, ok, err := normalizeCloudWatchEnvelope(trimmed); ok {
		return observations, err
	}
	return normalizePlaintext(trimmed)
}

func normalizeCloudWatchEnvelope(raw []byte) ([]*runtime.RuntimeObservation, bool, error) {
	var envelope cloudWatchEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, false, nil
	}
	if len(envelope.LogEvents) == 0 && strings.TrimSpace(envelope.MessageType) == "" && strings.TrimSpace(envelope.Owner) == "" && strings.TrimSpace(envelope.LogGroup) == "" && strings.TrimSpace(envelope.LogStream) == "" {
		return nil, false, nil
	}
	if strings.EqualFold(strings.TrimSpace(envelope.MessageType), "CONTROL_MESSAGE") {
		return nil, true, nil
	}

	observations := make([]*runtime.RuntimeObservation, 0, len(envelope.LogEvents))
	for idx, event := range envelope.LogEvents {
		observation, err := observationFromLine(strings.TrimSpace(event.Message), lineContext{
			eventID:    strings.TrimSpace(event.ID),
			recordedAt: unixMillisTime(event.Timestamp),
			accountID:  strings.TrimSpace(envelope.Owner),
			logGroup:   strings.TrimSpace(envelope.LogGroup),
			logStream:  strings.TrimSpace(envelope.LogStream),
			lineNumber: idx + 1,
			wrapped:    true,
		})
		if err != nil {
			return nil, true, fmt.Errorf("decode aws vpc flow log payload: line %d: %w", idx+1, err)
		}
		if observation != nil {
			observations = append(observations, observation)
		}
	}
	return observations, true, nil
}

func normalizePlaintext(raw []byte) ([]*runtime.RuntimeObservation, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	observations := make([]*runtime.RuntimeObservation, 0, len(lines))
	for idx, line := range lines {
		observation, err := observationFromLine(strings.TrimSpace(line), lineContext{lineNumber: idx + 1})
		if err != nil {
			return nil, fmt.Errorf("decode aws vpc flow log payload: line %d: %w", idx+1, err)
		}
		if observation != nil {
			observations = append(observations, observation)
		}
	}
	return observations, nil
}

type lineContext struct {
	eventID    string
	recordedAt time.Time
	accountID  string
	logGroup   string
	logStream  string
	lineNumber int
	wrapped    bool
}

func observationFromLine(line string, ctx lineContext) (*runtime.RuntimeObservation, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	fields := strings.Fields(line)
	if len(fields) != 14 {
		return nil, fmt.Errorf("expected 14 default-format fields, got %d", len(fields))
	}

	version := normalizeField(fields[0])
	accountID := firstNonEmpty(normalizeField(fields[1]), ctx.accountID)
	interfaceID := normalizeField(fields[2])
	srcIP := normalizeField(fields[3])
	dstIP := normalizeField(fields[4])
	srcPort, err := parseOptionalInt(fields[5])
	if err != nil {
		return nil, fmt.Errorf("parse srcport: %w", err)
	}
	dstPort, err := parseOptionalInt(fields[6])
	if err != nil {
		return nil, fmt.Errorf("parse dstport: %w", err)
	}
	protocol := protocolName(normalizeField(fields[7]))
	packets, err := parseOptionalInt64(fields[8])
	if err != nil {
		return nil, fmt.Errorf("parse packets: %w", err)
	}
	byteCount, err := parseOptionalInt64(fields[9])
	if err != nil {
		return nil, fmt.Errorf("parse bytes: %w", err)
	}
	startUnix, err := parseOptionalInt64(fields[10])
	if err != nil {
		return nil, fmt.Errorf("parse start: %w", err)
	}
	endUnix, err := parseOptionalInt64(fields[11])
	if err != nil {
		return nil, fmt.Errorf("parse end: %w", err)
	}
	action := strings.ToUpper(normalizeField(fields[12]))
	logStatus := strings.ToUpper(normalizeField(fields[13]))

	observedAt := unixSecondsTime(endUnix)
	if observedAt.IsZero() {
		observedAt = unixSecondsTime(startUnix)
	}
	if observedAt.IsZero() && !ctx.recordedAt.IsZero() {
		observedAt = ctx.recordedAt
	}

	metadata := map[string]any{
		"version":      version,
		"account_id":   accountID,
		"interface_id": interfaceID,
		"action":       action,
		"log_status":   logStatus,
		"packets":      packets,
		"bytes":        byteCount,
	}
	if startUnix > 0 {
		metadata["flow_start_unix"] = startUnix
	}
	if endUnix > 0 {
		metadata["flow_end_unix"] = endUnix
	}
	if ctx.logGroup != "" {
		metadata["cloudwatch_log_group"] = ctx.logGroup
	}
	if ctx.logStream != "" {
		metadata["cloudwatch_log_stream"] = ctx.logStream
	}

	observation := &runtime.RuntimeObservation{
		ID:           observationID(line, ctx.eventID),
		Kind:         runtime.ObservationKindNetworkFlow,
		Source:       SourceName,
		ObservedAt:   observedAt,
		RecordedAt:   ctx.recordedAt,
		ResourceID:   resourceID(interfaceID),
		ResourceType: "network_interface",
		Network: &runtime.NetworkEvent{
			Protocol: protocol,
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstIP:    dstIP,
			DstPort:  dstPort,
		},
		Tags: adapters.CompactTags(
			"aws",
			"vpc_flow_log",
			"network_flow",
			strings.ToLower(action),
			strings.ToLower(logStatus),
			strings.ToLower(protocol),
		),
		Metadata: metadata,
		Raw: map[string]any{
			"line": line,
		},
		Provenance: map[string]any{
			"format":      "aws_vpc_flow_logs_default",
			"event_id":    strings.TrimSpace(ctx.eventID),
			"line_number": ctx.lineNumber,
			"wrapped":     ctx.wrapped,
		},
	}
	return runtime.NormalizeObservation(observation)
}

func parseOptionalInt(raw string) (int, error) {
	value := normalizeField(raw)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func parseOptionalInt64(raw string) (int64, error) {
	value := normalizeField(raw)
	if value == "" {
		return 0, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

func protocolName(raw string) string {
	switch strings.TrimSpace(raw) {
	case "1":
		return "icmp"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "58":
		return "icmpv6"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func normalizeField(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || value == "-" {
		return ""
	}
	return value
}

func unixSecondsTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func unixMillisTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}

func observationID(line, eventID string) string {
	if strings.TrimSpace(eventID) != "" {
		return SourceName + ":" + strings.TrimSpace(eventID)
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(line)))
	return SourceName + ":" + hex.EncodeToString(sum[:16])
}

func resourceID(interfaceID string) string {
	if strings.TrimSpace(interfaceID) == "" {
		return ""
	}
	return "eni:" + strings.TrimSpace(interfaceID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
