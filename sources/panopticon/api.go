package panopticon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const maxAPIResponseBytes = 8 << 20

type panopticonAPICursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	Cursor              string `json:"cursor,omitempty"`
	Watermark           string `json:"watermark,omitempty"`
}

type panopticonAPIResponse struct {
	Records    []panopticonRecord `json:"records"`
	Events     []panopticonRecord `json:"events"`
	NextCursor string             `json:"next_cursor"`
	Watermark  string             `json:"watermark"`
}

func apiPathForFamily(family string) string {
	switch family {
	case familyAlert:
		return "/api/cerebro/alerts"
	case familyCase:
		return "/api/cerebro/cases"
	case familyIOC:
		return "/api/cerebro/iocs"
	default:
		return "/api/cerebro/events"
	}
}

func discoverAPIFamily(st settings, urnPrefix string) ([]sourcecdk.URN, error) {
	urnRaw := urnPrefix + url.PathEscape(st.baseURL+st.apiPath)
	urn, err := sourcecdk.ParseURN(urnRaw)
	if err != nil {
		return nil, fmt.Errorf("build panopticon api urn: %w", err)
	}
	return []sourcecdk.URN{urn}, nil
}

func (s *Source) checkAPI(ctx context.Context, st settings) error {
	_, err := s.readAPIPage(ctx, st, "")
	return err
}

func (s *Source) readAPIFamily(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor, kind, schemaRef string) (sourcecdk.Pull, error) {
	cursorState := decodeAPICursor(cursor)
	response, err := s.readAPIPage(ctx, st, cursorState.Cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	records := response.apiRecords()
	if len(records) > maxEventsPerPull {
		return sourcecdk.Pull{}, fmt.Errorf("panopticon api returned %d records, max %d", len(records), maxEventsPerPull)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(records))
	var watermark time.Time
	for _, rec := range records {
		recordTenant := strings.TrimSpace(rec.TenantID)
		if recordTenant == "" {
			return sourcecdk.Pull{}, fmt.Errorf("invalid panopticon api event: tenant_id is required")
		}
		if recordTenant != rec.TenantID {
			return sourcecdk.Pull{}, fmt.Errorf("invalid panopticon api event: tenant_id must not have leading or trailing whitespace")
		}
		if recordTenant != st.tenantID {
			return sourcecdk.Pull{}, fmt.Errorf("invalid panopticon api event: tenant_id %q does not match runtime tenant", recordTenant)
		}
		if st.runtimeID != "" && strings.TrimSpace(rec.Attributes["runtime_id"]) != "" && strings.TrimSpace(rec.Attributes["runtime_id"]) != st.runtimeID {
			continue
		}
		event, err := buildEvent(rec, kind, schemaRef)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("convert panopticon api event: %w", err)
		}
		if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, sourcecdkEventContracts()); err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("invalid panopticon api event: %w", err)
		}
		if err := validateFamilyContract(event); err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("invalid panopticon api event: %w", err)
		}
		events = append(events, event)
		if rec.OccurredAt.After(watermark) {
			watermark = rec.OccurredAt
		}
	}
	if parsed := parseAPIWatermark(response.Watermark); parsed.After(watermark) {
		watermark = parsed
	}

	pull := sourcecdk.Pull{Events: events}
	nextCursor := strings.TrimSpace(response.NextCursor)
	if nextCursor != "" {
		opaque := encodeAPICursor(panopticonAPICursor{
			Cursor:    nextCursor,
			Watermark: watermarkString(watermark, parseAPIWatermark(cursorState.Watermark)),
		})
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: opaque}
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	} else if !watermark.IsZero() || cursor != nil {
		opaque := encodeAPICursor(panopticonAPICursor{
			Cursor:    cursorState.Cursor,
			Watermark: watermarkString(watermark, parseAPIWatermark(cursorState.Watermark)),
		})
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	}
	if pull.Checkpoint != nil {
		if checkpointWatermark := parseAPIWatermark(decodeAPICursor(&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.CursorOpaque}).Watermark); !checkpointWatermark.IsZero() {
			pull.Checkpoint.Watermark = timestamppb.New(checkpointWatermark.UTC())
		}
	}
	return pull, nil
}

func (s *Source) readAPIPage(ctx context.Context, st settings, cursor string) (panopticonAPIResponse, error) {
	query := url.Values{}
	query.Set("tenant_id", st.tenantID)
	query.Set("family", st.family)
	query.Set("limit", strconv.Itoa(int(st.perPage)))
	if st.runtimeID != "" {
		query.Set("runtime_id", st.runtimeID)
	}
	if cursor = strings.TrimSpace(cursor); cursor != "" {
		query.Set("cursor", cursor)
	}
	endpoint := st.baseURL + st.apiPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return panopticonAPIResponse{}, fmt.Errorf("build panopticon api request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+st.token)

	resp, err := sourceHTTPClient(s).Do(req)
	if err != nil {
		return panopticonAPIResponse{}, fmt.Errorf("request panopticon api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxAPIResponseBytes)
	if err != nil {
		return panopticonAPIResponse{}, fmt.Errorf("read panopticon api response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return panopticonAPIResponse{}, apiResponseError(resp.StatusCode, payload)
	}
	var response panopticonAPIResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return panopticonAPIResponse{}, fmt.Errorf("decode panopticon api response: %w", err)
	}
	return response, nil
}

func sourceHTTPClient(s *Source) *http.Client {
	if s == nil {
		return sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: sourceID})
	}
	return sourcehttp.HardenClient(s.client, sourcehttp.ClientOptions{
		SourceID:      sourceID,
		AllowLoopback: s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func lookupIPAddrs(s *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if s == nil || s.lookupIPAddrs == nil {
		return net.DefaultResolver.LookupIPAddr
	}
	return s.lookupIPAddrs
}

func (r panopticonAPIResponse) apiRecords() []panopticonRecord {
	if r.Records != nil {
		return r.Records
	}
	return r.Events
}

func decodeAPICursor(cursor *cerebrov1.SourceCursor) panopticonAPICursor {
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return panopticonAPICursor{}
	}
	var decoded panopticonAPICursor
	if err := json.Unmarshal([]byte(opaque), &decoded); err == nil && decoded.Source == cursorSourceAPI {
		decoded.Cursor = strings.TrimSpace(decoded.Cursor)
		decoded.Watermark = strings.TrimSpace(decoded.Watermark)
		return decoded
	}
	return panopticonAPICursor{Cursor: opaque}
}

func encodeAPICursor(cursor panopticonAPICursor) string {
	cursor.Source = cursorSourceAPI
	cursor.ResumableCheckpoint = true
	cursor.Cursor = strings.TrimSpace(cursor.Cursor)
	cursor.Watermark = strings.TrimSpace(cursor.Watermark)
	raw, err := json.Marshal(cursor)
	if err != nil {
		return cursor.Cursor
	}
	return string(raw)
}

func parseAPIWatermark(raw string) time.Time {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func apiResponseError(statusCode int, payload []byte) error {
	message := strings.TrimSpace(string(payload))
	if message == "" {
		message = http.StatusText(statusCode)
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return fmt.Errorf("panopticon api returned status %d: %s", statusCode, message)
}
