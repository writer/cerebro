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
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const maxAPIResponseBytes = 8 << 20
const panopticonUserAgent = "cerebro-panopticon-source/1.0"

type panopticonAPICursor struct {
	Source              string `json:"source,omitempty"`
	ResumableCheckpoint bool   `json:"resumable_checkpoint,omitempty"`
	Page                int    `json:"page,omitempty"`
	CasePage            int    `json:"case_page,omitempty"`
	CaseIndex           int    `json:"case_index,omitempty"`
	IOCPage             int    `json:"ioc_page,omitempty"`
	Watermark           string `json:"watermark,omitempty"`
}

type nativeAPIPage struct {
	Total       int                      `json:"total"`
	Data        []map[string]interface{} `json:"data"`
	LastPage    int                      `json:"last_page"`
	CurrentPage int                      `json:"current_page"`
	NextPage    json.RawMessage          `json:"next_page"`
}

func apiPathForFamily(family string) string {
	switch family {
	case familyAlert:
		return "/api/v2/alerts"
	case familyCase, familyIOC:
		return "/api/v2/cases"
	default:
		return "/api/v2/alerts"
	}
}

func discoverAPIFamily(st settings, urnPrefix string) ([]sourcecdk.URN, error) {
	path := st.apiPath
	if st.family == familyIOC {
		path = strings.TrimRight(path, "/") + "/*/iocs"
	}
	urnRaw := urnPrefix + url.PathEscape(st.baseURL+path)
	urn, err := sourcecdk.ParseURN(urnRaw)
	if err != nil {
		return nil, fmt.Errorf("build panopticon api urn: %w", err)
	}
	return []sourcecdk.URN{urn}, nil
}

func (s *Source) checkAPI(ctx context.Context, st settings) error {
	st.perPage = 1
	_, err := s.readNativeAPIPage(ctx, st, st.apiPath, 1)
	return err
}

func (s *Source) readAPIFamily(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor, kind, schemaRef string) (sourcecdk.Pull, error) {
	if st.family == familyIOC {
		return s.readNativeIOCFamily(ctx, st, cursor)
	}
	cursorState := decodeAPICursor(cursor)
	page := cursorState.Page
	if page < 1 {
		page = 1
	}
	response, err := s.readNativeAPIPage(ctx, st, st.apiPath, page)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	records, err := nativeRecords(st, response.Data, kind, schemaRef, time.Time{})
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	next := cursorState
	if nextPage := response.nextPage(); nextPage > 0 {
		next.Page = nextPage
	} else {
		next.Page = 0
	}
	return recordsPull(records, cursorState, next, cursor != nil)
}

func (s *Source) readNativeIOCFamily(ctx context.Context, st settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	state := decodeAPICursor(cursor)
	if state.CasePage < 1 {
		state.CasePage = 1
	}
	if state.IOCPage < 1 {
		state.IOCPage = 1
	}
	current := state
	for scanned := 0; scanned < int(st.perPage)+1; scanned++ {
		cases, err := s.readNativeAPIPage(ctx, st, st.apiPath, current.CasePage)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		for current.CaseIndex < len(cases.Data) {
			caseItem := cases.Data[current.CaseIndex]
			caseID := nativeString(caseItem, "case_id")
			if caseID == "" {
				return sourcecdk.Pull{}, fmt.Errorf("panopticon case missing case_id")
			}
			caseOccurred := firstNativeTime(caseItem, "initial_date", "open_date", "close_date")
			iocPath := strings.TrimRight(st.apiPath, "/") + "/" + url.PathEscape(caseID) + "/iocs"
			iocs, err := s.readNativeAPIPage(ctx, st, iocPath, current.IOCPage)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := nativeRecords(st, iocs.Data, kindIOC, schemaRefIOC, caseOccurred)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			next := current
			if nextIOCPage := iocs.nextPage(); nextIOCPage > 0 {
				next.IOCPage = nextIOCPage
				return recordsPull(records, state, next, cursor != nil)
			}
			next.CaseIndex++
			next.IOCPage = 1
			if len(records) > 0 {
				if next.CaseIndex >= len(cases.Data) {
					if nextCasePage := cases.nextPage(); nextCasePage > 0 {
						next.CasePage = nextCasePage
						next.CaseIndex = 0
					} else {
						next.CasePage = 0
						next.IOCPage = 0
					}
				}
				return recordsPull(records, state, next, cursor != nil)
			}
			current = next
		}
		if nextCasePage := cases.nextPage(); nextCasePage > 0 {
			current.CasePage = nextCasePage
			current.CaseIndex = 0
			current.IOCPage = 1
			continue
		}
		return recordsPull(nil, state, panopticonAPICursor{}, cursor != nil)
	}
	return sourcecdk.Pull{}, fmt.Errorf("panopticon ioc pagination did not make progress")
}

func (s *Source) readNativeAPIPage(ctx context.Context, st settings, path string, page int) (nativeAPIPage, error) {
	if page < 1 {
		page = 1
	}
	query := url.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("per_page", strconv.Itoa(int(st.perPage)))
	if st.family == familyAlert {
		query.Set("sort", "asc")
	} else {
		query.Set("order_by", "case_id")
		query.Set("sort_dir", "asc")
	}
	endpoint := st.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nativeAPIPage{}, fmt.Errorf("build panopticon api request: %w", err)
	}
	req.Header = http.Header{"Accept": {"application/json"}, "User-Agent": {panopticonUserAgent}, "Authorization": {"Bearer " + st.token}}

	resp, err := sourceHTTPClient(s, st.privateEndpointAllowlist).Do(req)
	if err != nil {
		return nativeAPIPage{}, fmt.Errorf("request panopticon api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := sourcehttp.ReadLimitedBodyWithLimit(resp.Body, maxAPIResponseBytes)
	if err != nil {
		return nativeAPIPage{}, fmt.Errorf("read panopticon api response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nativeAPIPage{}, apiResponseError(resp.StatusCode, payload)
	}
	var response nativeAPIPage
	if err := json.Unmarshal(payload, &response); err != nil {
		return nativeAPIPage{}, fmt.Errorf("decode panopticon api response: %w", err)
	}
	return response, nil
}

func recordsPull(records []panopticonRecord, cursorState, next panopticonAPICursor, hadCursor bool) (sourcecdk.Pull, error) {
	if len(records) > maxEventsPerPull {
		return sourcecdk.Pull{}, fmt.Errorf("panopticon api returned %d records, max %d", len(records), maxEventsPerPull)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(records))
	var watermark time.Time
	for _, rec := range records {
		event, err := buildEvent(rec, rec.Kind, rec.SchemaRef)
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
	pull := sourcecdk.Pull{Events: events}
	watermarkValue := sourcecdk.WatermarkString(watermark, parseAPIWatermark(cursorState.Watermark))
	if next.hasMore() {
		next.Watermark = watermarkValue
		opaque := encodeAPICursor(next)
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: opaque}
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	} else if watermarkValue != "" || hadCursor {
		cursorState.Watermark = watermarkValue
		cursorState.Page = 0
		cursorState.CasePage = 0
		cursorState.CaseIndex = 0
		cursorState.IOCPage = 0
		opaque := encodeAPICursor(cursorState)
		pull.Checkpoint = &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	}
	if pull.Checkpoint != nil {
		if checkpointWatermark := parseAPIWatermark(decodeAPICursor(&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.CursorOpaque}).Watermark); !checkpointWatermark.IsZero() {
			pull.Checkpoint.Watermark = timestamppb.New(checkpointWatermark.UTC())
		}
	}
	return pull, nil
}

func nativeRecords(st settings, items []map[string]interface{}, kind, schemaRef string, fallbackOccurredAt time.Time) ([]panopticonRecord, error) {
	records := make([]panopticonRecord, 0, len(items))
	for _, item := range items {
		record, err := nativeRecord(st, item, kind, schemaRef, fallbackOccurredAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func nativeRecord(st settings, item map[string]interface{}, kind, schemaRef string, fallbackOccurredAt time.Time) (panopticonRecord, error) {
	switch kind {
	case kindAlert:
		alertID := nativeString(item, "alert_id")
		severity := firstString(nestedString(item, "severity", "severity_name"), nativeString(item, "severity"), nativeString(item, "alert_severity_id"))
		status := firstString(nestedString(item, "status", "status_name"), nativeString(item, "status"), nativeString(item, "alert_status_id"))
		title := firstString(nativeString(item, "alert_title"), nativeString(item, "title"))
		occurredAt := firstNativeTime(item, "alert_source_event_time", "observed_at", "alert_creation_time", "created_at")
		observedAt := firstString(nativeString(item, "observed_at"), nativeString(item, "alert_source_event_time"))
		createdAt := firstString(nativeString(item, "created_at"), nativeString(item, "alert_creation_time"))
		updatedAt := firstString(nativeString(item, "updated_at"), nativeString(item, "last_updated_at"), nativeString(item, "modified_at"), nativeString(item, "alert_updated_time"))
		closedAt := firstString(nativeString(item, "closed_at"), nativeString(item, "close_date"), nativeString(item, "alert_closed_time"))
		resolvedAt := firstString(nativeString(item, "resolved_at"), nativeString(item, "resolved_date"), nativeString(item, "alert_resolved_time"))
		caseID := nativeString(item, "case_id")
		return canonicalRecord(st, item, kind, schemaRef, "alert-"+alertID, occurredAt,
			map[string]string{"alert_id": alertID, "severity": severity, "status": status, "observed_at": observedAt, "created_at": createdAt, "updated_at": updatedAt, "closed_at": closedAt, "resolved_at": resolvedAt, "case_id": caseID},
			map[string]interface{}{"alert_id": alertID, "severity": severity, "status": status, "title": title, "observed_at": observedAt, "created_at": createdAt, "updated_at": updatedAt, "closed_at": closedAt, "resolved_at": resolvedAt, "case_id": caseID})
	case kindCase:
		caseID := nativeString(item, "case_id")
		status := firstString(nestedString(item, "state", "state_name"), nativeString(item, "status"), nativeString(item, "status_id"))
		title := firstString(nativeString(item, "case_name"), nativeString(item, "name"))
		occurredAt := firstNativeTime(item, "initial_date", "open_date", "close_date")
		createdAt := firstString(nativeString(item, "created_at"), nativeString(item, "initial_date"), nativeString(item, "open_date"))
		updatedAt := firstString(nativeString(item, "updated_at"), nativeString(item, "last_updated_at"), nativeString(item, "modified_at"))
		closedAt := firstString(nativeString(item, "closed_at"), nativeString(item, "close_date"))
		resolvedAt := firstString(nativeString(item, "resolved_at"), nativeString(item, "resolved_date"))
		return canonicalRecord(st, item, kind, schemaRef, "case-"+caseID, occurredAt,
			map[string]string{"case_id": caseID, "status": status, "created_at": createdAt, "updated_at": updatedAt, "closed_at": closedAt, "resolved_at": resolvedAt},
			map[string]interface{}{"case_id": caseID, "status": status, "title": title, "created_at": createdAt, "updated_at": updatedAt, "closed_at": closedAt, "resolved_at": resolvedAt})
	case kindIOC:
		iocID := nativeString(item, "ioc_id")
		iocType := firstString(nestedString(item, "ioc_type", "type_name"), nativeString(item, "ioc_type"), nativeString(item, "ioc_type_id"))
		value := firstString(nativeString(item, "ioc_value"), nativeString(item, "value"))
		occurredAt := fallbackOccurredAt
		return canonicalRecord(st, item, kind, schemaRef, "ioc-"+iocID, occurredAt, map[string]string{"ioc_id": iocID, "ioc_type": iocType, "value": value}, map[string]interface{}{"ioc_id": iocID, "ioc_type": iocType, "value": value})
	default:
		return panopticonRecord{}, fmt.Errorf("unsupported kind %q", kind)
	}
}

func canonicalRecord(st settings, item map[string]interface{}, kind, schemaRef, id string, occurredAt time.Time, attributes map[string]string, canonicalPayload map[string]interface{}) (panopticonRecord, error) {
	payload := make(map[string]interface{}, len(item)+len(canonicalPayload))
	for key, value := range item {
		payload[key] = value
	}
	for key, value := range canonicalPayload {
		payload[key] = value
	}
	if st.runtimeID != "" {
		attributes["runtime_id"] = st.runtimeID
		attributes[ports.EventAttributeSourceRuntimeID] = st.runtimeID
	}
	return panopticonRecord{ID: id, TenantID: st.tenantID, SourceID: sourceID, Kind: kind, OccurredAt: occurredAt, SchemaRef: schemaRef, Attributes: attributes, Payload: payload}, nil
}

func sourceHTTPClient(s *Source, privateEndpointAllowlist []string) *http.Client {
	if s == nil {
		return sourcehttp.NewClient(sourcehttp.ClientOptions{
			SourceID:                 sourceID,
			PrivateEndpointAllowlist: privateEndpointAllowlist,
		})
	}
	return sourcehttp.HardenClient(s.client, sourcehttp.ClientOptions{
		SourceID:                 sourceID,
		AllowLoopback:            s.allowLoopbackBaseURL,
		PrivateEndpointAllowlist: privateEndpointAllowlist,
		LookupIPAddrs:            lookupIPAddrs(s),
	})
}

func lookupIPAddrs(s *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if s == nil || s.lookupIPAddrs == nil {
		return net.DefaultResolver.LookupIPAddr
	}
	return s.lookupIPAddrs
}

func decodeAPICursor(cursor *cerebrov1.SourceCursor) panopticonAPICursor {
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return panopticonAPICursor{}
	}
	var decoded panopticonAPICursor
	if err := json.Unmarshal([]byte(opaque), &decoded); err == nil && decoded.Source == cursorSourceAPI {
		decoded.Watermark = strings.TrimSpace(decoded.Watermark)
		return decoded
	}
	if page, err := strconv.Atoi(opaque); err == nil {
		return panopticonAPICursor{Page: page}
	}
	return panopticonAPICursor{}
}

func encodeAPICursor(cursor panopticonAPICursor) string {
	cursor.Source = cursorSourceAPI
	cursor.ResumableCheckpoint = true
	cursor.Watermark = strings.TrimSpace(cursor.Watermark)
	raw, err := json.Marshal(cursor)
	if err != nil {
		return ""
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

func (c panopticonAPICursor) hasMore() bool {
	return c.Page > 0 || c.CasePage > 0 || c.IOCPage > 0
}

func (p nativeAPIPage) nextPage() int {
	raw := strings.TrimSpace(string(p.NextPage))
	if raw == "" || raw == "null" || raw == "false" || raw == "0" {
		return 0
	}
	if raw == "true" {
		return p.CurrentPage + 1
	}
	var page int
	if err := json.Unmarshal(p.NextPage, &page); err == nil && page > 0 {
		return page
	}
	return 0
}

var nativeTimeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02"}

func firstNativeTime(item map[string]interface{}, keys ...string) time.Time {
	for _, key := range keys {
		if parsed := (sourcecdk.JSONScalar{Value: item[key]}).Time(nativeTimeLayouts...); !parsed.IsZero() {
			return parsed
		}
	}
	return time.Time{}
}

func nativeString(item map[string]interface{}, key string) string {
	return (sourcecdk.JSONScalar{Value: item[key]}).String()
}

func nestedString(item map[string]interface{}, key, nestedKey string) string {
	nested, ok := item[key].(map[string]interface{})
	if !ok {
		return ""
	}
	return (sourcecdk.JSONScalar{Value: nested[nestedKey]}).String()
}

func firstString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
