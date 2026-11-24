package vulnerabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/vulnpipeline"
	"github.com/writer/cerebro/internal/vulnpipeline/vulnpipelinetest"
)

var errForbidden = errors.New("tenant forbidden")

const strixPayload = `{"items":[
 {"id":"v-1","scan_id":"s-1","title":"SQL injection in login","target":"https://app.example.com","severity":"critical","cvss":9.8,"status":"open","created_at":"2026-01-01T00:00:00Z","finding_type":"live_pentest"},
 {"id":"v-2","scan_id":"s-1","title":"Vulnerable lodash","target":"github.com/acme/web","severity":"high","cve":"CVE-2021-23337","status":"open","created_at":"2026-01-01T00:00:00Z","finding_type":"dependency","dependency_metadata":{"package":"lodash","ecosystem":"npm","installed_version":"4.17.15"}}
],"meta":{"page":1,"total_pages":1,"has_next":false}}`

const unknownPayload = `{"data":{"issues":[
 {"issue_id":"BT-1","name":"Outdated OpenSSL on bastion","risk":"P1","host":"bastion-1.internal","cve_list":["CVE-2024-6119"],"state":"Active"},
 {"issue_id":"BT-2","name":"Log4Shell in search","risk":"P0","host":"search-2.internal","cve_list":["CVE-2021-44228"],"state":"Active"}
]}}`

type testServer struct {
	t       *testing.T
	mux     *http.ServeMux
	service *vulnpipeline.Service
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	service := vulnpipeline.NewService(vulnpipelinetest.NewMemoryStore(), vulnpipeline.Options{
		Pullers:           []vulnpipeline.Puller{vulnpipeline.StrixPuller{}},
		IsSecretReference: func(value string) bool { return strings.HasPrefix(value, "env:") },
	})
	tenant := func(_ context.Context, requested string) (string, error) {
		switch requested {
		case "":
			return "tenant-a", nil
		case "tenant-a":
			return requested, nil
		default:
			return "", errForbidden
		}
	}
	h := NewHandler(service, tenant, func(context.Context) string { return "alice" }, func(err error) bool { return errors.Is(err, errForbidden) })
	mux := http.NewServeMux()
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET /vulnerabilities":                                        h.ListObservations,
		"GET /vulnerabilities/summary":                                h.Summary,
		"GET /vulnerabilities/catalog":                                h.Catalog,
		"GET /vulnerabilities/observations/{observationID}":           h.GetObservation,
		"POST /vulnerabilities/preview":                               h.Preview,
		"GET /vulnerabilities/profiles":                               h.ListProfiles,
		"POST /vulnerabilities/profiles":                              h.CreateProfile,
		"GET /vulnerabilities/profiles/{profileID}":                   h.GetProfile,
		"PATCH /vulnerabilities/profiles/{profileID}":                 h.UpdateProfile,
		"DELETE /vulnerabilities/profiles/{profileID}":                h.DeleteProfile,
		"POST /vulnerabilities/profiles/{profileID}/ingest":           h.Ingest,
		"POST /vulnerabilities/profiles/{profileID}/mapping/activate": h.ActivateMapping,
		"GET /vulnerabilities/profiles/{profileID}/batches":           h.ListBatches,
		"GET /vulnerabilities/profiles/{profileID}/quarantine":        h.ListQuarantine,
	} {
		mux.HandleFunc(pattern, handler)
	}
	return &testServer{t: t, mux: mux, service: service}
}

func (s *testServer) do(method string, target string, body string, headers ...string) (int, map[string]any) {
	s.t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)
	decoded := map[string]any{}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
			s.t.Fatalf("%s %s returned non-JSON body %q", method, target, recorder.Body.String())
		}
	}
	return recorder.Code, decoded
}

func (s *testServer) createProfile(body string) {
	s.t.Helper()
	if status, response := s.do(http.MethodPost, "/vulnerabilities/profiles", body); status != http.StatusCreated {
		s.t.Fatalf("create profile = %d %v", status, response)
	}
}

func TestPushIngestTagsSourceAndIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	s.createProfile(`{"source_id":"strix"}`)

	status, response := s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest", strixPayload, "Idempotency-Key", "delivery-1", "Content-Type", "application/json")
	ingest, _ := response["ingest"].(map[string]any)
	if status != http.StatusAccepted || ingest["accepted"] != float64(2) || ingest["format"] != vulnpipeline.FormatStrix {
		t.Fatalf("ingest = %d %v", status, response)
	}
	status, response = s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest", strixPayload, "Idempotency-Key", "delivery-1")
	if replay, _ := response["ingest"].(map[string]any); status != http.StatusOK || replay["idempotent_replay"] != true {
		t.Fatalf("replay = %d %v", status, response)
	}
	if status, response = s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest", `{"items":[]}`, "Idempotency-Key", "delivery-1"); status != http.StatusConflict {
		t.Fatalf("reused key with different body = %d %v", status, response)
	}

	status, response = s.do(http.MethodGet, "/vulnerabilities?severity=critical", "")
	observations, _ := response["observations"].([]any)
	if status != http.StatusOK || len(observations) != 1 {
		t.Fatalf("list = %d %v", status, response)
	}
	first := observations[0].(map[string]any)
	if first["source_id"] != "strix" || first["severity"] != "critical" {
		t.Fatalf("observation = %v", first)
	}
	if status, response = s.do(http.MethodGet, "/vulnerabilities/observations/"+first["id"].(string), ""); status != http.StatusOK || response["observation"] == nil {
		t.Fatalf("get observation = %d %v", status, response)
	}
	status, response = s.do(http.MethodGet, "/vulnerabilities/summary", "")
	if status != http.StatusOK || response["open"] != float64(2) {
		t.Fatalf("summary = %d %v", status, response)
	}
}

func TestUnknownFormatIsHeldUntilMappingIsActivated(t *testing.T) {
	s := newTestServer(t)
	s.createProfile(`{"source_id":"bugtracker"}`)

	status, response := s.do(http.MethodPost, "/vulnerabilities/profiles/bugtracker/ingest", unknownPayload)
	ingest, _ := response["ingest"].(map[string]any)
	if status != http.StatusAccepted || ingest["accepted"] != float64(0) || ingest["draft_mapping"] == nil {
		t.Fatalf("held ingest = %d %v", status, response)
	}
	if _, response = s.do(http.MethodGet, "/vulnerabilities?source_id=bugtracker", ""); len(response["observations"].([]any)) != 0 {
		t.Fatalf("held delivery produced observations: %v", response)
	}
	status, response = s.do(http.MethodPost, "/vulnerabilities/profiles/bugtracker/mapping/activate", "")
	if replayed, _ := response["replayed"].([]any); status != http.StatusOK || len(replayed) != 1 {
		t.Fatalf("activate = %d %v", status, response)
	}
	if _, response = s.do(http.MethodGet, "/vulnerabilities?source_id=bugtracker", ""); len(response["observations"].([]any)) != 2 {
		t.Fatalf("activation did not replay held delivery: %v", response)
	}
	if status, response = s.do(http.MethodGet, "/vulnerabilities/profiles/bugtracker/batches", ""); status != http.StatusOK || len(response["batches"].([]any)) == 0 {
		t.Fatalf("batches = %d %v", status, response)
	}
}

func TestQuarantineViewKeepsRejectedRecords(t *testing.T) {
	s := newTestServer(t)
	s.createProfile(`{"source_id":"strix","format":"strix"}`)
	s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest", `{"items":[{"id":"v-9","severity":"high"}]}`)
	status, response := s.do(http.MethodGet, "/vulnerabilities/profiles/strix/quarantine", "")
	records, _ := response["records"].([]any)
	if status != http.StatusOK || len(records) != 1 {
		t.Fatalf("quarantine = %d %v", status, response)
	}
	record := records[0].(map[string]any)
	if record["reason"] == "" || record["record"] == nil {
		t.Fatalf("quarantine record = %v", record)
	}
}

func TestProfilesRejectRawSecretsAndUnknownFields(t *testing.T) {
	s := newTestServer(t)
	if status, response := s.do(http.MethodPost, "/vulnerabilities/profiles", `{"source_id":"strix","pull":{"kind":"strix","config":{"api_token":"raw-token-value"}}}`); status != http.StatusBadRequest {
		t.Fatalf("raw secret = %d %v", status, response)
	}
	if status, response := s.do(http.MethodPost, "/vulnerabilities/profiles", `{"source_id":"strix","surprise":true}`); status != http.StatusBadRequest {
		t.Fatalf("unknown field = %d %v", status, response)
	}
	s.createProfile(`{"source_id":"strix","pull":{"kind":"strix","config":{"api_token":"env:CEREBRO_SOURCE_VULNERABILITY_PULL_API_TOKEN"}}}`)
	status, response := s.do(http.MethodGet, "/vulnerabilities/profiles/strix", "")
	profile, _ := response["profile"].(map[string]any)
	config, _ := profile["pull_config"].(map[string]any)
	secretKeys, _ := profile["pull_secret_keys"].([]any)
	if status != http.StatusOK || config["api_token"] != nil || len(secretKeys) != 1 || secretKeys[0] != "api_token" {
		t.Fatalf("profile = %d %v", status, response)
	}
	if status, response = s.do(http.MethodPatch, "/vulnerabilities/profiles/strix", `{"source_id":"other"}`); status != http.StatusBadRequest {
		t.Fatalf("source tag change = %d %v", status, response)
	}
	if status, _ = s.do(http.MethodDelete, "/vulnerabilities/profiles/strix", ""); status != http.StatusNoContent {
		t.Fatalf("delete = %d", status)
	}
	if status, _ = s.do(http.MethodGet, "/vulnerabilities/profiles/strix", ""); status != http.StatusNotFound {
		t.Fatalf("deleted profile = %d", status)
	}
}

func TestTenantForbiddenAndOversizedBodies(t *testing.T) {
	s := newTestServer(t)
	s.createProfile(`{"source_id":"strix"}`)
	if status, response := s.do(http.MethodGet, "/vulnerabilities?tenant_id=tenant-b", ""); status != http.StatusForbidden || response["error"] != "forbidden" {
		t.Fatalf("cross-tenant list = %d %v", status, response)
	}
	if status, _ := s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest?tenant_id=tenant-b", strixPayload); status != http.StatusForbidden {
		t.Fatalf("cross-tenant ingest = %d", status)
	}
	oversized := bytes.Repeat([]byte(" "), vulnpipeline.MaxPayloadBytes+1)
	if status, _ := s.do(http.MethodPost, "/vulnerabilities/profiles/strix/ingest", string(oversized)); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized ingest = %d", status)
	}
	if status, _ := s.do(http.MethodPost, "/vulnerabilities/profiles/missing/ingest", strixPayload); status != http.StatusNotFound {
		t.Fatalf("missing profile ingest = %d", status)
	}
}

func TestPreviewNormalizesWithoutPersisting(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"sample": json.RawMessage(unknownPayload)})
	status, response := s.do(http.MethodPost, "/vulnerabilities/preview", string(body))
	observations, _ := response["observations"].([]any)
	if status != http.StatusOK || len(observations) != 2 {
		t.Fatalf("preview = %d %v", status, response)
	}
	if _, response = s.do(http.MethodGet, "/vulnerabilities/summary", ""); response["total"] != float64(0) {
		t.Fatalf("preview persisted observations: %v", response)
	}
	if status, response = s.do(http.MethodGet, "/vulnerabilities/catalog", ""); status != http.StatusOK || len(response["formats"].([]any)) == 0 {
		t.Fatalf("catalog = %d %v", status, response)
	}
}

func TestMCPToolIngestsAndLists(t *testing.T) {
	s := newTestServer(t)
	s.createProfile(`{"source_id":"strix"}`)
	ctx := context.Background()
	result, err := MCPTool(ctx, s.service, "cerebro.vulnerabilities.ingest", "tenant-a", "agent", json.RawMessage(`{"profile_id":"strix","idempotency_key":"mcp-1","payload":`+strixPayload+`}`))
	if err != nil {
		t.Fatalf("ingest error = %v", err)
	}
	if ingest := result.Ingest; ingest == nil || ingest.Accepted != 2 {
		t.Fatalf("ingest = %+v", ingest)
	}
	result, err = MCPTool(ctx, s.service, "cerebro.vulnerabilities.list", "tenant-a", "agent", json.RawMessage(`{"severity":["high"],"limit":10}`))
	if err != nil {
		t.Fatalf("list error = %v", err)
	}
	if page := result.Observations; page == nil || len(page.Observations) != 1 || page.Observations[0].SourceID != "strix" {
		t.Fatalf("list = %+v", page)
	}
	if _, err := MCPTool(ctx, s.service, "cerebro.vulnerabilities.ingest", "tenant-a", "agent", json.RawMessage(`{"profile_id":"strix"}`)); !errors.Is(err, vulnpipeline.ErrInvalidRequest) {
		t.Fatalf("missing payload error = %v", err)
	}
	if _, err := MCPTool(ctx, s.service, "cerebro.vulnerabilities.list", "tenant-a", "agent", json.RawMessage(`{"limit":"-1"}`)); !errors.Is(err, vulnpipeline.ErrInvalidRequest) {
		t.Fatalf("negative limit error = %v", err)
	}
	if _, err := MCPTool(ctx, s.service, "cerebro.vulnerabilities.list", "tenant-a", "agent", json.RawMessage(`{"severity":{"nested":true}}`)); !errors.Is(err, vulnpipeline.ErrInvalidRequest) {
		t.Fatalf("malformed argument error = %v", err)
	}
	encoded, err := json.Marshal(&MCPResult{Summary: &vulnpipeline.SummaryView{}})
	if err != nil || !strings.HasPrefix(string(encoded), "{") || strings.Contains(string(encoded), "Summary") {
		t.Fatalf("summary result JSON = %s, %v", encoded, err)
	}
}
