package bootstrap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/claims"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/grcauditpacket"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
	archetypesource "github.com/writer/cerebro/sources/archetype"
	auth0source "github.com/writer/cerebro/sources/auth0"
	datadogsource "github.com/writer/cerebro/sources/datadog"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
	pagerdutysource "github.com/writer/cerebro/sources/pagerduty"
	sdksource "github.com/writer/cerebro/sources/sdk"
	slacksource "github.com/writer/cerebro/sources/slack"
)

func sourceGet(t *testing.T, server *httptest.Server, path string, config map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		return nil, err
	}
	if len(config) > 0 {
		payload, err := json.Marshal(config)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Cerebro-Source-Config", string(payload))
	}
	return server.Client().Do(req)
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode test JSON: %v", err)
	}
}

func TestSourceConfigFromRequestRejectsSensitiveQueryKeys(t *testing.T) {
	for _, key := range []string{"token", "api_key", "apiKey", "secret_access_key", "private_key", "privateKey", "signing_key", "key"} {
		t.Run(key, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sources/okta/check?"+key+"=secret", nil)
			if _, err := sourceConfigFromRequest(req); !errors.Is(err, sourceops.ErrInvalidRequest) {
				t.Fatalf("sourceConfigFromRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestSourceConfigFromRequestAllowsAWSAccessKeyIDQueryField(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/aws/check?account_id=123456789012&access_key_id=AKIAEXAMPLE", nil)
	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	if got := config["account_id"]; got != "123456789012" {
		t.Fatalf("config[account_id] = %q, want 123456789012", got)
	}
	if got := config["access_key_id"]; got != "AKIAEXAMPLE" {
		t.Fatalf("config[access_key_id] = %q, want AKIAEXAMPLE", got)
	}
}

func TestSourceConfigFromRequestAllowsNonSecretKeyQueryFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/aws/check?region=us-east-1&lookup_key=inventory&group_key=security@example.com&access_key_id=AKIAEXAMPLE", nil)
	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	for _, key := range []string{"region", "lookup_key", "group_key", "access_key_id"} {
		if got := config[key]; got == "" {
			t.Fatalf("config[%q] = %q, want value", key, got)
		}
	}
}

func TestConnectErrorHelpersUseSpecificCodes(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		code connect.Code
	}{
		{name: "report not found", err: reportConnectError(reports.ErrReportNotFound), code: connect.CodeNotFound},
		{name: "report unavailable", err: reportConnectError(reports.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "report invalid", err: reportConnectError(reports.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "report unknown", err: reportConnectError(errors.New("storage failed")), code: connect.CodeInternal},
		{name: "report canceled", err: reportConnectError(context.Canceled), code: connect.CodeCanceled},
		{name: "report deadline", err: reportConnectError(context.DeadlineExceeded), code: connect.CodeDeadlineExceeded},
		{name: "source not found", err: sourceConnectError(sourceops.ErrSourceNotFound), code: connect.CodeNotFound},
		{name: "source invalid", err: sourceConnectError(sourceops.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "source unknown", err: sourceConnectError(errors.New("transport failed")), code: connect.CodeInternal},
		{name: "runtime not found", err: sourceRuntimeConnectError(ports.ErrSourceRuntimeNotFound), code: connect.CodeNotFound},
		{name: "runtime unavailable", err: sourceRuntimeConnectError(sourceruntime.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "runtime invalid", err: sourceRuntimeConnectError(sourceruntime.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "runtime unknown", err: sourceRuntimeConnectError(errors.New("persist failed")), code: connect.CodeInternal},
		{name: "claim runtime not found", err: claimConnectError(ports.ErrSourceRuntimeNotFound), code: connect.CodeNotFound},
		{name: "claim invalid", err: claimConnectError(claims.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "claim unknown", err: claimConnectError(errors.New("persist failed")), code: connect.CodeInternal},
		{name: "finding not found", err: findingConnectError(ports.ErrFindingNotFound), code: connect.CodeNotFound},
		{name: "finding rule not found", err: findingConnectError(findings.ErrRuleNotFound), code: connect.CodeNotFound},
		{name: "finding rule selection required", err: findingConnectError(findings.ErrRuleSelectionRequired), code: connect.CodeInvalidArgument},
		{name: "finding rule unsupported", err: findingConnectError(findings.ErrRuleUnsupported), code: connect.CodeInvalidArgument},
		{name: "finding invalid", err: findingConnectError(findings.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "finding rule unavailable", err: findingConnectError(findings.ErrRuleUnavailable), code: connect.CodeFailedPrecondition},
		{name: "finding unavailable", err: findingConnectError(findings.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "finding unknown", err: findingConnectError(errors.New("finding store failed")), code: connect.CodeInternal},
		{name: "knowledge entity not found", err: knowledgeConnectError(ports.ErrGraphEntityNotFound), code: connect.CodeNotFound},
		{name: "knowledge invalid", err: knowledgeConnectError(knowledge.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "knowledge unavailable", err: knowledgeConnectError(knowledge.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "knowledge unknown", err: knowledgeConnectError(errors.New("knowledge store failed")), code: connect.CodeInternal},
		{name: "workflow replay unavailable", err: workflowReplayConnectError(workflowprojection.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "workflow replay unknown", err: workflowReplayConnectError(errors.New("replay failed")), code: connect.CodeInternal},
		{name: "graph query entity not found", err: graphQueryConnectError(ports.ErrGraphEntityNotFound), code: connect.CodeNotFound},
		{name: "graph query unavailable", err: graphQueryConnectError(graphquery.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "graph query invalid", err: graphQueryConnectError(graphquery.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "graph ingest run not found", err: graphIngestConnectError(graphingest.ErrRunNotFound), code: connect.CodeNotFound},
		{name: "graph ingest source not found", err: graphIngestConnectError(sourceops.ErrSourceNotFound), code: connect.CodeNotFound},
		{name: "graph ingest unavailable", err: graphIngestConnectError(graphingest.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "graph ingest invalid", err: graphIngestConnectError(graphingest.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "graph ingest unknown", err: graphIngestConnectError(errors.New("graph ingest failed")), code: connect.CodeInternal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(tt.err); got != tt.code {
				t.Fatalf("connect.CodeOf() = %s, want %s", got, tt.code)
			}
		})
	}
}

func TestConnectInternalErrorsHideDetails(t *testing.T) {
	internalErr := errors.New("postgres password leaked")
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "report", err: reportConnectError(internalErr)},
		{name: "source", err: sourceConnectError(internalErr)},
		{name: "runtime", err: sourceRuntimeConnectError(internalErr)},
		{name: "claim", err: claimConnectError(internalErr)},
		{name: "finding", err: findingConnectError(internalErr)},
		{name: "knowledge", err: knowledgeConnectError(internalErr)},
		{name: "workflow replay", err: workflowReplayConnectError(internalErr)},
		{name: "graph query", err: graphQueryConnectError(internalErr)},
		{name: "graph ingest", err: graphIngestConnectError(internalErr)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(tt.err); got != connect.CodeInternal {
				t.Fatalf("connect.CodeOf() = %s, want %s", got, connect.CodeInternal)
			}
			var connectErr *connect.Error
			if !errors.As(tt.err, &connectErr) {
				t.Fatalf("error = %T, want *connect.Error", tt.err)
			}
			if strings.Contains(connectErr.Message(), "postgres password leaked") {
				t.Fatalf("connect error exposed internal detail: %q", connectErr.Message())
			}
			if !strings.Contains(connectErr.Message(), "internal error") {
				t.Fatalf("connect error = %q, want generic internal error", connectErr.Message())
			}
		})
	}
}

func TestFindingEvaluationRunJSONSurfacesGraphDefaultsWithoutPresenceFields(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		},
		findingEvaluationRuns: map[string]*cerebrov1.FindingEvaluationRun{
			"running-run": {
				Id:            "running-run",
				RuntimeId:     "writer-okta-audit",
				RuleId:        "identity-okta-policy-rule-lifecycle-tampering",
				Status:        "running",
				StartedAt:     timestamppb.New(time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)),
				GraphRule:     proto.Bool(false),
				GraphRowsRead: proto.Uint32(0),
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	restResp, err := server.Client().Get(server.URL + "/finding-evaluation-runs/running-run")
	if err != nil {
		t.Fatalf("GET /finding-evaluation-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := restResp.Body.Close(); closeErr != nil {
			t.Fatalf("close REST evaluation run response body: %v", closeErr)
		}
	}()
	var restPayload map[string]any
	if err := json.NewDecoder(restResp.Body).Decode(&restPayload); err != nil {
		t.Fatalf("decode REST evaluation run response: %v", err)
	}
	restRun, ok := restPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("REST run payload = %#v, want object", restPayload["run"])
	}
	if got, present := restRun["graph_rule"]; !present || got != false {
		t.Fatalf("REST graph_rule = %#v (present=%t), want false present", got, present)
	}
	if got, present := restRun["graph_rows_read"]; !present || got != float64(0) {
		t.Fatalf("REST graph_rows_read = %#v (present=%t), want 0 present", got, present)
	}
	if _, present := restRun["finished_at"]; present {
		t.Fatalf("REST finished_at present on running run: %#v", restRun["finished_at"])
	}
	if _, present := restRun["finding_ids"]; present {
		t.Fatalf("REST finding_ids present on running run: %#v", restRun["finding_ids"])
	}

	connectReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure,
		strings.NewReader(`{"id":"running-run"}`),
	)
	if err != nil {
		t.Fatalf("new Connect evaluation run request: %v", err)
	}
	connectReq.Header.Set("Content-Type", "application/json")
	connectReq.Header.Set("Connect-Protocol-Version", "1")
	connectResp, err := server.Client().Do(connectReq)
	if err != nil {
		t.Fatalf("Connect GetFindingEvaluationRun error = %v", err)
	}
	defer func() {
		if closeErr := connectResp.Body.Close(); closeErr != nil {
			t.Fatalf("close Connect evaluation run response body: %v", closeErr)
		}
	}()
	var connectPayload map[string]any
	if err := json.NewDecoder(connectResp.Body).Decode(&connectPayload); err != nil {
		t.Fatalf("decode Connect evaluation run response: %v", err)
	}
	connectRun, ok := connectPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("Connect run payload = %#v, want object", connectPayload["run"])
	}
	if got, present := connectRun["graphRule"]; !present || got != false {
		t.Fatalf("Connect graphRule = %#v (present=%t), want false present", got, present)
	}
	if got, present := connectRun["graphRowsRead"]; !present || got != float64(0) {
		t.Fatalf("Connect graphRowsRead = %#v (present=%t), want 0 present", got, present)
	}
	if _, present := connectRun["finishedAt"]; present {
		t.Fatalf("Connect finishedAt present on running run: %#v", connectRun["finishedAt"])
	}
	if _, present := connectRun["findingIds"]; present {
		t.Fatalf("Connect findingIds present on running run: %#v", connectRun["findingIds"])
	}
}

func TestWriteSourceRuntimeErrorDoesNotExposeInternalMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeSourceRuntimeError(recorder, errors.New("postgres password leaked"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if strings.Contains(recorder.Body.String(), "postgres password leaked") {
		t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
	}

	invalid := httptest.NewRecorder()
	writeSourceRuntimeError(invalid, sourceruntime.ErrInvalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid runtime status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}
}

func TestResolveRuntimeSourceConfigClassifiesEnvErrorsAsInvalidRequest(t *testing.T) {
	_, err := resolveRuntimeSourceConfig(context.Background(), "github", map[string]string{ // #nosec G101 -- env-reference test fixture, not credential material.
		"token": "env:AWS_SECRET_ACCESS_KEY",
	})
	if !errors.Is(err, sourceruntime.ErrInvalidRequest) {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v, want invalid request", err)
	}

	recorder := httptest.NewRecorder()
	writeSourceRuntimeError(recorder, err)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if got := connect.CodeOf(sourceRuntimeConnectError(err)); got != connect.CodeInvalidArgument {
		t.Fatalf("connect code = %s, want %s", got, connect.CodeInvalidArgument)
	}
}

func TestResolveRuntimeSourceConfigAuthorizesResolvedTenantID(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_AZURE_TENANT_ID", "other")
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	})

	_, err := resolveRuntimeSourceConfig(ctx, "azure", map[string]string{
		"tenant_id": "env:CEREBRO_SOURCE_AZURE_TENANT_ID",
	})
	if !errors.Is(err, errTenantForbidden) {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v, want tenant forbidden", err)
	}
}

func TestResolveRuntimeSourceConfigRejectsTenantScopedEnvSelectors(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_OWNER", "writer")
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	})

	_, err := resolveRuntimeSourceConfig(ctx, "github", map[string]string{
		"owner": "env:CEREBRO_SOURCE_GITHUB_OWNER",
	})
	if !errors.Is(err, errTenantForbidden) {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v, want tenant forbidden", err)
	}
}

func TestResolveRuntimeSourceConfigRejectsUnscopedAWSSecretReferences(t *testing.T) {
	_, err := resolveRuntimeSourceConfigWithStore(
		context.Background(),
		config.ConnectorCredentialConfig{},
		config.ConnectorSecretStoreConfig{
			Enabled: []string{connectorStoreAWSSecretsManager},
			AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
				Region: "us-east-1",
			},
		},
		nil,
		"aws",
		map[string]string{
			sourceconfig.RuntimeTenantIDKey: "tenant-a",
			sourceconfig.RuntimeIDKey:       "runtime-a",
			"value":                         "aws-sm:us-east-1:shared/credentials#value",
		},
	)
	if !errors.Is(err, sourceruntime.ErrInvalidRequest) {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v, want invalid request", err)
	}
}

func TestResolveRuntimeSourceConfigAllowsTenantScopedLiteralEnvQuerySelectors(t *testing.T) {
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	})

	resolved, err := resolveRuntimeSourceConfig(ctx, "github", map[string]string{
		"phrase": "env:prod",
	})
	if err != nil {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v", err)
	}
	if got := resolved["phrase"]; got != "env:prod" {
		t.Fatalf("resolved phrase = %q, want env:prod", got)
	}
}

func TestResolveRuntimeSourceConfigAllowsAdminEnvSelectors(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_OWNER", "writer")
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{},
	})

	resolved, err := resolveRuntimeSourceConfig(ctx, "github", map[string]string{
		"owner": "env:CEREBRO_SOURCE_GITHUB_OWNER",
	})
	if err != nil {
		t.Fatalf("resolveRuntimeSourceConfig() error = %v", err)
	}
	if got := resolved["owner"]; got != "writer" {
		t.Fatalf("resolved owner = %q, want writer", got)
	}
}

func TestAuthorizeHTTPRequestTenantSkipsEnvTenantPlaceholders(t *testing.T) {
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	})
	err := authorizeHTTPRequestTenant(ctx, &cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			TenantId: "writer",
			Config: map[string]string{
				"tenant_id": "env:CEREBRO_SOURCE_AZURE_TENANT_ID",
			},
		},
	})
	if err != nil {
		t.Fatalf("authorizeHTTPRequestTenant() error = %v, want nil", err)
	}
}

func TestGraphIngestRuntimeUsesRuntimeConfigAuthorization(t *testing.T) {
	t.Setenv("CEREBRO_SOURCE_GITHUB_OWNER", "writer")
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	})
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-github": {
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer",
			Config:   map[string]string{"owner": "env:CEREBRO_SOURCE_GITHUB_OWNER"},
		},
	}}
	service := newGraphIngestService(config.Config{}, Dependencies{StateStore: store, GraphStore: &stubGraphStore{}}, registry)

	_, err = service.RunRuntime(ctx, graphingest.RuntimeRequest{RuntimeID: "writer-github"})
	if !errors.Is(err, errTenantForbidden) {
		t.Fatalf("RunRuntime() error = %v, want tenant forbidden", err)
	}
}

func TestWriteKnowledgeErrorMapsInvalidRequestToBadRequest(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeKnowledgeError(recorder, knowledge.ErrInvalidRequest)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestWriteHTTPErrorHelpersDoNotExposeInternalMessages(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "source", write: writeSourceError},
		{name: "claim", write: writeClaimError},
		{name: "finding", write: writeFindingError},
		{name: "knowledge", write: writeKnowledgeError},
		{name: "workflow replay", write: writeWorkflowReplayError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, errors.New("postgres password leaked"))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
			}
			if strings.Contains(recorder.Body.String(), "postgres password leaked") {
				t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
				t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
			}
		})
	}
}

func TestInvalidHTTPRequestErrorsReturnBadRequest(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "source", write: writeSourceError},
		{name: "report", write: writeReportError},
		{name: "source runtime", write: writeSourceRuntimeError},
		{name: "claim", write: writeClaimError},
		{name: "finding", write: writeFindingError},
		{name: "knowledge", write: writeKnowledgeError},
		{name: "workflow replay", write: writeWorkflowReplayError},
		{name: "graph query", write: writeGraphQueryError},
		{name: "graph ingest", write: writeGraphIngestError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, invalidHTTPRequestError(errors.New("bad query param")))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestWriteReportErrorDoesNotExposeInternalMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeReportError(recorder, errors.New("postgres password leaked"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if strings.Contains(recorder.Body.String(), "postgres password leaked") {
		t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
	}

	invalid := httptest.NewRecorder()
	writeReportError(invalid, reports.ErrInvalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid report status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}
}

func TestWriteGraphErrorsDoNotExposeInternalMessages(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "query", write: writeGraphQueryError},
		{name: "ingest", write: writeGraphIngestError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, errors.New("postgres password leaked"))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
			}
			if strings.Contains(recorder.Body.String(), "postgres password leaked") {
				t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
				t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
			}
		})
	}
}

func TestStoreBoundaryHelpersTreatTypedNilAsUnavailable(t *testing.T) {
	var graph *stubGraphStore
	if got := graphQueryStore(graph); got != nil {
		t.Fatalf("graphQueryStore(typed nil) = %#v, want nil", got)
	}
	if got := sourceProjectionGraphStore(graph); got != nil {
		t.Fatalf("sourceProjectionGraphStore(typed nil) = %#v, want nil", got)
	}
	var state *stubRuntimeStore
	if got := sourceRuntimeStore(state); got != nil {
		t.Fatalf("sourceRuntimeStore(typed nil) = %#v, want nil", got)
	}
	if got := reportStore(state); got != nil {
		t.Fatalf("reportStore(typed nil) = %#v, want nil", got)
	}
	var log *recordingAppendLog
	if got := eventReplayer(log); got != nil {
		t.Fatalf("eventReplayer(typed nil) = %#v, want nil", got)
	}
}

type stubAppendLog struct {
	err error
}

func (s stubAppendLog) Ping(context.Context) error                             { return s.err }
func (s stubAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return s.err }

type stubStore struct {
	err error
}

func (s stubStore) Ping(context.Context) error { return s.err }

type deadlineAwareStore struct {
	sawDeadline bool
}

func (s *deadlineAwareStore) Ping(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("health check deadline is required")
	}
	s.sawDeadline = true
	return nil
}

type typedNilPinger struct{}

func (s *typedNilPinger) Ping(context.Context) error {
	return errors.New("typed nil pinger was called")
}

type recordingAppendLog struct {
	err            error
	events         []*cerebrov1.EventEnvelope
	replayEvents   []*cerebrov1.EventEnvelope
	replayRequests []ports.ReplayRequest
	indexScans     []ports.RuntimeIndexScan
	indexScanCalls int
	enforceIndex   bool
	indexReady     bool
}

func (s *recordingAppendLog) Ping(context.Context) error { return s.err }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

func (s *recordingAppendLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.enforceIndex && request.RequireRuntimeIndex && !s.indexReady {
		return nil, errors.New("runtime index required but not ready")
	}
	s.replayRequests = append(s.replayRequests, request)
	source := s.events
	if len(s.replayEvents) != 0 {
		source = s.replayEvents
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(source))
	for _, event := range source {
		if event == nil {
			continue
		}
		if request.RuntimeID != "" && event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != request.RuntimeID {
			continue
		}
		if !replayEventMatchesKindPrefixes(event.GetKind(), request.KindPrefix, request.KindPrefixes) {
			continue
		}
		if request.TenantID != "" && event.GetTenantId() != request.TenantID {
			continue
		}
		if !matchesReplayAttributes(event, request.AttributeEquals) {
			continue
		}
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
		if request.Limit != 0 && uint32(len(events)) >= request.Limit { // #nosec G115 -- replay fixture size is bounded by in-memory test setup.
			break
		}
	}
	return events, nil
}

func (s *recordingAppendLog) ScanRuntimeIndex(_ context.Context, fromSeq uint64, _ uint32) (ports.RuntimeIndexScan, error) {
	s.indexScanCalls++
	idx := s.indexScanCalls - 1
	if idx < len(s.indexScans) {
		scan := s.indexScans[idx]
		if scan.Watermark > 0 {
			s.indexReady = true
		}
		return scan, nil
	}
	return ports.RuntimeIndexScan{Watermark: fromSeq, CaughtUp: true}, nil
}

func replayEventMatchesKindPrefixes(kind string, kindPrefix string, kindPrefixes []string) bool {
	if strings.TrimSpace(kindPrefix) == "" && len(kindPrefixes) == 0 {
		return true
	}
	if strings.TrimSpace(kindPrefix) != "" && strings.HasPrefix(kind, strings.TrimSpace(kindPrefix)) {
		return true
	}
	for _, prefix := range kindPrefixes {
		if strings.TrimSpace(prefix) != "" && strings.HasPrefix(kind, strings.TrimSpace(prefix)) {
			return true
		}
	}
	return false
}

func matchesReplayAttributes(event *cerebrov1.EventEnvelope, expected map[string]string) bool {
	for key, value := range expected {
		if event.GetAttributes()[key] != value {
			return false
		}
	}
	return true
}

type stubRuntimeStore struct {
	mu                              sync.Mutex
	err                             error
	runtimes                        map[string]*cerebrov1.SourceRuntime
	sourceRuntimeListFilter         ports.SourceRuntimeFilter
	entities                        map[string]*ports.ProjectedEntity
	links                           map[string]*ports.ProjectedLink
	claims                          map[string]*ports.ClaimRecord
	claimListRequest                ports.ListClaimsRequest
	findings                        map[string]*ports.FindingRecord
	findingListRequest              ports.ListFindingsRequest
	findingEvidence                 map[string]*cerebrov1.FindingEvidence
	findingEvidenceListRequest      ports.ListFindingEvidenceRequest
	findingEvaluationRuns           map[string]*cerebrov1.FindingEvaluationRun
	findingEvaluationRunListRequest ports.ListFindingEvaluationRunsRequest
	findingCandidateRuns            map[string]*ports.FindingCandidateRun
	findingCandidates               map[string]*ports.FindingCandidateRecord
	findingCandidateListRequest     ports.ListFindingCandidatesRequest
	reportRuns                      map[string]*cerebrov1.ReportRun
	grcAuditPackets                 map[string]*ports.GRCAuditPacketReceipt
	runtimeIndexWatermark           uint64
	runtimeIndexWatermarks          []uint64
}

// leaseAwareRuntimeStore embeds stubRuntimeStore and additionally
// implements ports.SourceRuntimeLeaseStore so the bootstrap layer's
// SyncWithLease path can be exercised end-to-end. holdsAll=true makes
// every Acquire fail; tests use this to drive the lease-held conflict
// path.
type leaseAwareRuntimeStore struct {
	*stubRuntimeStore
	mu       sync.Mutex
	holder   string
	holdsAll bool
}

func (s *leaseAwareRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, _ string, owner string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holdsAll && s.holder != owner {
		return false, nil
	}
	s.holder = owner
	return true, nil
}

func (s *leaseAwareRuntimeStore) RenewSourceRuntimeLease(_ context.Context, _ string, owner string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holder == owner, nil
}

func (s *leaseAwareRuntimeStore) ReleaseSourceRuntimeLease(_ context.Context, _ string, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holder == owner {
		s.holder = ""
	}
	return nil
}

func (s *stubRuntimeStore) Ping(context.Context) error { return s.err }

func (s *stubRuntimeStore) ApplyAuditProjectionEvent(_ context.Context, event *cerebrov1.EventEnvelope) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	recorded, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return false, err
	}
	var packet grcauditpacket.Packet
	if err := json.Unmarshal([]byte(recorded.PayloadJSON), &packet); err != nil {
		return false, err
	}
	if err := grcauditpacket.Verify(packet); err != nil {
		return false, err
	}
	if s.grcAuditPackets == nil {
		s.grcAuditPackets = make(map[string]*ports.GRCAuditPacketReceipt)
	}
	if _, exists := s.grcAuditPackets[packet.ID]; exists {
		return false, nil
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		return false, err
	}
	s.grcAuditPackets[packet.ID] = &ports.GRCAuditPacketReceipt{
		ID: packet.ID, TenantID: packet.TenantID, FindingID: packet.FindingReference.ID,
		Digest: packet.Digest, Payload: payload, CreatedAt: packet.GeneratedAt,
	}
	return true, nil
}

func (s *stubRuntimeStore) GetGRCAuditPacket(_ context.Context, packetID string) (*ports.GRCAuditPacketReceipt, error) {
	if s.err != nil {
		return nil, s.err
	}
	receipt, ok := s.grcAuditPackets[packetID]
	if !ok {
		return nil, ports.ErrGRCAuditPacketNotFound
	}
	copy := *receipt
	copy.Payload = append([]byte(nil), receipt.Payload...)
	return &copy, nil
}

func (s *stubRuntimeStore) RuntimeIndexWatermark(context.Context) (uint64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.runtimeIndexWatermark, nil
}

func (s *stubRuntimeStore) PutRuntimeIndexEntries(_ context.Context, _ []ports.RuntimeIndexEntry, watermark uint64) error {
	if s.err != nil {
		return s.err
	}
	s.runtimeIndexWatermark = watermark
	s.runtimeIndexWatermarks = append(s.runtimeIndexWatermarks, watermark)
	return nil
}

func (s *stubRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	if s.runtimes == nil {
		s.runtimes = make(map[string]*cerebrov1.SourceRuntime)
	}
	s.runtimes[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

func (s *stubRuntimeStore) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.sourceRuntimeListFilter = filter
	var ids []string
	for id := range s.runtimes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var runtimes []*cerebrov1.SourceRuntime
	allowedRuntimeIDs := normalizedTestStrings(append(filter.RuntimeIDs, filter.RuntimeID))
	for _, id := range ids {
		runtime := s.runtimes[id]
		if len(allowedRuntimeIDs) != 0 && !containsTrimmed(allowedRuntimeIDs, runtime.GetId()) {
			continue
		}
		if filter.TenantID != "" && runtime.GetTenantId() != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && runtime.GetSourceId() != filter.SourceID {
			continue
		}
		runtimes = append(runtimes, proto.Clone(runtime).(*cerebrov1.SourceRuntime))
	}
	if filter.Limit != 0 && len(runtimes) > int(filter.Limit) {
		runtimes = runtimes[:filter.Limit]
	}
	return runtimes, nil
}

func (s *stubRuntimeStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubRuntimeStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func (s *stubRuntimeStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if finding == nil {
		return nil, nil
	}
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	cloned := cloneFinding(finding)
	if existing, ok := s.findings[cloned.ID]; ok {
		cloned = preserveFindingWorkflow(existing, cloned)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) GetFinding(_ context.Context, id string) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[id]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	return cloneFinding(finding), nil
}

func (s *stubRuntimeStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if claim == nil {
		return nil, nil
	}
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	s.claims[claim.ID] = cloneClaim(claim)
	return cloneClaim(claim), nil
}

func (s *stubRuntimeStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.claimListRequest = request
	claims := []*ports.ClaimRecord{}
	for _, claim := range s.claims {
		if !claimMatches(request, claim) {
			continue
		}
		claims = append(claims, cloneClaim(claim))
	}
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i]
		right := claims[j]
		switch {
		case left.ObservedAt.Equal(right.ObservedAt) && left.UpdatedAt.Equal(right.UpdatedAt):
			return left.ID < right.ID
		case left.ObservedAt.Equal(right.ObservedAt):
			return left.UpdatedAt.After(right.UpdatedAt)
		case left.ObservedAt.IsZero():
			return false
		case right.ObservedAt.IsZero():
			return true
		default:
			return left.ObservedAt.After(right.ObservedAt)
		}
	})
	if request.Limit != 0 && len(claims) > int(request.Limit) {
		claims = claims[:int(request.Limit)]
	}
	return claims, nil
}

func (s *stubRuntimeStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingListRequest = request
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		if request.PriorityOrder && severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func (s *stubRuntimeStore) ListEndpointVulnerabilityFindingRecords(_ context.Context, request ports.EndpointVulnerabilityFindingQuery) ([]*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !endpointVulnerabilityFindingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func (s *stubRuntimeStore) SummarizeFindings(_ context.Context, request ports.ListFindingsRequest) (ports.FindingSummary, error) {
	if s.err != nil {
		return ports.FindingSummary{}, s.err
	}
	summary := ports.FindingSummary{
		BySeverity:       map[string]int{},
		ByStatus:         map[string]int{},
		RiskReasonCounts: map[string]int{},
	}
	controls := map[string]struct{}{}
	now := time.Now().UTC()
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		summary.TotalFindings++
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status == "" {
			status = "unknown"
		}
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		if severity == "" {
			severity = "unknown"
		}
		summary.ByStatus[status]++
		summary.BySeverity[severity]++
		if finding.RiskScore > summary.MaxRiskScore {
			summary.MaxRiskScore = finding.RiskScore
		}
		summary.RiskScoreTotal += finding.RiskScore
		for _, reason := range finding.RiskReasons {
			reason = strings.TrimSpace(reason)
			if reason != "" {
				summary.RiskReasonCounts[reason]++
			}
		}
		if status == "open" {
			summary.OpenFindings++
			if severity == "critical" {
				summary.CriticalFindings++
			}
			if severity == "high" {
				summary.HighFindings++
			}
			if !finding.DueAt.IsZero() && now.After(finding.DueAt.UTC()) {
				summary.OverdueFindings++
			}
			if strings.TrimSpace(finding.Assignee) == "" {
				summary.Unassigned++
			}
			if len(finding.ControlRefs) == 0 {
				controls["Unmapped\x00Needs mapping"] = struct{}{}
				continue
			}
			for _, ref := range finding.ControlRefs {
				framework := strings.TrimSpace(ref.FrameworkName)
				controlID := strings.TrimSpace(ref.ControlID)
				if framework == "" {
					framework = "Unmapped"
				}
				if controlID == "" {
					controlID = "Needs mapping"
				}
				controls[framework+"\x00"+controlID] = struct{}{}
			}
		}
	}
	summary.ControlsFailing = len(controls)
	for control := range controls {
		summary.FailingControlKeys = append(summary.FailingControlKeys, control)
	}
	sort.Strings(summary.FailingControlKeys)
	return summary, nil
}

func (s *stubRuntimeStore) UpdateFindingStatus(_ context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Status = strings.TrimSpace(request.Status)
	cloned.StatusReason = strings.TrimSpace(request.Reason)
	cloned.StatusUpdatedAt = request.UpdatedAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) UpdateFindingAssignee(_ context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Assignee = strings.TrimSpace(request.Assignee)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) UpdateFindingDueDate(_ context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.DueAt = request.DueAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) AddFindingNote(_ context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Notes = append(cloned.Notes, request.Note)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) LinkFindingTicket(_ context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	exists := false
	for _, ticket := range cloned.Tickets {
		if strings.TrimSpace(ticket.URL) == strings.TrimSpace(request.Ticket.URL) {
			exists = true
			break
		}
	}
	if !exists {
		cloned.Tickets = append(cloned.Tickets, request.Ticket)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) LinkFindingExternalRef(_ context.Context, request ports.FindingExternalRefLink) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	replaced := false
	for index, ref := range cloned.ExternalRefs {
		if externalRefKey(ref) == externalRefKey(request.ExternalRef) {
			cloned.ExternalRefs[index] = request.ExternalRef
			replaced = true
			break
		}
	}
	if !replaced {
		cloned.ExternalRefs = append(cloned.ExternalRefs, request.ExternalRef)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func externalRefKey(ref ports.FindingExternalRef) string {
	return strings.TrimSpace(ref.System) + "|" + strings.TrimSpace(ref.Kind) + "|" + strings.TrimSpace(ref.ExternalID)
}

func (s *stubRuntimeStore) PutFindingEvidence(_ context.Context, evidence *cerebrov1.FindingEvidence) error {
	if s.err != nil {
		return s.err
	}
	if evidence == nil {
		return nil
	}
	if s.findingEvidence == nil {
		s.findingEvidence = make(map[string]*cerebrov1.FindingEvidence)
	}
	s.findingEvidence[evidence.GetId()] = cloneFindingEvidence(evidence)
	return nil
}

func (s *stubRuntimeStore) GetFindingEvidence(_ context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	if s.err != nil {
		return nil, s.err
	}
	evidence, ok := s.findingEvidence[id]
	if !ok {
		return nil, ports.ErrFindingEvidenceNotFound
	}
	return cloneFindingEvidence(evidence), nil
}

func (s *stubRuntimeStore) ListFindingEvidence(_ context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingEvidenceListRequest = request
	evidence := []*cerebrov1.FindingEvidence{}
	for _, record := range s.findingEvidence {
		if !findingEvidenceMatches(request, record) {
			continue
		}
		evidence = append(evidence, cloneFindingEvidence(record))
	}
	sort.Slice(evidence, func(i, j int) bool {
		left := evidence[i]
		right := evidence[j]
		switch {
		case left.GetCreatedAt().AsTime().Equal(right.GetCreatedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetCreatedAt().AsTime().After(right.GetCreatedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(evidence) > int(request.Limit) {
		evidence = evidence[:int(request.Limit)]
	}
	return evidence, nil
}

func (s *stubRuntimeStore) CountFindingEvidence(_ context.Context, request ports.ListFindingEvidenceRequest) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	count := 0
	for _, record := range s.findingEvidence {
		if findingEvidenceMatches(request, record) {
			count++
		}
	}
	return count, nil
}

func (s *stubRuntimeStore) PutFindingCandidateRun(_ context.Context, run *ports.FindingCandidateRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.findingCandidateRuns == nil {
		s.findingCandidateRuns = make(map[string]*ports.FindingCandidateRun)
	}
	cloned := *run
	s.findingCandidateRuns[cloned.ID] = &cloned
	return nil
}

func (s *stubRuntimeStore) GetFindingCandidateRun(_ context.Context, id string) (*ports.FindingCandidateRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.findingCandidateRuns[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	cloned := *run
	return &cloned, nil
}

func (s *stubRuntimeStore) ListFindingCandidateRuns(_ context.Context, request ports.ListFindingCandidatesRequest) ([]*ports.FindingCandidateRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	runs := []*ports.FindingCandidateRun{}
	for _, run := range s.findingCandidateRuns {
		if request.RuntimeID != "" && strings.TrimSpace(run.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
			continue
		}
		cloned := *run
		runs = append(runs, &cloned)
	}
	return runs, nil
}

func (s *stubRuntimeStore) UpsertFindingCandidate(_ context.Context, candidate *ports.FindingCandidateRecord) (*ports.FindingCandidateRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if candidate == nil {
		return nil, nil
	}
	if s.findingCandidates == nil {
		s.findingCandidates = make(map[string]*ports.FindingCandidateRecord)
	}
	cloned := cloneFindingCandidate(candidate)
	if existing := s.findingCandidates[cloned.ID]; existing != nil {
		cloned.ObservationCount += existing.ObservationCount
	}
	s.findingCandidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
}

func (s *stubRuntimeStore) GetFindingCandidate(_ context.Context, id string) (*ports.FindingCandidateRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	candidate, ok := s.findingCandidates[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	return cloneFindingCandidate(candidate), nil
}

func (s *stubRuntimeStore) ListFindingCandidates(_ context.Context, request ports.ListFindingCandidatesRequest) ([]*ports.FindingCandidateRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingCandidateListRequest = request
	candidates := []*ports.FindingCandidateRecord{}
	for _, candidate := range s.findingCandidates {
		if request.RuntimeID != "" && strings.TrimSpace(candidate.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
			continue
		}
		if request.CandidateID != "" && strings.TrimSpace(candidate.ID) != strings.TrimSpace(request.CandidateID) {
			continue
		}
		if request.RuleID != "" && strings.TrimSpace(candidate.RuleID) != strings.TrimSpace(request.RuleID) {
			continue
		}
		if request.Status != "" && strings.TrimSpace(candidate.Status) != strings.TrimSpace(request.Status) {
			continue
		}
		if request.Fingerprint != "" && strings.TrimSpace(candidate.Fingerprint) != strings.TrimSpace(request.Fingerprint) {
			continue
		}
		candidates = append(candidates, cloneFindingCandidate(candidate))
	}
	return candidates, nil
}

func (s *stubRuntimeStore) ExpireStaleFindingCandidates(_ context.Context, request ports.FindingCandidateExpiration) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	eventIDs := map[string]struct{}{}
	for _, eventID := range request.EvaluatedEventIDs {
		if eventID = strings.TrimSpace(eventID); eventID != "" {
			eventIDs[eventID] = struct{}{}
		}
	}
	if len(eventIDs) == 0 {
		return 0, nil
	}
	expired := 0
	for id, candidate := range s.findingCandidates {
		if strings.TrimSpace(candidate.TenantID) != strings.TrimSpace(request.TenantID) ||
			strings.TrimSpace(candidate.RuntimeID) != strings.TrimSpace(request.RuntimeID) ||
			strings.TrimSpace(candidate.RuleID) != strings.TrimSpace(request.RuleID) ||
			strings.TrimSpace(candidate.Status) != "candidate" ||
			strings.TrimSpace(candidate.LastRunID) == strings.TrimSpace(request.RunID) ||
			(!candidate.UpdatedAt.IsZero() && !candidate.UpdatedAt.Before(request.RunStartedAt)) {
			continue
		}
		overlap := false
		if candidate.Finding != nil {
			for _, eventID := range candidate.Finding.EventIDs {
				if _, ok := eventIDs[strings.TrimSpace(eventID)]; ok {
					overlap = true
					break
				}
			}
		}
		if !overlap {
			continue
		}
		cloned := cloneFindingCandidate(candidate)
		cloned.Status = "expired"
		cloned.UpdatedAt = time.Now().UTC()
		s.findingCandidates[id] = cloned
		expired++
	}
	return expired, nil
}

func (s *stubRuntimeStore) MarkFindingCandidatePromoted(_ context.Context, promotion ports.FindingCandidatePromotion) (*ports.FindingCandidateRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	candidate, ok := s.findingCandidates[strings.TrimSpace(promotion.CandidateID)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned := cloneFindingCandidate(candidate)
	if cloned.Status != "candidate" {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned.Status = "promoted"
	cloned.PromotedFindingID = strings.TrimSpace(promotion.PromotedFindingID)
	cloned.DecisionID = strings.TrimSpace(promotion.DecisionID)
	cloned.PromotedBy = strings.TrimSpace(promotion.PromotedBy)
	cloned.PromotionRationale = strings.TrimSpace(promotion.Rationale)
	cloned.ChangeTicket = strings.TrimSpace(promotion.ChangeTicket)
	cloned.PromotedAt = promotion.PromotedAt.UTC()
	s.findingCandidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
}

func (s *stubRuntimeStore) MarkFindingCandidateRejected(_ context.Context, rejection ports.FindingCandidateRejection) (*ports.FindingCandidateRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	candidate, ok := s.findingCandidates[strings.TrimSpace(rejection.CandidateID)]
	if !ok {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned := cloneFindingCandidate(candidate)
	if cloned.Status != "candidate" {
		return nil, ports.ErrFindingCandidateNotFound
	}
	cloned.Status = "rejected"
	cloned.DecisionID = strings.TrimSpace(rejection.DecisionID)
	cloned.RejectedBy = strings.TrimSpace(rejection.RejectedBy)
	cloned.RejectionRationale = strings.TrimSpace(rejection.Rationale)
	cloned.RejectedAt = rejection.RejectedAt.UTC()
	s.findingCandidates[cloned.ID] = cloned
	return cloneFindingCandidate(cloned), nil
}

func (s *stubRuntimeStore) PutFindingEvaluationRun(_ context.Context, run *cerebrov1.FindingEvaluationRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.findingEvaluationRuns == nil {
		s.findingEvaluationRuns = make(map[string]*cerebrov1.FindingEvaluationRun)
	}
	s.findingEvaluationRuns[run.GetId()] = cloneFindingEvaluationRun(run)
	return nil
}

func (s *stubRuntimeStore) GetFindingEvaluationRun(_ context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.findingEvaluationRuns[id]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	return cloneFindingEvaluationRun(run), nil
}

func (s *stubRuntimeStore) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.findingEvaluationRunListRequest = request
	runs := []*cerebrov1.FindingEvaluationRun{}
	for _, run := range s.findingEvaluationRuns {
		if !findingEvaluationRunMatches(request, run) {
			continue
		}
		runs = append(runs, cloneFindingEvaluationRun(run))
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		switch {
		case left.GetStartedAt().AsTime().Equal(right.GetStartedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetStartedAt().AsTime().After(right.GetStartedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(runs) > int(request.Limit) {
		runs = runs[:int(request.Limit)]
	}
	return runs, nil
}

func (s *stubRuntimeStore) PutReportRun(_ context.Context, run *cerebrov1.ReportRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.reportRuns == nil {
		s.reportRuns = make(map[string]*cerebrov1.ReportRun)
	}
	s.reportRuns[run.GetId()] = cloneReportRun(run)
	return nil
}

func (s *stubRuntimeStore) GetReportRun(_ context.Context, id string) (*cerebrov1.ReportRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.reportRuns[id]
	if !ok {
		return nil, ports.ErrReportRunNotFound
	}
	return cloneReportRun(run), nil
}

type stubGraphStore struct {
	mu                  sync.Mutex
	err                 error
	entities            map[string]*ports.ProjectedEntity
	links               map[string]*ports.ProjectedLink
	checkpoints         map[string]graphstore.IngestCheckpoint
	ingestRuns          map[string]graphstore.IngestRun
	neighborhood        *ports.EntityNeighborhood
	neighborhoodRootURN string
	neighborhoodLimit   int
	ingestRunListFilter graphstore.IngestRunFilter
	cypherPlan          *ports.CypherPlan
	cypherRows          [][]ports.CypherRow
	cypherRequests      []ports.CypherQueryRequest
}

func (s *stubGraphStore) Ping(context.Context) error {
	return s.err
}

func (s *stubGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.neighborhoodRootURN = rootURN
	s.neighborhoodLimit = limit
	if entity, ok := s.entities[rootURN]; ok && entity != nil {
		return &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        entity.URN,
				EntityType: entity.EntityType,
				Label:      entity.Label,
			},
		}, nil
	}
	if s.neighborhood == nil {
		return nil, ports.ErrGraphEntityNotFound
	}
	return cloneNeighborhood(s.neighborhood), nil
}

func (s *stubGraphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.cypherRequests = append(s.cypherRequests, request)
	if strings.Contains(request.Query, "RETURN n.entity_type AS name") {
		return []ports.CypherRow{{Values: map[string]any{"name": "asset", "count": int64(1)}}}, nil
	}
	if strings.Contains(request.Query, "RETURN r.relation AS name") {
		return nil, nil
	}
	if len(s.cypherRows) > 0 {
		rows := s.cypherRows[0]
		s.cypherRows = s.cypherRows[1:]
		return rows, nil
	}
	return nil, nil
}

func (s *stubGraphStore) ExplainReadCypher(_ context.Context, request ports.CypherQueryRequest) (*ports.CypherPlan, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.cypherRequests = append(s.cypherRequests, ports.CypherQueryRequest{
		Query:    "EXPLAIN " + request.Query,
		Params:   request.Params,
		RowLimit: request.RowLimit,
	})
	return s.cypherPlan, nil
}

func (s *stubGraphStore) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	if s.err != nil {
		return graphstore.IngestCheckpoint{}, false, s.err
	}
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}

func (s *stubGraphStore) PutIngestCheckpoint(_ context.Context, checkpoint graphstore.IngestCheckpoint) error {
	if s.err != nil {
		return s.err
	}
	if s.checkpoints == nil {
		s.checkpoints = make(map[string]graphstore.IngestCheckpoint)
	}
	s.checkpoints[checkpoint.ID] = checkpoint
	return nil
}

func (s *stubGraphStore) PutIngestRun(_ context.Context, run graphstore.IngestRun) error {
	if s.err != nil {
		return s.err
	}
	if s.ingestRuns == nil {
		s.ingestRuns = make(map[string]graphstore.IngestRun)
	}
	s.ingestRuns[run.ID] = run
	return nil
}

func (s *stubGraphStore) GetIngestRun(_ context.Context, id string) (graphstore.IngestRun, bool, error) {
	if s.err != nil {
		return graphstore.IngestRun{}, false, s.err
	}
	run, ok := s.ingestRuns[id]
	return run, ok, nil
}

func (s *stubGraphStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.ingestRunListFilter = filter
	runs := make([]graphstore.IngestRun, 0, len(s.ingestRuns))
	for _, run := range s.ingestRuns {
		if filter.RuntimeID != "" && run.RuntimeID != filter.RuntimeID {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		if left.StartedAt == right.StartedAt {
			return left.ID > right.ID
		}
		return left.StartedAt > right.StartedAt
	})
	if filter.Limit > 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func TestBootstrapEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /health response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /health response: %v", err)
	}
	if payload["status"] != "ready" {
		t.Fatalf("health status = %#v, want %q", payload["status"], "ready")
	}
	for _, field := range []string{"service_name", "version", "commit", "build_date", "api_version", "image_tag"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("public /health included %q metadata: %#v", field, payload[field])
		}
	}
	sourcesResp, err := server.Client().Get(server.URL + "/sources")
	if err != nil {
		t.Fatalf("GET /sources error = %v", err)
	}
	defer func() {
		if closeErr := sourcesResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources response body: %v", closeErr)
		}
	}()
	var sourcesPayload map[string]any
	if err := json.NewDecoder(sourcesResp.Body).Decode(&sourcesPayload); err != nil {
		t.Fatalf("decode /sources response: %v", err)
	}
	entries, ok := sourcesPayload["sources"].([]any)
	if !ok || len(entries) != 7 {
		t.Fatalf("/sources entries = %#v, want 7 entries", sourcesPayload["sources"])
	}
	checkResp, err := sourceGet(t, server, "/sources/github/check", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/check error = %v", err)
	}
	defer func() {
		if closeErr := checkResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/check response body: %v", closeErr)
		}
	}()
	var checkPayload map[string]any
	if err := json.NewDecoder(checkResp.Body).Decode(&checkPayload); err != nil {
		t.Fatalf("decode /sources/github/check response: %v", err)
	}
	if checkPayload["status"] != "ok" {
		t.Fatalf("check status = %#v, want %q", checkPayload["status"], "ok")
	}
	discoverResp, err := sourceGet(t, server, "/sources/github/discover", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/discover error = %v", err)
	}
	defer func() {
		if closeErr := discoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/discover response body: %v", closeErr)
		}
	}()
	var discoverPayload map[string]any
	if err := json.NewDecoder(discoverResp.Body).Decode(&discoverPayload); err != nil {
		t.Fatalf("decode /sources/github/discover response: %v", err)
	}
	urns, ok := discoverPayload["urns"].([]any)
	if !ok || len(urns) != 1 {
		t.Fatalf("discover urns = %#v, want one default GitHub repository URN", discoverPayload["urns"])
	}
	if got := urns[0]; got != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("discover urns[0] = %#v, want default GitHub repository URN", got)
	}
	readResp, err := sourceGet(t, server, "/sources/github/read", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/read error = %v", err)
	}
	defer func() {
		if closeErr := readResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/read response body: %v", closeErr)
		}
	}()
	var readPayload map[string]any
	if err := json.NewDecoder(readResp.Body).Decode(&readPayload); err != nil {
		t.Fatalf("decode /sources/github/read response: %v", err)
	}
	if events, ok := readPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("read events = %#v, want 1 entry", readPayload["events"])
	}
	repeatedCursorResp, err := sourceGet(t, server, "/sources/github/read?cursor=0&cursor=1", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/read repeated cursor error = %v", err)
	}
	defer func() {
		if closeErr := repeatedCursorResp.Body.Close(); closeErr != nil {
			t.Fatalf("close repeated cursor response body: %v", closeErr)
		}
	}()
	var repeatedCursorPayload map[string]any
	if err := json.NewDecoder(repeatedCursorResp.Body).Decode(&repeatedCursorPayload); err != nil {
		t.Fatalf("decode repeated cursor response: %v", err)
	}
	repeatedCursorEvents, ok := repeatedCursorPayload["events"].([]any)
	if !ok || len(repeatedCursorEvents) != 1 {
		t.Fatalf("repeated cursor events = %#v, want 1 entry", repeatedCursorPayload["events"])
	}
	repeatedCursorEvent, ok := repeatedCursorEvents[0].(map[string]any)
	if !ok || repeatedCursorEvent["id"] != "github-pr-2" {
		t.Fatalf("repeated cursor event = %#v, want github-pr-2", repeatedCursorEvents[0])
	}
	previewEvents, ok := readPayload["preview_events"].([]any)
	if !ok || len(previewEvents) != 1 {
		t.Fatalf("read preview_events = %#v, want 1 entry", readPayload["preview_events"])
	}
	previewEvent, ok := previewEvents[0].(map[string]any)
	if !ok || previewEvent["event_id"] != "github-pr-1" {
		t.Fatalf("read preview_event = %#v, want event_id github-pr-1", previewEvents[0])
	}
	oktaCheckResp, err := sourceGet(t, server, "/sources/okta/check?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/check error = %v", err)
	}
	defer func() {
		if closeErr := oktaCheckResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/check response body: %v", closeErr)
		}
	}()
	var oktaCheckPayload map[string]any
	if err := json.NewDecoder(oktaCheckResp.Body).Decode(&oktaCheckPayload); err != nil {
		t.Fatalf("decode /sources/okta/check response: %v", err)
	}
	if oktaCheckPayload["status"] != "ok" {
		t.Fatalf("okta check status = %#v, want %q", oktaCheckPayload["status"], "ok")
	}
	oktaDiscoverResp, err := sourceGet(t, server, "/sources/okta/discover?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/discover error = %v", err)
	}
	defer func() {
		if closeErr := oktaDiscoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/discover response body: %v", closeErr)
		}
	}()
	var oktaDiscoverPayload map[string]any
	if err := json.NewDecoder(oktaDiscoverResp.Body).Decode(&oktaDiscoverPayload); err != nil {
		t.Fatalf("decode /sources/okta/discover response: %v", err)
	}
	if urns, ok := oktaDiscoverPayload["urns"].([]any); !ok || len(urns) != 2 {
		t.Fatalf("okta discover urns = %#v, want 2 entries", oktaDiscoverPayload["urns"])
	}
	oktaReadResp, err := sourceGet(t, server, "/sources/okta/read?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/read error = %v", err)
	}
	defer func() {
		if closeErr := oktaReadResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/read response body: %v", closeErr)
		}
	}()
	var oktaReadPayload map[string]any
	if err := json.NewDecoder(oktaReadResp.Body).Decode(&oktaReadPayload); err != nil {
		t.Fatalf("decode /sources/okta/read response: %v", err)
	}
	if events, ok := oktaReadPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("okta read events = %#v, want 1 entry", oktaReadPayload["events"])
	}
	oktaPreviewEvents, ok := oktaReadPayload["preview_events"].([]any)
	if !ok || len(oktaPreviewEvents) != 1 {
		t.Fatalf("okta read preview_events = %#v, want 1 entry", oktaReadPayload["preview_events"])
	}
	datadogConfig := map[string]string{"tenant_id": "tenant"}
	datadogCheckResp, err := sourceGet(t, server, "/sources/datadog/check?family=users", datadogConfig)
	if err != nil {
		t.Fatalf("GET /sources/datadog/check error = %v", err)
	}
	defer func() {
		if closeErr := datadogCheckResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/datadog/check response body: %v", closeErr)
		}
	}()
	var datadogCheckPayload map[string]any
	if err := json.NewDecoder(datadogCheckResp.Body).Decode(&datadogCheckPayload); err != nil {
		t.Fatalf("decode /sources/datadog/check response: %v", err)
	}
	if datadogCheckPayload["status"] != "ok" {
		t.Fatalf("datadog check status = %#v, want %q", datadogCheckPayload["status"], "ok")
	}
	datadogDiscoverResp, err := sourceGet(t, server, "/sources/datadog/discover?family=users", datadogConfig)
	if err != nil {
		t.Fatalf("GET /sources/datadog/discover error = %v", err)
	}
	defer func() {
		if closeErr := datadogDiscoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/datadog/discover response body: %v", closeErr)
		}
	}()
	var datadogDiscoverPayload map[string]any
	if err := json.NewDecoder(datadogDiscoverResp.Body).Decode(&datadogDiscoverPayload); err != nil {
		t.Fatalf("decode /sources/datadog/discover response: %v", err)
	}
	datadogURNs, ok := datadogDiscoverPayload["urns"].([]any)
	if !ok || len(datadogURNs) != 1 {
		t.Fatalf("datadog discover urns = %#v, want 1 entry", datadogDiscoverPayload["urns"])
	}
	if got := datadogURNs[0]; got != "urn:cerebro:tenant:datadog_users:user-1" {
		t.Fatalf("datadog discover urns[0] = %#v, want Datadog users URN", got)
	}
	datadogReadResp, err := sourceGet(t, server, "/sources/datadog/read?family=users", datadogConfig)
	if err != nil {
		t.Fatalf("GET /sources/datadog/read error = %v", err)
	}
	defer func() {
		if closeErr := datadogReadResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/datadog/read response body: %v", closeErr)
		}
	}()
	var datadogReadPayload map[string]any
	if err := json.NewDecoder(datadogReadResp.Body).Decode(&datadogReadPayload); err != nil {
		t.Fatalf("decode /sources/datadog/read response: %v", err)
	}
	datadogEvents, ok := datadogReadPayload["events"].([]any)
	if !ok || len(datadogEvents) != 1 {
		t.Fatalf("datadog read events = %#v, want 1 entry", datadogReadPayload["events"])
	}
	datadogEvent, ok := datadogEvents[0].(map[string]any)
	if !ok || datadogEvent["kind"] != "datadog.users" {
		t.Fatalf("datadog read event = %#v, want kind datadog.users", datadogEvents[0])
	}
	datadogPreviewEvents, ok := datadogReadPayload["preview_events"].([]any)
	if !ok || len(datadogPreviewEvents) != 1 {
		t.Fatalf("datadog read preview_events = %#v, want 1 entry", datadogReadPayload["preview_events"])
	}
	datadogPreviewEvent, ok := datadogPreviewEvents[0].(map[string]any)
	if !ok || datadogPreviewEvent["payload_decoded"] != true {
		t.Fatalf("datadog read preview_event = %#v, want decoded payload", datadogPreviewEvents[0])
	}
	leakyQueryResp, err := server.Client().Get(server.URL + "/sources/github/check?token=secret")
	if err != nil {
		t.Fatalf("GET /sources/github/check leaky query error = %v", err)
	}
	defer func() {
		if closeErr := leakyQueryResp.Body.Close(); closeErr != nil {
			t.Fatalf("close leaky query response body: %v", closeErr)
		}
	}()
	if leakyQueryResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("leaky query status = %d, want %d", leakyQueryResp.StatusCode, http.StatusBadRequest)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	versionResp, err := client.GetVersion(context.Background(), connect.NewRequest(&cerebrov1.GetVersionRequest{}))
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if versionResp.Msg.ServiceName != buildinfo.ServiceName {
		t.Fatalf("ServiceName = %q, want %q", versionResp.Msg.ServiceName, buildinfo.ServiceName)
	}

	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "ready" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "ready")
	}
	listResp, err := client.ListSources(context.Background(), connect.NewRequest(&cerebrov1.ListSourcesRequest{}))
	if err != nil {
		t.Fatalf("ListSources() error = %v", err)
	}
	if len(listResp.Msg.Sources) != 7 {
		t.Fatalf("len(ListSources.Sources) = %d, want 7", len(listResp.Msg.Sources))
	}
	checkSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("CheckSource() error = %v", err)
	}
	if checkSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource status = %q, want %q", checkSourceResp.Msg.Status, "ok")
	}
	discoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource() error = %v", err)
	}
	if len(discoverSourceResp.Msg.Urns) != 1 {
		t.Fatalf("len(DiscoverSource.Urns) = %d, want 1", len(discoverSourceResp.Msg.Urns))
	}
	if got := discoverSourceResp.Msg.Urns[0]; got != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("DiscoverSource.Urns[0] = %q, want default GitHub repository URN", got)
	}
	readSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if len(readSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource.Events) = %d, want 1", len(readSourceResp.Msg.Events))
	}
	if len(readSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource.PreviewEvents) = %d, want 1", len(readSourceResp.Msg.PreviewEvents))
	}
	if !readSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource.PreviewEvents[0].PayloadDecoded = false, want true")
	}
	oktaCheckSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("CheckSource(okta) error = %v", err)
	}
	if oktaCheckSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource(okta) status = %q, want %q", oktaCheckSourceResp.Msg.Status, "ok")
	}
	oktaDiscoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource(okta) error = %v", err)
	}
	if len(oktaDiscoverSourceResp.Msg.Urns) != 2 {
		t.Fatalf("len(DiscoverSource(okta).Urns) = %d, want 2", len(oktaDiscoverSourceResp.Msg.Urns))
	}
	oktaReadSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("ReadSource(okta) error = %v", err)
	}
	if len(oktaReadSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource(okta).Events) = %d, want 1", len(oktaReadSourceResp.Msg.Events))
	}
	if len(oktaReadSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource(okta).PreviewEvents) = %d, want 1", len(oktaReadSourceResp.Msg.PreviewEvents))
	}
	if !oktaReadSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource(okta).PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestBootstrapSourcePreviewEndpointsDoNotResolveEnvReferences(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	t.Setenv("CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN", "resolved-token")
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := sourceGet(t, server, "/sources/bootstrap_token/read", map[string]string{ // #nosec G101 -- env-reference test fixture, not credential material.
		"token": "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN",
	})
	if err != nil {
		t.Fatalf("GET /sources/bootstrap_token/read error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sources/bootstrap_token/read status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if source.readToken != "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN" {
		t.Fatalf("HTTP read token = %q, want literal env reference", source.readToken)
	}

	source.readToken = ""
	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	if _, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "bootstrap_token",
		Config:   map[string]string{"token": "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN"}, // #nosec G101 -- env-reference test fixture, not credential material.
	})); err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if source.readToken != "env:CEREBRO_SOURCE_BOOTSTRAP_TOKEN_TOKEN" {
		t.Fatalf("Connect read token = %q, want literal env reference", source.readToken)
	}
}

func TestBootstrapSourcePreviewRejectsServerLocalSourceConfig(t *testing.T) {
	kubernetes := &bootstrapTokenSource{id: "kubernetes"}
	trivy := &bootstrapTokenSource{id: "trivy"}
	registry, err := sourcecdk.NewRegistry(kubernetes, trivy)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, tt := range []struct {
		name   string
		path   string
		config map[string]string
	}{
		{
			name:   "http kubernetes in cluster",
			path:   "/sources/kubernetes/check",
			config: map[string]string{"tenant_id": "writer", "in_cluster": "true"},
		},
		{
			name:   "http kubernetes kubeconfig path",
			path:   "/sources/kubernetes/discover",
			config: map[string]string{"tenant_id": "writer", "kubeconfig_path": "/var/run/cerebro/kubeconfig"},
		},
		{
			name:   "http trivy report path",
			path:   "/sources/trivy/read",
			config: map[string]string{"tenant_id": "writer", "report_path": "/var/lib/cerebro/report.json"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sourceGet(t, server, tt.path, tt.config)
			if err != nil {
				t.Fatalf("GET %s error = %v", tt.path, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("GET %s status = %d, want %d", tt.path, resp.StatusCode, http.StatusBadRequest)
			}
		})
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	if _, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "kubernetes",
		Config:   map[string]string{"tenant_id": "writer", "in_cluster": "true"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CheckSource(kubernetes) error = %v, want InvalidArgument", err)
	}
	if _, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "trivy",
		Config:   map[string]string{"tenant_id": "writer", "path": "/var/lib/cerebro/report.json"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("ReadSource(trivy) error = %v, want InvalidArgument", err)
	}
}

func TestAuthMiddlewareProtectsNonPublicRoutes(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "ci",
				TenantID:  "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	healthResp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	openAPIResp, err := server.Client().Get(server.URL + "/openapi.yaml")
	if err != nil {
		t.Fatalf("GET /openapi.yaml without auth error = %v", err)
	}
	_ = openAPIResp.Body.Close()
	if openAPIResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /openapi.yaml without auth status = %d, want %d", openAPIResp.StatusCode, http.StatusOK)
	}

	unauthResp, err := server.Client().Get(server.URL + "/sources")
	if err != nil {
		t.Fatalf("GET /sources without auth error = %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /sources without auth status = %d, want %d", unauthResp.StatusCode, http.StatusUnauthorized)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/sources", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	authResp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /sources with auth error = %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sources with auth status = %d, want %d", authResp.StatusCode, http.StatusOK)
	}
}

func TestAuthenticateRequestPrefersStructuredCredentialMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	principal, _, _, ok := authenticateRequest(config.AuthConfig{
		APIKeys: []config.APIKey{{
			Key:       "shared-token",
			Principal: "legacy",
			TenantID:  "writer",
		}},
		APICredentials: []config.APICredential{{
			Key:            "shared-token",
			ID:             "legacy-api-key-1",
			ClientID:       "legacy-api-key",
			Principal:      "structured",
			TenantID:       "writer",
			AllowedTenants: []string{"writer"},
		}},
	}, nil, req)
	if !ok {
		t.Fatal("authenticateRequest() ok = false, want true")
	}
	for key, want := range map[string]string{ // #nosec G101 -- credential_id/client_id are expected auth claim names in a test fixture.
		"auth_mode":     "api_credential",
		"credential_id": "legacy-api-key-1",
		"client_id":     "legacy-api-key",
		"principal":     "structured",
		"tenant_id":     "writer",
	} {
		var got string
		switch key {
		case "auth_mode":
			got = principal.AuthMode
		case "credential_id":
			got = principal.CredentialID
		case "client_id":
			got = principal.ClientID
		case "principal":
			got = principal.Name
		case "tenant_id":
			got = principal.TenantID
		}
		if got != want {
			t.Fatalf("principal %s = %q, want %q", key, got, want)
		}
	}
}

func TestAuthMiddlewareEmitsAccessAuditEvents(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "ci",
				TenantID:  "writer",
			}},
			RequestOrigin: config.RequestOriginConfig{
				TrustedProxyCIDRs: []string{"127.0.0.0/8"},
				TrustedProxyCount: 1,
			},
		},
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id=writer&api_key=leaked", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.5")
		req.Header.Set("X-Request-ID", "audit-request-1")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("GET /sources with auth error = %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /sources with auth status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"kind":                  "event",
		"name":                  "cerebro.api.access",
		"outcome":               "allowed",
		"status":                float64(http.StatusOK),
		"status_code":           float64(http.StatusOK),
		"effective_status_code": float64(http.StatusOK),
		"method":                http.MethodGet,
		"route":                 "GET /sources",
		"tenant_id":             "writer",
		"effective_tenant_id":   "writer",
		"requested_tenant_id":   "writer",
		"principal_tenant_id":   "writer",
		"principal":             "ci",
		"auth_mode":             "api_key",
		"operation_family":      "source",
		"operation_type":        "read",
		"client_ip":             "198.51.100.7",
		"request_id":            "audit-request-1",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("audit payload[%q] = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("audit payload duration_ms = %#v, want numeric; payload=%#v", payload["duration_ms"], payload)
	}
	for _, forbidden := range []string{"test-key", "leaked", "api_key=leaked", "Authorization"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("audit log leaked %q in %s", forbidden, stderr)
		}
	}
}

func TestAuthMiddlewareEmitsDeniedAccessAuditEvents(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "ci",
				TenantID:  "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	unauthStderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Get(server.URL + "/sources?tenant_id=writer")
		if err != nil {
			t.Fatalf("GET /sources without auth error = %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /sources without auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
	unauthPayload := decodeBootstrapTelemetryPayload(t, unauthStderr)
	for key, want := range map[string]any{
		"name":                  "cerebro.api.access",
		"outcome":               "denied",
		"status":                float64(http.StatusUnauthorized),
		"status_code":           float64(http.StatusUnauthorized),
		"effective_status_code": float64(http.StatusUnauthorized),
		"route":                 "GET /sources",
		"tenant_id":             "writer",
		"effective_tenant_id":   "writer",
		"requested_tenant_id":   "writer",
		"operation_family":      "source",
		"operation_type":        "read",
		"denial_reason":         "unauthenticated",
	} {
		if got := unauthPayload[key]; got != want {
			t.Fatalf("unauth audit payload[%q] = %#v, want %#v; payload=%#v", key, got, want, unauthPayload)
		}
	}
	if _, ok := unauthPayload["principal"]; ok {
		t.Fatalf("unauth audit payload included principal: %#v", unauthPayload)
	}

	forbiddenStderr := captureBootstrapStderr(t, func() {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id=other", nil)
		if err != nil {
			t.Fatalf("NewRequest forbidden: %v", err)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("GET /sources forbidden error = %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET /sources forbidden status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
	})
	forbiddenPayload := decodeBootstrapTelemetryPayload(t, forbiddenStderr)
	for key, want := range map[string]any{
		"name":                  "cerebro.api.access",
		"outcome":               "denied",
		"status":                float64(http.StatusForbidden),
		"status_code":           float64(http.StatusForbidden),
		"effective_status_code": float64(http.StatusForbidden),
		"route":                 "GET /sources",
		"tenant_id":             "other",
		"effective_tenant_id":   "writer",
		"requested_tenant_id":   "other",
		"principal":             "ci",
		"principal_tenant_id":   "writer",
		"auth_mode":             "api_key",
		"operation_family":      "source",
		"operation_type":        "read",
		"tenant_mismatch":       true,
		"denial_reason":         "tenant_forbidden",
	} {
		if got := forbiddenPayload[key]; got != want {
			t.Fatalf("forbidden audit payload[%q] = %#v, want %#v; payload=%#v", key, got, want, forbiddenPayload)
		}
	}
	if strings.Contains(forbiddenStderr, "test-key") {
		t.Fatalf("forbidden audit log leaked bearer token: %s", forbiddenStderr)
	}
}

func TestAuthMiddlewareSkipsAccessAuditForPublicRoutes(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth:            config.AuthConfig{Enabled: true},
	}
	app := New(cfg, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Get(server.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health error = %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
	if strings.Contains(stderr, "cerebro.api.access") {
		t.Fatalf("public route emitted access audit event: %s", stderr)
	}
}

func TestAccessAuditOutcomeClassifiesDownstreamAuthorizationFailures(t *testing.T) {
	outcome, reason := accessAuditOutcome(http.StatusForbidden, "allowed", "", "")
	if outcome != "denied" || reason != "authorization_failed" {
		t.Fatalf("accessAuditOutcome(403) = (%q, %q), want denied authorization_failed", outcome, reason)
	}
	outcome, reason = accessAuditOutcome(http.StatusInternalServerError, "allowed", "", "")
	if outcome != "error" || reason != "" {
		t.Fatalf("accessAuditOutcome(500) = (%q, %q), want error empty reason", outcome, reason)
	}
	outcome, reason = accessAuditOutcome(http.StatusOK, "allowed", "", "permission_denied")
	if outcome != "denied" || reason != "authorization_failed" {
		t.Fatalf("accessAuditOutcome(gRPC permission_denied) = (%q, %q), want denied authorization_failed", outcome, reason)
	}
	if got := accessAuditEffectiveStatusCode(http.StatusOK, "permission_denied"); got != http.StatusForbidden {
		t.Fatalf("accessAuditEffectiveStatusCode(permission_denied) = %d, want %d", got, http.StatusForbidden)
	}
	if got := accessAuditEffectiveStatusCode(http.StatusOK, "unauthenticated"); got != http.StatusUnauthorized {
		t.Fatalf("accessAuditEffectiveStatusCode(unauthenticated) = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := accessAuditEffectiveStatusCode(http.StatusOK, "aborted"); got != http.StatusConflict {
		t.Fatalf("accessAuditEffectiveStatusCode(aborted) = %d, want %d", got, http.StatusConflict)
	}
}

func TestAccessAuditResponseWriterPreservesFlush(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &accessAuditResponseWriter{ResponseWriter: recorder}
	flusher, ok := any(writer).(http.Flusher)
	if !ok {
		t.Fatal("accessAuditResponseWriter does not implement http.Flusher")
	}
	flusher.Flush()
	if !recorder.Flushed {
		t.Fatal("wrapped recorder was not flushed")
	}
	if writer.Status() != http.StatusOK {
		t.Fatalf("status = %d, want %d", writer.Status(), http.StatusOK)
	}
}

func TestAccessAuditConnectProcedureSanitizesUnknownProcedures(t *testing.T) {
	if got := accessAuditConnectProcedure(cerebrov1connect.BootstrapServiceListSourcesProcedure); got != "cerebro.v1.BootstrapService/ListSources" {
		t.Fatalf("known connect procedure = %q, want ListSources", got)
	}
	raw := "/cerebro.v1.BootstrapService/secret-token-value"
	if got := accessAuditConnectProcedure(raw); got != "unknown" {
		t.Fatalf("unknown connect procedure = %q, want unknown", got)
	}
}

func TestFallbackAccessAuditRouteIncludesEndpointVulnerabilityFindings(t *testing.T) {
	for _, tt := range []struct {
		path string
		want string
	}{
		{path: "/endpoint-vulnerability-findings", want: "GET /endpoint-vulnerability-findings"},
		{path: "/platform/endpoints/dev-1/vulnerability-findings", want: "GET /platform/endpoints/{deviceKey}/vulnerability-findings"},
	} {
		if got := fallbackAccessAuditRoute(http.MethodGet, tt.path); got != tt.want {
			t.Fatalf("fallbackAccessAuditRoute(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestAccessAuditRemoteIPDropsPort(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want string
	}{
		{raw: "203.0.113.10:54321", want: "203.0.113.10"},
		{raw: "[2001:db8::1]:443", want: "2001:db8::1"},
		{raw: "203.0.113.20", want: "203.0.113.20"},
		{raw: "not an address", want: ""},
	} {
		if got := accessAuditRemoteIP(tt.raw); got != tt.want {
			t.Fatalf("accessAuditRemoteIP(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestResolveRequestOriginUsesConfiguredPublicOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://internal.local/platform/devices/token?rotate=true", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.5")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{
		PublicOrigin:      "https://api.writer.com",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		TrustedProxyCount: 1,
	})
	if got := origin.PublicURL; got != "https://api.writer.com/platform/devices/token?rotate=true" {
		t.Fatalf("PublicURL = %q, want configured public origin URL", got)
	}
	if got := origin.ClientIP; got != "198.51.100.10" {
		t.Fatalf("ClientIP = %q, want forwarded client", got)
	}
}

func TestResolveRequestOriginInfersConfiguredTrustedProxyHops(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources", nil)
	req.RemoteAddr = "203.0.113.20:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 192.0.2.10, 203.0.113.20")
	req.Header.Set("X-Forwarded-Proto", "http, https")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{
		TrustedProxyCIDRs: []string{"192.0.2.0/24", "203.0.113.0/24"},
	})
	if got := origin.ClientIP; got != "198.51.100.99" {
		t.Fatalf("ClientIP = %q, want configured trusted-proxy client", got)
	}
	if got := origin.PublicURL; got != "https://example.com/sources" {
		t.Fatalf("PublicURL = %q, want trailing trusted forwarded proto", got)
	}
}

func TestResolveRequestOriginDoesNotTrustCallerSuppliedForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.200")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "attacker.example")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{})
	if origin.TrustedProxy {
		t.Fatal("TrustedProxy = true, want false without explicit trusted proxy CIDRs")
	}
	if got := origin.ClientIP; got != "10.0.1.20" {
		t.Fatalf("ClientIP = %q, want remote address", got)
	}
	if got := origin.PublicURL; got != "http://example.com/sources" {
		t.Fatalf("PublicURL = %q, want request origin", got)
	}
}

func TestResolveRequestOriginRejectsMalformedForwardedHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Header.Set("X-Forwarded-Host", "user@evil.example")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	if got := origin.PublicURL; got != "http://example.com/sources" {
		t.Fatalf("PublicURL = %q, want request host when forwarded host is malformed", got)
	}
}

func TestResolveRequestOriginRejectsMalformedTrailingForwardedOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/sources", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https, gopher")
	req.Header.Set("X-Forwarded-Host", "stale.example, user@evil.example")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	if got := origin.PublicURL; got != "http://internal.local/sources" {
		t.Fatalf("PublicURL = %q, want request origin when trailing forwarded origin is malformed", got)
	}
}

func TestResolveRequestOriginDoesNotMixForwardedOriginWithFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/sources", nil)
	req.RemoteAddr = "10.0.1.20:443"
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https, gopher")
	req.Header.Set("X-Forwarded-Host", "api.writer.com, api.writer.com")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	if got := origin.PublicURL; got != "http://internal.local/sources" {
		t.Fatalf("PublicURL = %q, want request origin when forwarded proto is malformed", got)
	}
}

func TestResolveRequestOriginIgnoresForwardedHostFromUntrustedRemote(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://internal.local/platform/devices/token", nil)
	req.RemoteAddr = "198.51.100.20:54321"
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	origin := resolveRequestOrigin(req, config.RequestOriginConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	if got := origin.PublicURL; got != "http://internal.local/platform/devices/token" {
		t.Fatalf("PublicURL = %q, want direct request URL", got)
	}
	if got := origin.ClientIP; got != "198.51.100.20" {
		t.Fatalf("ClientIP = %q, want remote address", got)
	}
}

func TestAccessAuditOperationClassifiesFamiliesAndSensitiveActions(t *testing.T) {
	for _, tt := range []struct {
		method        string
		path          string
		route         string
		family        string
		operationType string
		sensitive     bool
	}{
		{method: http.MethodGet, path: "/sources/github/read", route: "GET /sources/{sourceID}/read", family: "source", operationType: "read", sensitive: true},
		{method: http.MethodPost, path: "/source-runtimes/runtime-1/sync", route: "POST /source-runtimes/{runtimeID}/sync", family: "source_runtime", operationType: "write", sensitive: true},
		{method: http.MethodGet, path: "/platform/graph/neighborhood", route: "GET /platform/graph/neighborhood", family: "graph", operationType: "read", sensitive: false},
		{method: http.MethodPost, path: "/cerebro.v1.BootstrapService/SyncSourceRuntime", route: "/cerebro.v1.BootstrapService/{Procedure}", family: "source_runtime", operationType: "write", sensitive: true},
		{method: http.MethodPost, path: "/cerebro.v1.BootstrapService/GetEntityNeighborhood", route: "/cerebro.v1.BootstrapService/{Procedure}", family: "graph", operationType: "read", sensitive: false},
	} {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		got := accessAuditOperation(req, tt.route)
		if got.Family != tt.family || got.Type != tt.operationType || got.SensitiveAction != tt.sensitive {
			t.Fatalf("accessAuditOperation(%s %s) = %#v, want family=%q type=%q sensitive=%v", tt.method, tt.path, got, tt.family, tt.operationType, tt.sensitive)
		}
	}
}

func TestScopedCosmoCredentialAllowsOnlyReadRoutes(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{{
				Key:       "scoped-token",
				Principal: "cosmo-security",
				TenantID:  "writer",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
		},
	}
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:asset:app": {
				URN:        "urn:cerebro:writer:asset:app",
				TenantID:   "writer",
				SourceID:   "aws",
				EntityType: "asset",
				Label:      "app",
			},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
		},
	}
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(cfg, Dependencies{GraphStore: graph, StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, path := range []string{
		"/sources",
		"/platform/graph/neighborhood?root_urn=urn:cerebro:writer:asset:app",
		"/platform/graph/crown-jewel-rankings?tenant_id=writer",
		"/source-runtimes/writer-runtime",
	} {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s): %v", path, err)
		}
		req.Header.Set("Authorization", "Bearer scoped-token")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusOK)
		}
	}

	otherTenantReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:other:asset:app", nil)
	if err != nil {
		t.Fatalf("NewRequest other tenant: %v", err)
	}
	otherTenantReq.Header.Set("Authorization", "Bearer scoped-token")
	otherTenantResp, err := server.Client().Do(otherTenantReq)
	if err != nil {
		t.Fatalf("GET other tenant graph error = %v", err)
	}
	_ = otherTenantResp.Body.Close()
	if otherTenantResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET other tenant graph status = %d, want %d", otherTenantResp.StatusCode, http.StatusForbidden)
	}

	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/source-runtimes/writer-runtime/sync"},
		{method: http.MethodGet, path: "/sources/github/read"},
	} {
		req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s %s): %v", tt.method, tt.path, err)
		}
		req.Header.Set("Authorization", "Bearer scoped-token")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s error = %v", tt.method, tt.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, resp.StatusCode, http.StatusForbidden)
		}
	}
}

func TestScopeForHTTPRequestIncludesGRCAskPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/grc/ask", nil)
	if got := httpRoutePolicyForRequest(req).Scope; got != scopeCosmoSecurityRead {
		t.Fatalf("scopeForHTTPRequest(POST /grc/ask) = %q, want %q", got, scopeCosmoSecurityRead)
	}
}

func TestCandidatePromotionRequiresExplicitScope(t *testing.T) {
	readOnly := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{Scopes: []string{scopeCosmoSecurityRead}},
	})
	if err := authorizeFindingCandidatePromotion(readOnly); !errors.Is(err, errScopeForbidden) {
		t.Fatalf("authorizeFindingCandidatePromotion(read-only) error = %v, want %v", err, errScopeForbidden)
	}
	promoter := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{Scopes: []string{scopeFindingCandidatePromote}},
	})
	if err := authorizeFindingCandidatePromotion(promoter); err != nil {
		t.Fatalf("authorizeFindingCandidatePromotion(promoter) error = %v", err)
	}
	if err := authorizeFindingCandidatePromotion(context.Background()); err != nil {
		t.Fatalf("authorizeFindingCandidatePromotion(no auth) error = %v", err)
	}
}

func TestCandidateScopesCoverReadAndPromotionRoutes(t *testing.T) {
	for _, tt := range []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodGet, path: "/finding-candidates/candidate-1", want: scopeCosmoSecurityRead},
		{method: http.MethodPost, path: "/finding-candidates/candidate-1/promote", want: scopeFindingCandidatePromote},
		{method: http.MethodPost, path: "/finding-candidates/candidate-1/reject", want: scopeFindingCandidatePromote},
	} {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if got := httpRoutePolicyForRequest(req).Scope; got != tt.want {
			t.Fatalf("scopeForHTTPRequest(%s %s) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
	for _, tt := range []struct {
		procedure string
		want      string
	}{
		{procedure: cerebrov1connect.BootstrapServiceListFindingCandidatesProcedure, want: scopeCosmoSecurityRead},
		{procedure: cerebrov1connect.BootstrapServiceGetFindingCandidateProcedure, want: scopeCosmoSecurityRead},
		{procedure: cerebrov1connect.BootstrapServicePromoteFindingCandidateProcedure, want: scopeFindingCandidatePromote},
		{procedure: cerebrov1connect.BootstrapServiceRejectFindingCandidateProcedure, want: scopeFindingCandidatePromote},
	} {
		if got := connectProcedurePolicyFor(tt.procedure).Scope; got != tt.want {
			t.Fatalf("connectProcedurePolicyFor(%s).Scope = %q, want %q", tt.procedure, got, tt.want)
		}
	}
}

func TestScopedCosmoCredentialEnforcesConnectProcedures(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{{
				Key:       "scoped-token",
				Principal: "cosmo-security",
				TenantID:  "writer",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
		},
	}
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:asset:app": {
				URN:        "urn:cerebro:writer:asset:app",
				TenantID:   "writer",
				SourceID:   "aws",
				EntityType: "asset",
				Label:      "app",
			},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
		},
	}
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(cfg, Dependencies{GraphStore: graph, StateStore: store}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	versionReq := connect.NewRequest(&cerebrov1.GetVersionRequest{})
	versionReq.Header().Set("Authorization", "Bearer scoped-token")
	if _, err := client.GetVersion(context.Background(), versionReq); err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	healthReq := connect.NewRequest(&cerebrov1.CheckHealthRequest{})
	healthReq.Header().Set("Authorization", "Bearer scoped-token")
	if _, err := client.CheckHealth(context.Background(), healthReq); err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	listSourcesReq := connect.NewRequest(&cerebrov1.ListSourcesRequest{})
	listSourcesReq.Header().Set("Authorization", "Bearer scoped-token")
	listSourcesResp, err := client.ListSources(context.Background(), listSourcesReq)
	if err != nil {
		t.Fatalf("ListSources() error = %v", err)
	}
	if len(listSourcesResp.Msg.GetSources()) == 0 {
		t.Fatal("ListSources() returned no sources, want source catalog")
	}

	readReq := connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:writer:asset:app",
	})
	readReq.Header().Set("Authorization", "Bearer scoped-token")
	if _, err := client.GetEntityNeighborhood(context.Background(), readReq); err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}

	syncReq := connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{Id: "writer-runtime"})
	syncReq.Header().Set("Authorization", "Bearer scoped-token")
	if _, err := client.SyncSourceRuntime(context.Background(), syncReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("SyncSourceRuntime() code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestScopedCosmoCredentialAuditsGRPCProcedureDenials(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{{
				Key:       "scoped-token",
				Principal: "cosmo-security",
				TenantID:  "writer",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewUnstartedServer(app.Handler())
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL, connect.WithGRPC())
	syncReq := connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{Id: "writer-runtime"})
	syncReq.Header().Set("Authorization", "Bearer scoped-token")
	stderr := captureBootstrapStderr(t, func() {
		if _, err := client.SyncSourceRuntime(context.Background(), syncReq); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("SyncSourceRuntime() code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
		}
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                  "cerebro.api.access",
		"outcome":               "denied",
		"status":                float64(http.StatusOK),
		"route":                 "/cerebro.v1.BootstrapService/{Procedure}",
		"connect_procedure":     "cerebro.v1.BootstrapService/SyncSourceRuntime",
		"connect_code":          "permission_denied",
		"effective_status_code": float64(http.StatusForbidden),
		"denial_reason":         "authorization_failed",
		"principal":             "cosmo-security",
		"principal_tenant_id":   "writer",
		"auth_mode":             "api_credential",
		"operation_family":      "source_runtime",
		"operation_type":        "write",
		"sensitive_action":      true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("gRPC audit payload[%q] = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if strings.Contains(stderr, "scoped-token") {
		t.Fatalf("gRPC audit log leaked bearer token: %s", stderr)
	}
}

func TestCapabilityTokenRequiresSecurityGroup(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:                 true,
			CapabilityTokenSecrets:  []string{"capability-secret"},
			CapabilityTokenAudience: "cerebro-api",
		},
	}
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:asset:app": {
				URN:        "urn:cerebro:writer:asset:app",
				TenantID:   "writer",
				SourceID:   "aws",
				EntityType: "asset",
				Label:      "app",
			},
		},
	}
	app := New(cfg, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	authorizedToken := signCapabilityToken(t, "capability-secret", map[string]any{
		"aud":           "cerebro-api",
		"sub":           "slack:U123",
		"exp":           time.Now().Add(time.Hour).Unix(),
		"iat":           time.Now().Add(-time.Minute).Unix(),
		"tenant_id":     "writer",
		"scopes":        []string{scopeCosmoSecurityRead},
		"groups":        []string{"security"},
		"client_id":     "cosmo",
		"credential_id": "cosmo-capability",
	})
	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:writer:asset:app", nil)
	if err != nil {
		t.Fatalf("NewRequest authorized: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+authorizedToken)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET with authorized capability error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with authorized capability status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	nonSecurityToken := signCapabilityToken(t, "capability-secret", map[string]any{
		"aud":       "cerebro-api",
		"sub":       "slack:U999",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"tenant_id": "writer",
		"scopes":    []string{scopeCosmoSecurityRead},
		"groups":    []string{"engineering"},
	})
	forbiddenReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:writer:asset:app", nil)
	if err != nil {
		t.Fatalf("NewRequest forbidden: %v", err)
	}
	forbiddenReq.Header.Set("Authorization", "Bearer "+nonSecurityToken)
	forbiddenResp, err := server.Client().Do(forbiddenReq)
	if err != nil {
		t.Fatalf("GET with non-security capability error = %v", err)
	}
	_ = forbiddenResp.Body.Close()
	if forbiddenResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET with non-security capability status = %d, want %d", forbiddenResp.StatusCode, http.StatusForbidden)
	}

	expiredToken := signCapabilityToken(t, "capability-secret", map[string]any{
		"aud":       "cerebro-api",
		"sub":       "slack:U123",
		"exp":       time.Now().Add(-time.Minute).Unix(),
		"tenant_id": "writer",
		"scopes":    []string{scopeCosmoSecurityRead},
		"groups":    []string{"security"},
	})
	expiredReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:writer:asset:app", nil)
	if err != nil {
		t.Fatalf("NewRequest expired: %v", err)
	}
	expiredReq.Header.Set("Authorization", "Bearer "+expiredToken)
	expiredResp, err := server.Client().Do(expiredReq)
	if err != nil {
		t.Fatalf("GET with expired capability error = %v", err)
	}
	_ = expiredResp.Body.Close()
	if expiredResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET with expired capability status = %d, want %d", expiredResp.StatusCode, http.StatusUnauthorized)
	}

	noScopesToken := signCapabilityToken(t, "capability-secret", map[string]any{
		"aud":       "cerebro-api",
		"sub":       "slack:U123",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"tenant_id": "writer",
		"groups":    []string{"security"},
	})
	noScopesReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:writer:asset:app", nil)
	if err != nil {
		t.Fatalf("NewRequest no scopes: %v", err)
	}
	noScopesReq.Header.Set("Authorization", "Bearer "+noScopesToken)
	noScopesResp, err := server.Client().Do(noScopesReq)
	if err != nil {
		t.Fatalf("GET with no-scope capability error = %v", err)
	}
	_ = noScopesResp.Body.Close()
	if noScopesResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET with no-scope capability status = %d, want %d", noScopesResp.StatusCode, http.StatusUnauthorized)
	}
}

//nolint:unparam // Helper keeps explicit secret argument so JWT signing fixtures remain self-documenting.
func signCapabilityToken(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal token header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal token claims: %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature
}

func TestAuthMiddlewareEnforcesTenantOnHTTPProtoBodies(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	registry, err := sourcecdk.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := strings.NewReader(`{"runtime":{"id":"runtime-1","sourceId":"github","tenantId":"other"}}`)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/runtime-1", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT /source-runtimes tenant mismatch error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /source-runtimes tenant mismatch status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestAuthMiddlewareEnforcesTenantOnIDOnlyRoutes(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"other-runtime": {
				Id:       "other-runtime",
				SourceId: "okta",
				TenantId: "other",
			},
		},
		findings: map[string]*ports.FindingRecord{
			"other-finding": {
				ID:       "other-finding",
				TenantID: "other",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, tt := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "get runtime", method: http.MethodGet, path: "/source-runtimes/other-runtime"},
		{name: "sync runtime", method: http.MethodPost, path: "/source-runtimes/other-runtime/sync"},
		{name: "get finding", method: http.MethodGet, path: "/findings/other-finding"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer writer-key")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s error = %v", tt.method, tt.path, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, resp.StatusCode, http.StatusNotFound)
			}
		})
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getRuntimeReq := connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{Id: "other-runtime"})
	getRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetSourceRuntime(context.Background(), getRuntimeReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetSourceRuntime(other) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodeNotFound, err)
	}
	getFindingReq := connect.NewRequest(&cerebrov1.GetFindingRequest{Id: "other-finding"})
	getFindingReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetFinding(context.Background(), getFindingReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetFinding(other) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodeNotFound, err)
	}
}

func TestListSourceRuntimesRequiresTenantFilterWithAllowedTenantAuth(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:        true,
			APIKeys:        []config.APIKey{{Key: "allowed-key"}},
			AllowedTenants: []string{"writer"},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
			"other-runtime":  {Id: "other-runtime", SourceId: "github", TenantId: "other"},
			"blank-runtime":  {Id: "blank-runtime", SourceId: "github"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes", nil)
	if err != nil {
		t.Fatalf("NewRequest without tenant: %v", err)
	}
	req.Header.Set("Authorization", "Bearer allowed-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /source-runtimes without tenant error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /source-runtimes without tenant status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	scopedReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("NewRequest with tenant: %v", err)
	}
	scopedReq.Header.Set("Authorization", "Bearer allowed-key")
	scopedResp, err := server.Client().Do(scopedReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with tenant error = %v", err)
	}
	defer func() {
		if closeErr := scopedResp.Body.Close(); closeErr != nil {
			t.Fatalf("close scoped response body: %v", closeErr)
		}
	}()
	if scopedResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with tenant status = %d, want %d", scopedResp.StatusCode, http.StatusOK)
	}
	var payload map[string][]map[string]any
	if err := json.NewDecoder(scopedResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime list: %v", err)
	}
	if got := len(payload["runtimes"]); got != 1 {
		t.Fatalf("listed runtime count = %d, want 1", got)
	}
}

func TestListSourceRuntimesRequiresTenantFilterWithPrincipalAllowedTenants(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APICredentials: []config.APICredential{{
				Key:            "allowed-token",
				Principal:      "cosmo-security",
				AllowedTenants: []string{"writer"},
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
			"other-runtime":  {Id: "other-runtime", SourceId: "github", TenantId: "other"},
			"blank-runtime":  {Id: "blank-runtime", SourceId: "github"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes", nil)
	if err != nil {
		t.Fatalf("NewRequest without tenant: %v", err)
	}
	req.Header.Set("Authorization", "Bearer allowed-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /source-runtimes without tenant error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /source-runtimes without tenant status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	scopedReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("NewRequest with tenant: %v", err)
	}
	scopedReq.Header.Set("Authorization", "Bearer allowed-token")
	scopedResp, err := server.Client().Do(scopedReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with tenant error = %v", err)
	}
	defer func() {
		if closeErr := scopedResp.Body.Close(); closeErr != nil {
			t.Fatalf("close scoped response body: %v", closeErr)
		}
	}()
	if scopedResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with tenant status = %d, want %d", scopedResp.StatusCode, http.StatusOK)
	}
	var payload map[string][]map[string]any
	if err := json.NewDecoder(scopedResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime list: %v", err)
	}
	if got := len(payload["runtimes"]); got != 1 {
		t.Fatalf("listed runtime count = %d, want 1", got)
	}
	if got := payload["runtimes"][0]["id"]; got != "writer-runtime" {
		t.Fatalf("listed runtime id = %v, want writer-runtime", got)
	}

	blankReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?runtime_id=blank-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest with blank runtime_id: %v", err)
	}
	blankReq.Header.Set("Authorization", "Bearer allowed-token")
	blankResp, err := server.Client().Do(blankReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with blank runtime_id error = %v", err)
	}
	defer func() {
		if closeErr := blankResp.Body.Close(); closeErr != nil {
			t.Fatalf("close blank response body: %v", closeErr)
		}
	}()
	if blankResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with blank runtime_id status = %d, want %d", blankResp.StatusCode, http.StatusOK)
	}
	var blankPayload map[string][]map[string]any
	if err := json.NewDecoder(blankResp.Body).Decode(&blankPayload); err != nil {
		t.Fatalf("decode blank source runtime list: %v", err)
	}
	if got := len(blankPayload["runtimes"]); got != 0 {
		t.Fatalf("blank runtime count = %d, want 0", got)
	}
}

func TestListSourceRuntimesAuthorizesRuntimeIDWithAllowedTenantAuth(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:        true,
			APIKeys:        []config.APIKey{{Key: "allowed-key"}},
			AllowedTenants: []string{"writer"},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
			"other-runtime":  {Id: "other-runtime", SourceId: "github", TenantId: "other"},
			"blank-runtime":  {Id: "blank-runtime", SourceId: "github"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?runtime_id=writer-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest with runtime_id: %v", err)
	}
	req.Header.Set("Authorization", "Bearer allowed-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /source-runtimes with runtime_id error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with runtime_id status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string][]map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime list: %v", err)
	}
	if got := len(payload["runtimes"]); got != 1 {
		t.Fatalf("listed runtime count = %d, want 1", got)
	}
	if got := payload["runtimes"][0]["id"]; got != "writer-runtime" {
		t.Fatalf("listed runtime id = %v, want writer-runtime", got)
	}

	blankReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?runtime_id=blank-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest with blank runtime_id: %v", err)
	}
	blankReq.Header.Set("Authorization", "Bearer allowed-key")
	blankResp, err := server.Client().Do(blankReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with blank runtime_id error = %v", err)
	}
	defer func() {
		if closeErr := blankResp.Body.Close(); closeErr != nil {
			t.Fatalf("close blank response body: %v", closeErr)
		}
	}()
	if blankResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with blank runtime_id status = %d, want %d", blankResp.StatusCode, http.StatusOK)
	}
	var blankPayload map[string][]map[string]any
	if err := json.NewDecoder(blankResp.Body).Decode(&blankPayload); err != nil {
		t.Fatalf("decode blank source runtime list: %v", err)
	}
	if got := len(blankPayload["runtimes"]); got != 1 {
		t.Fatalf("blank runtime count = %d, want 1", got)
	}
	if got := blankPayload["runtimes"][0]["id"]; got != "blank-runtime" {
		t.Fatalf("blank runtime id = %v, want blank-runtime", got)
	}

	forbiddenReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?runtime_id=other-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest with forbidden runtime_id: %v", err)
	}
	forbiddenReq.Header.Set("Authorization", "Bearer allowed-key")
	forbiddenResp, err := server.Client().Do(forbiddenReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with forbidden runtime_id error = %v", err)
	}
	defer func() {
		if closeErr := forbiddenResp.Body.Close(); closeErr != nil {
			t.Fatalf("close forbidden response body: %v", closeErr)
		}
	}()
	if forbiddenResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with forbidden runtime_id status = %d, want %d", forbiddenResp.StatusCode, http.StatusOK)
	}
	var forbiddenPayload map[string][]map[string]any
	if err := json.NewDecoder(forbiddenResp.Body).Decode(&forbiddenPayload); err != nil {
		t.Fatalf("decode forbidden source runtime list: %v", err)
	}
	if got := len(forbiddenPayload["runtimes"]); got != 0 {
		t.Fatalf("forbidden runtime count = %d, want 0", got)
	}

	missingReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes?runtime_id=missing-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest with missing runtime_id: %v", err)
	}
	missingReq.Header.Set("Authorization", "Bearer allowed-key")
	missingResp, err := server.Client().Do(missingReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes with missing runtime_id error = %v", err)
	}
	defer func() {
		if closeErr := missingResp.Body.Close(); closeErr != nil {
			t.Fatalf("close missing response body: %v", closeErr)
		}
	}()
	if missingResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with missing runtime_id status = %d, want %d", missingResp.StatusCode, http.StatusOK)
	}
	var missingPayload map[string][]map[string]any
	if err := json.NewDecoder(missingResp.Body).Decode(&missingPayload); err != nil {
		t.Fatalf("decode missing source runtime list: %v", err)
	}
	if got := len(missingPayload["runtimes"]); got != 0 {
		t.Fatalf("missing runtime count = %d, want 0", got)
	}
}

func TestListSourceRuntimesUsesTenantHeaderWithAllowedTenantAuth(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:        true,
			APIKeys:        []config.APIKey{{Key: "allowed-key"}},
			AllowedTenants: []string{"writer"},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
			"other-runtime":  {Id: "other-runtime", SourceId: "github", TenantId: "other"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes", nil)
	if err != nil {
		t.Fatalf("NewRequest with tenant header: %v", err)
	}
	req.Header.Set("Authorization", "Bearer allowed-key")
	req.Header.Set("X-Cerebro-Tenant", "writer")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /source-runtimes with tenant header error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes with tenant header status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string][]map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime list: %v", err)
	}
	if got := len(payload["runtimes"]); got != 1 {
		t.Fatalf("listed runtime count = %d, want 1", got)
	}
}

func TestListSourceRuntimesAllowsUnscopedAdminKeyWithoutTenantFilter(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{Key: "admin-key"}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-runtime": {Id: "writer-runtime", SourceId: "github", TenantId: "writer"},
			"other-runtime":  {Id: "other-runtime", SourceId: "github", TenantId: "other"},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes", nil)
	if err != nil {
		t.Fatalf("NewRequest without tenant: %v", err)
	}
	req.Header.Set("Authorization", "Bearer admin-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /source-runtimes without tenant error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes without tenant status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string][]map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime list: %v", err)
	}
	if got := len(payload["runtimes"]); got != 2 {
		t.Fatalf("listed runtime count = %d, want 2", got)
	}
}

func TestListSourceRuntimesInvalidLimitReturnsBadRequest(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/source-runtimes?limit=bogus")
	if err != nil {
		t.Fatalf("GET /source-runtimes invalid limit error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /source-runtimes invalid limit status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRedactSourceRuntimeDropsInternalProgressHash(t *testing.T) {
	runtime := redactSourceRuntime(&cerebrov1.SourceRuntime{
		Id: "writer-github",
		Config: map[string]string{
			"token":                            "secret-token",
			sourceRuntimeProgressConfigHashKey: "internal-hash",
			"owner":                            "writer",
		},
	})
	if _, ok := runtime.GetConfig()[sourceRuntimeProgressConfigHashKey]; ok {
		t.Fatal("redacted runtime exposed internal progress hash")
	}
	if got := runtime.GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("redacted token = %q, want [redacted]", got)
	}
	if got := runtime.GetConfig()["owner"]; got != "writer" {
		t.Fatalf("redacted owner = %q, want writer", got)
	}
}

func TestAuthMiddlewareRejectsBlankTenantSourceRuntimesForScopedKeys(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"blank-runtime": {
				Id:       "blank-runtime",
				SourceId: "github",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/new-runtime", strings.NewReader(`{"runtime":{"sourceId":"github"}}`))
	if err != nil {
		t.Fatalf("NewRequest put: %v", err)
	}
	putReq.Header.Set("Authorization", "Bearer writer-key")
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := server.Client().Do(putReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes blank tenant error = %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /source-runtimes blank tenant status = %d, want %d", putResp.StatusCode, http.StatusForbidden)
	}

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes/blank-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest get: %v", err)
	}
	getReq.Header.Set("Authorization", "Bearer writer-key")
	getResp, err := server.Client().Do(getReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes blank tenant error = %v", err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /source-runtimes blank tenant status = %d, want %d", getResp.StatusCode, http.StatusNotFound)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	putRuntimeReq := connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{Id: "connect-new-runtime", SourceId: "github"},
	})
	putRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.PutSourceRuntime(context.Background(), putRuntimeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("PutSourceRuntime(blank tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	getRuntimeReq := connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{Id: "blank-runtime"})
	getRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetSourceRuntime(context.Background(), getRuntimeReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetSourceRuntime(blank tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodeNotFound, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnMapBackedProtoFields(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := protojson.Marshal(&cerebrov1.RunReportRequest{
		Parameters: map[string]string{"tenant_id": "other"},
	})
	if err != nil {
		t.Fatalf("marshal report request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/reports/finding-summary/runs", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /reports/finding-summary/runs error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /reports/finding-summary/runs status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	allowedCfg := cfg
	allowedCfg.Auth.APIKeys = nil
	allowedCfg.Auth.APICredentials = []config.APICredential{{
		Key:            "allowed-key",
		Principal:      "cosmo-security",
		AllowedTenants: []string{"writer"},
	}}
	allowedApp := New(allowedCfg, Dependencies{}, nil)
	allowedServer := httptest.NewServer(allowedApp.Handler())
	defer allowedServer.Close()

	allowedBody, err := protojson.Marshal(&cerebrov1.RunReportRequest{
		Parameters: map[string]string{"tenant_id": "writer"},
	})
	if err != nil {
		t.Fatalf("marshal allowed report request: %v", err)
	}
	allowedReq, err := http.NewRequest(http.MethodPost, allowedServer.URL+"/reports/finding-summary/runs", bytes.NewReader(allowedBody))
	if err != nil {
		t.Fatalf("NewRequest allowed: %v", err)
	}
	allowedReq.Header.Set("Authorization", "Bearer allowed-key")
	allowedReq.Header.Set("Content-Type", "application/json")
	allowedResp, err := allowedServer.Client().Do(allowedReq)
	if err != nil {
		t.Fatalf("POST /reports/finding-summary/runs allowed error = %v", err)
	}
	_ = allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /reports/finding-summary/runs allowed status = %d, want %d", allowedResp.StatusCode, http.StatusServiceUnavailable)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	runReq := connect.NewRequest(&cerebrov1.RunReportRequest{
		Parameters: map[string]string{"tenant_id": "other"},
	})
	runReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.RunReport(context.Background(), runReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("RunReport(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnReportRunLookups(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		reportRuns: map[string]*cerebrov1.ReportRun{
			"other-report-run": {
				Id:         "other-report-run",
				ReportId:   "finding-summary",
				Parameters: map[string]string{"tenant_id": "other"},
				Status:     "completed",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report-runs/other-report-run", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /report-runs/other-report-run error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /report-runs/other-report-run status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getReq := connect.NewRequest(&cerebrov1.GetReportRunRequest{Id: "other-report-run"})
	getReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetReportRun(context.Background(), getReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetReportRun(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodeNotFound, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnGraphRootURN(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:other:github_user:alice", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /platform/graph/neighborhood error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/neighborhood status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	neighborhoodReq := connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:other:github_user:alice",
	})
	neighborhoodReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetEntityNeighborhood(context.Background(), neighborhoodReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetEntityNeighborhood(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestGraphPackageImpactEndpointReturnsCanonicalPackageRoot(t *testing.T) {
	rootURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			rootURN: {
				URN:        rootURN,
				TenantID:   "writer",
				SourceID:   "github",
				EntityType: "package",
				Label:      "foo",
			},
		},
	}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/impact/package?tenant_id=writer&package=pkg:npm/foo@1.2.3")
	if err != nil {
		t.Fatalf("GET /platform/graph/impact/package error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/impact/package status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		RootURN string `json:"root_urn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.RootURN != rootURN {
		t.Fatalf("root_urn = %q, want %q", body.RootURN, rootURN)
	}
}

func TestGraphImpactEndpointRejectsExplicitZeroBounds(t *testing.T) {
	app := New(config.Config{}, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, query := range []string{
		"tenant_id=writer&package=pkg:npm/foo&limit=0",
		"tenant_id=writer&package=pkg:npm/foo&depth=0",
	} {
		resp, err := server.Client().Get(server.URL + "/platform/graph/impact/package?" + query)
		if err != nil {
			t.Fatalf("GET /platform/graph/impact/package?%s error = %v", query, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET /platform/graph/impact/package?%s status = %d, want %d", query, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

func TestGraphAWSPublicEndpointInsightsEndpoint(t *testing.T) {
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{
		{{Values: map[string]any{
			"aws_endpoint_count":                   int64(2),
			"internet_indicator_count":             int64(2),
			"internet_host_count":                  int64(1),
			"internet_ip_count":                    int64(1),
			"overlapping_aws_endpoint_count":       int64(1),
			"overlapping_internet_indicator_count": int64(1),
			"overlapping_vulnview_asset_count":     int64(1),
		}}},
		nil,
		{{Values: map[string]any{
			"aws_urn":               "urn:cerebro:writer:aws_application_load_balancer:alb",
			"aws_entity_type":       "aws.application.load.balancer",
			"aws_label":             "alb",
			"indicator_urn":         "urn:cerebro:writer:internet_host:app.example.com",
			"indicator_entity_type": "internet.host",
			"indicator_label":       "app.example.com",
			"vulnview_urn":          "urn:cerebro:writer:external_asset:app.example.com",
			"vulnview_entity_type":  "external.asset",
			"vulnview_label":        "app.example.com",
		}}},
		nil,
		nil,
		nil,
	}}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/aws-public-endpoint-insights?tenant_id=writer&account_id=account-a&region=us-east-1&search=app&limit=5")
	if err != nil {
		t.Fatalf("GET /platform/graph/aws-public-endpoint-insights error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/aws-public-endpoint-insights status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Counts   struct {
			AWSEndpoints              int `json:"aws_endpoints"`
			OverlappingVulnViewAssets int `json:"overlapping_vulnview_assets"`
		} `json:"counts"`
		Overlaps []struct {
			InternetIndicator struct {
				URN string `json:"urn"`
			} `json:"internet_indicator"`
		} `json:"overlaps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantID != "writer" || body.Counts.AWSEndpoints != 2 || body.Counts.OverlappingVulnViewAssets != 1 {
		t.Fatalf("body = %#v", body)
	}
	if len(body.Overlaps) != 1 || body.Overlaps[0].InternetIndicator.URN != "urn:cerebro:writer:internet_host:app.example.com" {
		t.Fatalf("overlaps = %#v", body.Overlaps)
	}
	if len(graph.cypherRequests) != 6 || graph.cypherRequests[0].Params["tenant_id"] != "writer" {
		t.Fatalf("cypher requests = %#v", graph.cypherRequests)
	}
}

func TestGraphPersonAccessPathsEndpoint(t *testing.T) {
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{
		{{Values: map[string]any{
			"person_urn":            "urn:cerebro:writer:person:vanta:person-1",
			"person_entity_type":    "person",
			"person_label":          "designer@example.com",
			"identity_urn":          "urn:cerebro:writer:identity:email:designer@example.com",
			"identity_entity_type":  "identity.email",
			"identity_label":        "designer@example.com",
			"principal_urn":         "urn:cerebro:writer:okta_user:00u1",
			"principal_entity_type": "okta.user",
			"principal_label":       "designer@example.com",
			"target_urn":            "urn:cerebro:writer:aws_role:DesignerAnalytics",
			"target_entity_type":    "aws.role",
			"target_label":          "DesignerAnalytics",
			"relation_chain":        []any{"assigned_to"},
		}}},
	}}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/person-access-paths?tenant_id=writer&person_query=Product%20Designer&limit=5&depth=2")
	if err != nil {
		t.Fatalf("GET /platform/graph/person-access-paths error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/person-access-paths status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Counts   struct {
			Paths int `json:"paths"`
		} `json:"counts"`
		Paths []struct {
			Principal struct {
				URN string `json:"urn"`
			} `json:"principal"`
			AccessTarget struct {
				URN string `json:"urn"`
			} `json:"access_target"`
			RelationChain []string `json:"relation_chain"`
		} `json:"paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantID != "writer" || body.Counts.Paths != 1 || len(body.Paths) != 1 {
		t.Fatalf("body = %#v", body)
	}
	if body.Paths[0].Principal.URN != "urn:cerebro:writer:okta_user:00u1" || body.Paths[0].AccessTarget.URN != "urn:cerebro:writer:aws_role:DesignerAnalytics" {
		t.Fatalf("paths = %#v", body.Paths)
	}
	if len(graph.cypherRequests) != 1 || graph.cypherRequests[0].Params["person_query"] != "product designer" {
		t.Fatalf("cypher requests = %#v", graph.cypherRequests)
	}
}

func TestGraphEffectiveAccessPathsEndpoint(t *testing.T) {
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{
		{{Values: map[string]any{
			"identity_urn":            "urn:cerebro:writer:identity:email:alice@example.com",
			"identity_entity_type":    "identity.email",
			"identity_label":          "alice@example.com",
			"principal_urn":           "urn:cerebro:writer:okta_user:00u1",
			"principal_entity_type":   "okta.user",
			"principal_label":         "alice@example.com",
			"mediator_urn":            "urn:cerebro:writer:okta_group:grp-security",
			"mediator_entity_type":    "okta.group",
			"mediator_label":          "Security Engineering",
			"target_urn":              "urn:cerebro:writer:okta_application:app-aws-admin",
			"target_entity_type":      "okta.application",
			"target_label":            "AWS Admin Console",
			"entitlement_urn":         "urn:cerebro:writer:okta_entitlement:administratoraccess",
			"entitlement_entity_type": "okta.entitlement",
			"entitlement_label":       "AdministratorAccess",
			"capability_urn":          "urn:cerebro:writer:privileged_capability:cloud_admin",
			"capability_entity_type":  "privileged.capability",
			"capability_label":        "Cloud administrator",
			"assignment_kind":         "group_app_assignment",
			"relation_chain":          []any{"member_of", "assigned_to", "grants_entitlement", "confers_capability"},
			"edges": []any{
				map[string]any{
					"from_urn":         "urn:cerebro:writer:okta_user:00u1",
					"from_entity_type": "okta.user",
					"from_label":       "alice@example.com",
					"relation":         "member_of",
					"to_urn":           "urn:cerebro:writer:okta_group:grp-security",
					"to_entity_type":   "okta.group",
					"to_label":         "Security Engineering",
					"source_id":        "okta",
					"runtime_id":       "writer-okta",
					"attributes_json":  `{"event_id":"evt-member","at":"2026-06-10T17:00:00Z"}`,
				},
				map[string]any{
					"from_urn":         "urn:cerebro:writer:okta_group:grp-security",
					"from_entity_type": "okta.group",
					"from_label":       "Security Engineering",
					"relation":         "assigned_to",
					"to_urn":           "urn:cerebro:writer:okta_application:app-aws-admin",
					"to_entity_type":   "okta.application",
					"to_label":         "AWS Admin Console",
					"source_id":        "okta",
					"runtime_id":       "writer-okta",
					"attributes_json":  `{"event_id":"evt-assign","at":"2026-06-10T18:00:00Z"}`,
				},
				map[string]any{
					"from_urn":         "urn:cerebro:writer:okta_application:app-aws-admin",
					"from_entity_type": "okta.application",
					"from_label":       "AWS Admin Console",
					"relation":         "grants_entitlement",
					"to_urn":           "urn:cerebro:writer:okta_entitlement:administratoraccess",
					"to_entity_type":   "okta.entitlement",
					"to_label":         "AdministratorAccess",
					"source_id":        "okta",
					"runtime_id":       "writer-okta",
					"attributes_json":  `{"event_id":"evt-entitlement","at":"2026-06-10T18:00:00Z"}`,
				},
				map[string]any{
					"from_urn":         "urn:cerebro:writer:okta_entitlement:administratoraccess",
					"from_entity_type": "okta.entitlement",
					"from_label":       "AdministratorAccess",
					"relation":         "confers_capability",
					"to_urn":           "urn:cerebro:writer:privileged_capability:cloud_admin",
					"to_entity_type":   "privileged.capability",
					"to_label":         "Cloud administrator",
					"source_id":        "okta",
					"runtime_id":       "writer-okta",
					"attributes_json":  `{"event_id":"evt-capability","at":"2026-06-10T18:00:00Z"}`,
				},
			},
		}}},
	}}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/effective-access-paths?tenant_id=writer&identity_query=alice&application_urn=urn%3Acerebro%3Awriter%3Aokta_application%3Aapp-aws-admin&capability=cloud_admin&limit=5")
	if err != nil {
		t.Fatalf("GET /platform/graph/effective-access-paths error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/effective-access-paths status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Counts   struct {
			Paths             int `json:"paths"`
			GroupMediatedPath int `json:"group_mediated_paths"`
		} `json:"counts"`
		Paths []struct {
			Mediator struct {
				URN string `json:"urn"`
			} `json:"mediator"`
			Capability struct {
				URN string `json:"urn"`
			} `json:"capability"`
			Edges []struct {
				Relation  string `json:"relation"`
				SourceID  string `json:"source_id"`
				RuntimeID string `json:"runtime_id"`
				EventID   string `json:"event_id"`
				At        string `json:"at"`
			} `json:"edges"`
		} `json:"paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantID != "writer" || body.Counts.Paths != 1 || body.Counts.GroupMediatedPath != 1 || len(body.Paths) != 1 {
		t.Fatalf("body = %#v", body)
	}
	if body.Paths[0].Mediator.URN != "urn:cerebro:writer:okta_group:grp-security" || body.Paths[0].Capability.URN != "urn:cerebro:writer:privileged_capability:cloud_admin" {
		t.Fatalf("path = %#v", body.Paths[0])
	}
	if len(body.Paths[0].Edges) != 4 || body.Paths[0].Edges[1].SourceID != "okta" || body.Paths[0].Edges[1].RuntimeID != "writer-okta" || body.Paths[0].Edges[1].EventID != "evt-assign" || body.Paths[0].Edges[1].At != "2026-06-10T18:00:00Z" {
		t.Fatalf("edges = %#v", body.Paths[0].Edges)
	}
	if len(graph.cypherRequests) != 1 || graph.cypherRequests[0].Params["capability_id"] != "cloud_admin" {
		t.Fatalf("cypher requests = %#v", graph.cypherRequests)
	}
}

func TestGraphCrownJewelRankingsEndpoint(t *testing.T) {
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{
		{{Values: map[string]any{
			"seed_urn":         "urn:cerebro:writer:aws_secret_store:prod-secrets",
			"seed_entity_type": "aws.secret_store",
			"seed_label":       "prod-secrets",
		}}},
		{{Values: map[string]any{
			"seed_urn":         "urn:cerebro:writer:aws_secret_store:prod-secrets",
			"from_urn":         "urn:cerebro:writer:aws_public_principal:public_internet",
			"from_entity_type": "aws.public_principal",
			"from_label":       "public_internet",
			"relation":         "can_reach",
			"to_urn":           "urn:cerebro:writer:aws_secret_store:prod-secrets",
			"to_entity_type":   "aws.secret_store",
			"to_label":         "prod-secrets",
		}}},
	}}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/crown-jewel-rankings?tenant_id=writer&account_id=123456789012&entity_type=aws.secret_store&limit=5&depth=3&seed_limit=5")
	if err != nil {
		t.Fatalf("GET /platform/graph/crown-jewel-rankings error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/crown-jewel-rankings status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Counts   struct {
			Seeds int `json:"seeds"`
		} `json:"counts"`
		Rankings []struct {
			Entity struct {
				URN string `json:"urn"`
			} `json:"entity"`
			Seed bool `json:"seed"`
		} `json:"rankings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantID != "writer" || body.Counts.Seeds != 1 || len(body.Rankings) == 0 {
		t.Fatalf("body = %#v", body)
	}
	if len(graph.cypherRequests) != 2 || graph.cypherRequests[0].Params["entity_type"] != "aws.secret_store" {
		t.Fatalf("cypher requests = %#v", graph.cypherRequests)
	}
}

func TestAuthMiddlewareRejectsUnscopedGraphIngestRunListings(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/ingest-runs?status=failed", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-runs error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/ingest-runs status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listReq := connect.NewRequest(&cerebrov1.ListGraphIngestRunsRequest{
		Status: graphstore.IngestRunStatusFailed,
	})
	listReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.ListGraphIngestRuns(context.Background(), listReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ListGraphIngestRuns(unscoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareNormalizesForeignGraphIngestRunLookup(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubGraphStore{ingestRuns: map[string]graphstore.IngestRun{
		"other-run": {
			ID:        "other-run",
			RuntimeID: "runtime-other",
			SourceID:  "okta",
			TenantID:  "other",
			Status:    graphstore.IngestRunStatusCompleted,
		},
	}}
	app := New(cfg, Dependencies{GraphStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/ingest-runs/other-run", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-runs/other-run error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /platform/graph/ingest-runs/other-run status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getReq := connect.NewRequest(&cerebrov1.GetGraphIngestRunRequest{Id: "other-run"})
	getReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetGraphIngestRun(context.Background(), getReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetGraphIngestRun(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodeNotFound, err)
	}
}

func TestAuthMiddlewareRequiresTenantScopeForGlobalWorkflowOperations(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{AppendLog: &recordingAppendLog{}, GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	replayReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/workflow/replay", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest replay: %v", err)
	}
	replayReq.Header.Set("Authorization", "Bearer writer-key")
	replayReq.Header.Set("Content-Type", "application/json")
	replayResp, err := server.Client().Do(replayReq)
	if err != nil {
		t.Fatalf("POST /platform/workflow/replay error = %v", err)
	}
	_ = replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/workflow/replay status = %d, want %d", replayResp.StatusCode, http.StatusForbidden)
	}

	healthReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/ingest-health", nil)
	if err != nil {
		t.Fatalf("NewRequest health: %v", err)
	}
	healthReq.Header.Set("Authorization", "Bearer writer-key")
	healthResp, err := server.Client().Do(healthReq)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-health error = %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/ingest-health status = %d, want %d", healthResp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectReplayReq := connect.NewRequest(&cerebrov1.ReplayWorkflowEventsRequest{})
	connectReplayReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.ReplayWorkflowEvents(context.Background(), connectReplayReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ReplayWorkflowEvents(unscoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	connectHealthReq := connect.NewRequest(&cerebrov1.CheckGraphIngestHealthRequest{})
	connectHealthReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.CheckGraphIngestHealth(context.Background(), connectHealthReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("CheckGraphIngestHealth(scoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnKnowledgeWrites(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	decisionReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/platform/knowledge/decisions",
		strings.NewReader(`{"decisionType":"finding-triage","targetIds":["urn:cerebro:other:asset:app"]}`),
	)
	if err != nil {
		t.Fatalf("NewRequest decision: %v", err)
	}
	decisionReq.Header.Set("Authorization", "Bearer writer-key")
	decisionReq.Header.Set("Content-Type", "application/json")
	decisionResp, err := server.Client().Do(decisionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/decisions error = %v", err)
	}
	_ = decisionResp.Body.Close()
	if decisionResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/knowledge/decisions status = %d, want %d", decisionResp.StatusCode, http.StatusForbidden)
	}

	actionReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/platform/knowledge/actions",
		strings.NewReader(`{"title":"Fix finding","targetIds":["urn:cerebro:writer:asset:app"],"metadata":{"tenant_id":"other"}}`),
	)
	if err != nil {
		t.Fatalf("NewRequest action: %v", err)
	}
	actionReq.Header.Set("Authorization", "Bearer writer-key")
	actionReq.Header.Set("Content-Type", "application/json")
	actionResp, err := server.Client().Do(actionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/actions error = %v", err)
	}
	_ = actionResp.Body.Close()
	if actionResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/knowledge/actions status = %d, want %d", actionResp.StatusCode, http.StatusForbidden)
	}

	metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "other"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectActionReq := connect.NewRequest(&cerebrov1.WriteActionRequest{
		Title:     "Fix finding",
		TargetIds: []string{"urn:cerebro:writer:asset:app"},
		Metadata:  metadata,
	})
	connectActionReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.WriteAction(context.Background(), connectActionReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WriteAction(other metadata tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	connectOutcomeReq := connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
		DecisionId:  "urn:cerebro:other:decision:decision-1",
		OutcomeType: "finding-resolution",
		Verdict:     "resolved",
	})
	connectOutcomeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.WriteOutcome(context.Background(), connectOutcomeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WriteOutcome(other decision tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestBootstrapHealthDegradesOnDependencyError(t *testing.T) {
	const rawDependencyError = "state store unavailable at postgres://user:pass@internal-db:5432/cerebro"
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  stubAppendLog{},
		StateStore: stubStore{err: errors.New(rawDependencyError)},
		GraphStore: stubStore{},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "degraded" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "degraded")
	}
	if got := healthResp.Msg.Components[1].Status; got != "error" {
		t.Fatalf("state_store status = %q, want %q", got, "error")
	}
	if got := healthResp.Msg.Components[1].Detail; got != "unhealthy" {
		t.Fatalf("state_store detail = %q, want sanitized detail", got)
	}
	if got := healthResp.Msg.Components[1].Detail; got == rawDependencyError {
		t.Fatalf("state_store detail leaked raw dependency error")
	}
}

func TestBootstrapReadinessReturnsUnavailableWhenDegraded(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: stubStore{err: errors.New("state store unavailable")},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /health response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /health response: %v", err)
	}
	if payload["status"] != "degraded" {
		t.Fatalf("health status = %#v, want degraded", payload["status"])
	}
}

func TestBootstrapLivenessDoesNotPingDependencies(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: stubStore{err: errors.New("state store unavailable")},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, path := range []string{"/healthz", "/livez"} {
		resp, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		var payload map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("decode %s response: %v", path, err)
		}
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close %s response body: %v", path, closeErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusOK)
		}
		if payload["status"] != "live" {
			t.Fatalf("%s status = %#v, want live", path, payload["status"])
		}
	}
}

func TestBackfillFindingRiskSkipsMissingStateStore(t *testing.T) {
	app := New(config.Config{}, Dependencies{}, nil)
	if err := app.BackfillFindingRisk(context.Background()); err != nil {
		t.Fatalf("BackfillFindingRisk() error = %v, want nil without state store", err)
	}
}

func TestPublicCollectionRoutesRejectUndocumentedMethods(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	handler := app.Handler()
	for _, path := range []string{"/health", "/healthz", "/livez", "/sources"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d, want %d", path, resp.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestBootstrapHealthPingsUseTimeoutContext(t *testing.T) {
	stateStore := &deadlineAwareStore{}
	response := healthResponse(context.Background(), config.Config{ImageTag: "v9.9.9"}, Dependencies{StateStore: stateStore})
	if response.GetStatus() != "ready" {
		t.Fatalf("health status = %q, want ready", response.GetStatus())
	}
	if response.GetServiceName() != buildinfo.ServiceName || response.GetVersion() != buildinfo.Version || response.GetCommit() != buildinfo.Commit {
		t.Fatalf("health build metadata = service:%q version:%q commit:%q", response.GetServiceName(), response.GetVersion(), response.GetCommit())
	}
	if response.GetApiVersion() != buildinfo.APIVersion || response.GetBuildDate() != buildinfo.BuildDate || response.GetImageTag() != "v9.9.9" {
		t.Fatalf("health deploy metadata = api:%q build:%q image:%q", response.GetApiVersion(), response.GetBuildDate(), response.GetImageTag())
	}
	if !stateStore.sawDeadline {
		t.Fatal("state store ping did not receive a deadline")
	}
}

func TestBootstrapHealthTreatsTypedNilPingerAsUnconfigured(t *testing.T) {
	var stateStore *typedNilPinger
	response := healthResponse(context.Background(), config.Config{}, Dependencies{StateStore: stateStore})
	if response.GetStatus() != "ready" {
		t.Fatalf("health status = %q, want ready", response.GetStatus())
	}
	if got := response.GetComponents()[1].GetStatus(); got != "unconfigured" {
		t.Fatalf("state_store status = %q, want unconfigured", got)
	}
}

func TestBootstrapHealthDefaultsImageTagFromBuildVersion(t *testing.T) {
	previousVersion := buildinfo.Version
	buildinfo.Version = "2.1.50"
	t.Cleanup(func() { buildinfo.Version = previousVersion })

	response := healthResponse(context.Background(), config.Config{}, Dependencies{})
	if response.GetImageTag() != "v2.1.50" {
		t.Fatalf("ImageTag = %q, want %q", response.GetImageTag(), "v2.1.50")
	}
}

func TestReadProtoJSONRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/reports/finding-summary/runs", strings.NewReader(strings.Repeat("x", maxProtoJSONBodyBytes+1)))
	err := readProtoJSON(req, &cerebrov1.RunReportRequest{})
	if err == nil {
		t.Fatal("readProtoJSON() error = nil, want non-nil")
	}
	if !errors.Is(err, errProtoJSONBodyTooLarge) {
		t.Fatalf("readProtoJSON() error = %v, want size error", err)
	}
	if !errors.Is(err, errInvalidHTTPRequest) {
		t.Fatalf("readProtoJSON() error = %v, want invalid request error", err)
	}
}

func TestReadProtoJSONClassifiesMalformedBodyAsInvalidRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/reports/finding-summary/runs", strings.NewReader("{"))
	err := readProtoJSON(req, &cerebrov1.RunReportRequest{})
	if !errors.Is(err, errInvalidHTTPRequest) {
		t.Fatalf("readProtoJSON() error = %v, want invalid request error", err)
	}

	recorder := httptest.NewRecorder()
	writeFindingError(recorder, err)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestSourceRuntimeEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{}
	runtimeStore := &stubRuntimeStore{}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	putBody, err := protojson.Marshal(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "test",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal put runtime body: %v", err)
	}
	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/writer-okta-users", bytes.NewReader(putBody))
	if err != nil {
		t.Fatalf("new put request: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := server.Client().Do(putReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := putResp.Body.Close(); closeErr != nil {
			t.Fatalf("close put runtime response body: %v", closeErr)
		}
	}()
	var putPayload map[string]any
	if err := json.NewDecoder(putResp.Body).Decode(&putPayload); err != nil {
		t.Fatalf("decode put runtime response: %v", err)
	}
	runtimePayload, ok := putPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime payload = %#v, want object", putPayload["runtime"])
	}
	configPayload, ok := runtimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime config = %#v, want object", runtimePayload["config"])
	}
	if got := configPayload["token"]; got != "[redacted]" {
		t.Fatalf("put runtime token = %#v, want [redacted]", got)
	}
	if got := runtimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("put runtime tenant_id = %#v, want writer", got)
	}

	getResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-users")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get runtime response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode get runtime response: %v", err)
	}
	getRuntimePayload, ok := getPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("get runtime payload = %#v, want object", getPayload["runtime"])
	}
	if got := getRuntimePayload["source_id"]; got != "okta" {
		t.Fatalf("get runtime source_id = %#v, want okta", got)
	}
	if got := getRuntimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("get runtime tenant_id = %#v, want writer", got)
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /source-runtimes error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list runtime response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list runtime response: %v", err)
	}
	listRuntimes, ok := listPayload["runtimes"].([]any)
	if !ok || len(listRuntimes) != 1 {
		t.Fatalf("list runtimes = %#v, want one runtime", listPayload["runtimes"])
	}
	listRuntimePayload, ok := listRuntimes[0].(map[string]any)
	if !ok {
		t.Fatalf("listed runtime = %#v, want object", listRuntimes[0])
	}
	listConfigPayload, ok := listRuntimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("listed runtime config = %#v, want object", listRuntimePayload["config"])
	}
	if got := listConfigPayload["token"]; got != "[redacted]" {
		t.Fatalf("listed runtime token = %#v, want [redacted]", got)
	}

	syncReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/sync?page_limit=1", nil)
	if err != nil {
		t.Fatalf("new sync request: %v", err)
	}
	syncResp, err := server.Client().Do(syncReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/sync error = %v", err)
	}
	defer func() {
		if closeErr := syncResp.Body.Close(); closeErr != nil {
			t.Fatalf("close sync runtime response body: %v", closeErr)
		}
	}()
	var syncPayload map[string]any
	if err := json.NewDecoder(syncResp.Body).Decode(&syncPayload); err != nil {
		t.Fatalf("decode sync runtime response: %v", err)
	}
	if got := syncPayload["events_appended"]; got != float64(1) {
		t.Fatalf("sync events_appended = %#v, want 1", got)
	}
	if got := syncPayload["entities_projected"]; got != float64(4) {
		t.Fatalf("sync entities_projected = %#v, want 4", got)
	}
	if got := syncPayload["links_projected"]; got != float64(5) {
		t.Fatalf("sync links_projected = %#v, want 5", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	putRuntimeResp, err := client.PutSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer",
			Config:   map[string]string{"token": "test"},
		},
	}))
	if err != nil {
		t.Fatalf("PutSourceRuntime() error = %v", err)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("PutSourceRuntime token = %q, want [redacted]", got)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("PutSourceRuntime tenant_id = %q, want writer", got)
	}

	getRuntimeResp, err := client.GetSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{
		Id: "writer-okta-users",
	}))
	if err != nil {
		t.Fatalf("GetSourceRuntime() error = %v", err)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetSourceId(); got != "okta" {
		t.Fatalf("GetSourceRuntime source_id = %q, want okta", got)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("GetSourceRuntime tenant_id = %q, want writer", got)
	}

	syncRuntimeResp, err := client.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-okta-users",
		PageLimit: 1,
	}))
	if err != nil {
		t.Fatalf("SyncSourceRuntime() error = %v", err)
	}
	if syncRuntimeResp.Msg.GetEventsAppended() != 1 {
		t.Fatalf("SyncSourceRuntime events_appended = %d, want 1", syncRuntimeResp.Msg.GetEventsAppended())
	}
	if syncRuntimeResp.Msg.GetEntitiesProjected() != 4 {
		t.Fatalf("SyncSourceRuntime entities_projected = %d, want 4", syncRuntimeResp.Msg.GetEntitiesProjected())
	}
	if syncRuntimeResp.Msg.GetLinksProjected() != 5 {
		t.Fatalf("SyncSourceRuntime links_projected = %d, want 5", syncRuntimeResp.Msg.GetLinksProjected())
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("len(appendLog.events) = %d, want 2", len(appendLog.events))
	}
	if len(runtimeStore.entities) == 0 || len(graphStore.entities) == 0 {
		t.Fatalf("projected entities = state:%d graph:%d, want non-zero", len(runtimeStore.entities), len(graphStore.entities))
	}
}

func TestSourceRuntimeHealthEndpointIncludesRuntimeGraphAndFindingState(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	started := now.Add(-10 * time.Minute)
	finished := now.Add(-9 * time.Minute)
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-users": {
				Id:       "writer-okta-users",
				SourceId: "okta",
				TenantId: "writer",
				Config: map[string]string{
					"family":                                  "user",
					"__cerebro_runtime_status":                "completed",
					"__cerebro_runtime_records_scanned":       "8",
					"__cerebro_runtime_records_accepted":      "7",
					"__cerebro_runtime_records_rejected":      "1",
					"__cerebro_runtime_entities_projected":    "12",
					"__cerebro_runtime_links_projected":       "16",
					"__cerebro_runtime_last_failure_category": "missing_required_attribute",
					"__cerebro_runtime_contract_probe_state":  "failure",
				},
				Checkpoint: &cerebrov1.SourceCheckpoint{
					Watermark:    timestamppb.New(now.Add(-2 * time.Hour)),
					CursorOpaque: "checkpoint-secret",
				},
				NextCursor:   &cerebrov1.SourceCursor{Opaque: "next-secret"},
				LastSyncedAt: timestamppb.New(now.Add(-30 * time.Minute)),
			},
		},
		findingEvaluationRuns: map[string]*cerebrov1.FindingEvaluationRun{
			"finding-run-1": {
				Id:               "finding-run-1",
				RuntimeId:        "writer-okta-users",
				RuleId:           "okta.user.mfa",
				Status:           "completed",
				EventsEvaluated:  7,
				EventsProcessed:  9,
				EventsMatched:    3,
				FindingsUpserted: 2,
				FindingsEmitted:  1,
				StartedAt:        timestamppb.New(started),
				FinishedAt:       timestamppb.New(finished),
			},
		},
	}
	graphStore := &stubGraphStore{
		ingestRuns: map[string]graphstore.IngestRun{
			"graph-run-1": {
				ID:                "graph-run-1",
				RuntimeID:         "writer-okta-users",
				Status:            graphstore.IngestRunStatusCompleted,
				StartedAt:         started.Format(time.RFC3339Nano),
				FinishedAt:        finished.Format(time.RFC3339Nano),
				PagesRead:         4,
				EventsRead:        8,
				EntitiesProjected: 12,
				LinksProjected:    16,
				GraphNodesBefore:  100,
				GraphNodesAfter:   109,
				GraphLinksBefore:  200,
				GraphLinksAfter:   211,
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/source-runtimes/health?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /source-runtimes/health error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close health response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /source-runtimes/health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode source runtime health response: %v", err)
	}
	runtimes, ok := payload["runtimes"].([]any)
	if !ok || len(runtimes) != 1 {
		t.Fatalf("health runtimes = %#v, want one runtime", payload["runtimes"])
	}
	record, ok := runtimes[0].(map[string]any)
	if !ok {
		t.Fatalf("health runtime = %#v, want object", runtimes[0])
	}
	if got := record["runtime_id"]; got != "writer-okta-users" {
		t.Fatalf("runtime_id = %#v, want writer-okta-users", got)
	}
	if got := record["family"]; got != "user" {
		t.Fatalf("family = %#v, want user", got)
	}
	if got := record["enabled_state"]; got != "enabled" {
		t.Fatalf("enabled_state = %#v, want enabled", got)
	}
	if got := record["status"]; got != "failing" {
		t.Fatalf("status = %#v, want failing", got)
	}
	recentSync, ok := record["recent_sync"].(map[string]any)
	if !ok {
		t.Fatalf("recent_sync = %#v, want object", record["recent_sync"])
	}
	if got := recentSync["records_scanned"]; got != float64(8) {
		t.Fatalf("records_scanned = %#v, want 8", got)
	}
	if got := recentSync["records_accepted"]; got != float64(7) {
		t.Fatalf("records_accepted = %#v, want 7", got)
	}
	if got := recentSync["records_rejected"]; got != float64(1) {
		t.Fatalf("records_rejected = %#v, want 1", got)
	}
	if got := recentSync["entities_projected"]; got != float64(12) {
		t.Fatalf("entities_projected = %#v, want 12", got)
	}
	if got := recentSync["links_projected"]; got != float64(16) {
		t.Fatalf("links_projected = %#v, want 16", got)
	}
	if got := record["last_failure_category"]; got != "missing_required_attribute" {
		t.Fatalf("last_failure_category = %#v, want missing_required_attribute", got)
	}
	if got := record["contract_probe_state"]; got != "failure" {
		t.Fatalf("contract_probe_state = %#v, want failure", got)
	}
	if got := record["cursor_pending"]; got != true {
		t.Fatalf("cursor_pending = %#v, want true", got)
	}
	if got := record["checkpoint_cursor_present"]; got != true {
		t.Fatalf("checkpoint_cursor_present = %#v, want true", got)
	}
	if _, ok := record["next_cursor"]; ok {
		t.Fatalf("health record leaked next_cursor: %#v", record["next_cursor"])
	}
	graphRun, ok := record["latest_graph_run"].(map[string]any)
	if !ok {
		t.Fatalf("latest_graph_run = %#v, want object", record["latest_graph_run"])
	}
	if got := graphRun["graph_node_delta"]; got != float64(9) {
		t.Fatalf("graph_node_delta = %#v, want 9", got)
	}
	if got := graphRun["graph_link_delta"]; got != float64(11) {
		t.Fatalf("graph_link_delta = %#v, want 11", got)
	}
	if got := graphRun["duration_seconds"]; got != float64(60) {
		t.Fatalf("graph duration_seconds = %#v, want 60", got)
	}
	findingRun, ok := record["latest_finding_evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("latest_finding_evaluation = %#v, want object", record["latest_finding_evaluation"])
	}
	if got := findingRun["events_processed"]; got != float64(9) {
		t.Fatalf("finding events_processed = %#v, want 9", got)
	}
	if got := findingRun["duration_seconds"]; got != float64(60) {
		t.Fatalf("finding duration_seconds = %#v, want 60", got)
	}
}

func TestSourceRuntimeInvalidEventsEndpointReturnsSafeDiagnostic(t *testing.T) {
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-evidencecas": {
				Id:       "writer-evidencecas",
				SourceId: "evidence_cas",
				TenantId: "writer",
				Config: map[string]string{
					"__cerebro_runtime_last_failure_category":    "missing_required_attribute",
					"__cerebro_runtime_last_invalid_event_id":    "evidence-cas-redacted-event",
					"__cerebro_runtime_last_invalid_field":       "resource_urn",
					"__cerebro_runtime_last_invalid_status":      "terminal",
					"__cerebro_runtime_last_invalid_retryable":   "false",
					"__cerebro_runtime_last_invalid_observed_at": "2026-06-06T00:05:00Z",
					"__cerebro_runtime_last_invalid_occurred_at": "2026-06-06T00:00:00Z",
					"__cerebro_runtime_last_invalid_diagnostic":  "missing required field resource_urn",
				},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: runtimeStore}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/source-runtimes/writer-evidencecas/invalid-events")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/invalid-events error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close invalid events response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET invalid-events status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode invalid events response: %v", err)
	}
	events, ok := payload["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("invalid events = %#v, want one event", payload["events"])
	}
	record, ok := events[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid event = %#v, want object", events[0])
	}
	if got := record["failure_category"]; got != "missing_required_attribute" {
		t.Fatalf("failure_category = %#v, want missing_required_attribute", got)
	}
	fields, ok := record["fields"].([]any)
	if !ok || len(fields) != 1 || fields[0] != "resource_urn" {
		t.Fatalf("fields = %#v, want resource_urn", record["fields"])
	}
	if got := record["status"]; got != "terminal" {
		t.Fatalf("status = %#v, want terminal", got)
	}
	if got := record["retryable"]; got != false {
		t.Fatalf("retryable = %#v, want false", got)
	}
	if _, present := record["payload"]; present {
		t.Fatalf("invalid event leaked payload: %#v", record["payload"])
	}
}

func TestConnectSourceRuntimeEndpointsResolveEnvReferences(t *testing.T) {
	source := &bootstrapTokenSource{id: "runtime_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	t.Setenv("CEREBRO_SOURCE_RUNTIME_TOKEN_TOKEN", "resolved-token")
	runtimeStore := &stubRuntimeStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	if _, err := client.PutSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-runtime-token",
			SourceId: "runtime_token",
			Config:   map[string]string{"token": "env:CEREBRO_SOURCE_RUNTIME_TOKEN_TOKEN"}, // #nosec G101 -- env-reference test fixture, not credential material.
		},
	})); err != nil {
		t.Fatalf("PutSourceRuntime() error = %v", err)
	}
	if source.checkToken != "resolved-token" {
		t.Fatalf("connect put check token = %q, want resolved-token", source.checkToken)
	}
	if got := runtimeStore.runtimes["writer-runtime-token"].GetConfig()["token"]; got != "env:CEREBRO_SOURCE_RUNTIME_TOKEN_TOKEN" {
		t.Fatalf("stored token = %q, want env reference", got)
	}

	if _, err := client.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{
		Id: "writer-runtime-token",
	})); err != nil {
		t.Fatalf("SyncSourceRuntime() error = %v", err)
	}
	if source.readToken != "resolved-token" {
		t.Fatalf("connect sync read token = %q, want resolved-token", source.readToken)
	}
}

func TestSyncSourceRuntimeReturnsConflictWhenLeaseHeld(t *testing.T) {
	source := &bootstrapTokenSource{id: "runtime_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &leaseAwareRuntimeStore{
		stubRuntimeStore: &stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-runtime-token": {
					Id:       "writer-runtime-token",
					SourceId: "runtime_token",
					TenantId: "writer",
				},
			},
		},
		holder:   "other-task",
		holdsAll: true,
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	t.Run("http", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-runtime-token/sync", nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
	})

	t.Run("connect", func(t *testing.T) {
		client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
		_, err := client.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{
			Id: "writer-runtime-token",
		}))
		if err == nil {
			t.Fatal("SyncSourceRuntime() error = nil, want non-nil")
		}
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) {
			t.Fatalf("SyncSourceRuntime() error %v is not *connect.Error", err)
		}
		if connectErr.Code() != connect.CodeAborted {
			t.Fatalf("SyncSourceRuntime() code = %v, want %v", connectErr.Code(), connect.CodeAborted)
		}
	})

	if source.readToken != "" {
		t.Fatalf("source.Read should not have been called while lease was held; readToken = %q", source.readToken)
	}
}

func TestGraphIngestEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-users": {
			Id:       "writer-okta-users",
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "test",
			},
		},
		"writer-okta-bad": {
			Id:       "writer-okta-bad",
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "missing",
				"token":  "test",
			},
		},
	}}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	runReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/graph-ingest-runs?page_limit=1&checkpoint_id=graph-okta", nil)
	if err != nil {
		t.Fatalf("new graph ingest request: %v", err)
	}
	runResp, err := server.Client().Do(runReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs error = %v", err)
	}
	defer func() {
		if closeErr := runResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest response body: %v", closeErr)
		}
	}()
	if runResp.StatusCode != http.StatusOK {
		t.Fatalf("graph ingest status = %d, want %d", runResp.StatusCode, http.StatusOK)
	}
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode graph ingest response: %v", err)
	}
	resultPayload, ok := runPayload["result"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest result = %#v, want object", runPayload["result"])
	}
	runRecord, ok := resultPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest run = %#v, want object", resultPayload["run"])
	}
	runID, ok := runRecord["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("graph ingest run id = %#v, want non-empty string", runRecord["id"])
	}
	if got := runRecord["status"]; got != "completed" {
		t.Fatalf("graph ingest status = %#v, want completed", got)
	}
	if got := runRecord["checkpoint_id"]; got != "graph-okta" {
		t.Fatalf("graph ingest checkpoint_id = %#v, want graph-okta", got)
	}
	overrideReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/source-runtimes/writer-okta-users/graph-ingest-runs?page_limit=1&reset_checkpoint=true",
		strings.NewReader(`{"checkpoint_id":"body-checkpoint"}`),
	)
	if err != nil {
		t.Fatalf("new graph ingest override request: %v", err)
	}
	overrideResp, err := server.Client().Do(overrideReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs override error = %v", err)
	}
	defer func() {
		if closeErr := overrideResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest override response body: %v", closeErr)
		}
	}()
	var overridePayload map[string]any
	if err := json.NewDecoder(overrideResp.Body).Decode(&overridePayload); err != nil {
		t.Fatalf("decode graph ingest override response: %v", err)
	}
	overrideResult, ok := overridePayload["result"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest override result = %#v, want object", overridePayload["result"])
	}
	overrideRun, ok := overrideResult["run"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest override run = %#v, want object", overrideResult["run"])
	}
	if got := overrideRun["checkpoint_id"]; got != "body-checkpoint" {
		t.Fatalf("graph ingest override checkpoint_id = %#v, want body-checkpoint", got)
	}

	getResp, err := server.Client().Get(server.URL + "/platform/graph/ingest-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest get response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode graph ingest get response: %v", err)
	}
	getRun, ok := getPayload["run"].(map[string]any)
	if !ok || getRun["id"] != runID {
		t.Fatalf("graph ingest get run = %#v, want id %q", getPayload["run"], runID)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	_, err = client.RunGraphIngestRuntime(context.Background(), connect.NewRequest(&cerebrov1.RunGraphIngestRuntimeRequest{
		RuntimeId: "writer-okta-bad",
		PageLimit: 1,
	}))
	if err == nil {
		t.Fatal("RunGraphIngestRuntime(bad) error = nil, want non-nil")
	}
	listResp, err := client.ListGraphIngestRuns(context.Background(), connect.NewRequest(&cerebrov1.ListGraphIngestRunsRequest{
		Status: graphstore.IngestRunStatusFailed,
		Limit:  5,
	}))
	if err != nil {
		t.Fatalf("ListGraphIngestRuns(failed) error = %v", err)
	}
	if got := len(listResp.Msg.GetRuns()); got != 1 {
		t.Fatalf("len(ListGraphIngestRuns(failed).Runs) = %d, want 1", got)
	}
	if got := listResp.Msg.GetFailedCount(); got != 1 {
		t.Fatalf("ListGraphIngestRuns failed_count = %d, want 1", got)
	}
	healthResp, err := client.CheckGraphIngestHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckGraphIngestHealthRequest{Limit: 5}))
	if err != nil {
		t.Fatalf("CheckGraphIngestHealth() error = %v", err)
	}
	if got := healthResp.Msg.GetStatus(); got != "degraded" {
		t.Fatalf("CheckGraphIngestHealth status = %q, want degraded", got)
	}
	if got := healthResp.Msg.GetFailedCount(); got != 1 {
		t.Fatalf("CheckGraphIngestHealth failed_count = %d, want 1", got)
	}
}

func TestGraphIngestArchetypeRuntimeProjectsFindingsEndToEnd(t *testing.T) {
	var sawAuth atomic.Bool
	archetypeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawAuth.Store(true)
		}
		switch r.URL.Path {
		case "/api/v1/scans":
			writeTestJSON(t, w, []map[string]any{{
				"id":            1,
				"repository_id": 7,
				"status":        "completed",
				"completed_at":  "2026-06-17T12:05:00Z",
			}})
		case "/api/v1/repositories":
			writeTestJSON(t, w, []map[string]any{{
				"id":    7,
				"owner": "WriterInternal",
				"name":  "Archetype",
			}})
		case "/api/v1/scans/1/vulnerabilities":
			writeTestJSON(t, w, []map[string]any{{
				"id":             10,
				"scan_id":        1,
				"line_number":    42,
				"file_path":      "backend/app/core/security.py",
				"category":       "ssrf",
				"severity":       "high",
				"description":    "Server-side request forgery in outbound fetch path",
				"analyzer_score": 0.91,
				"analyzer_label": "high-confidence",
				"created_at":     "2026-06-17T12:06:00Z",
			}})
		case "/api/v1/repositories/7/knowledge":
			writeTestJSON(t, w, map[string]any{
				"entries": []map[string]any{{
					"slug":            "repository-commit-learning",
					"title":           "Repository commit learning",
					"summary":         "Archetype learned the latest repository head.",
					"repository_id":   7,
					"repository_name": "Archetype",
					"owner":           "WriterInternal",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer archetypeAPI.Close()

	source, err := archetypesource.NewFixture()
	if err != nil {
		t.Fatalf("archetype NewFixture() error = %v", err)
	}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry(archetype) error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-archetype-vulnerabilities": {
			Id:       "writer-archetype-vulnerabilities",
			SourceId: "archetype",
			TenantId: "writer",
			Config: map[string]string{
				"base_url": archetypeAPI.URL,
				"family":   "vulnerability",
				"token":    "test-token",
			},
		},
	}}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	runResp, err := server.Client().Post(server.URL+"/source-runtimes/writer-archetype-vulnerabilities/graph-ingest-runs?page_limit=1&checkpoint_id=graph-archetype", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs error = %v", err)
	}
	defer func() { _ = runResp.Body.Close() }()
	if runResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(runResp.Body)
		t.Fatalf("graph ingest status = %d, want 200: %s", runResp.StatusCode, body)
	}
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode graph ingest response: %v", err)
	}
	resultPayload, ok := runPayload["result"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest result = %#v, want object", runPayload["result"])
	}
	ingestPayload, ok := resultPayload["ingest"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest details = %#v, want object", resultPayload["ingest"])
	}
	if got := ingestPayload["events_read"]; got != float64(3) {
		t.Fatalf("events_read = %#v, want 3", got)
	}
	if got := ingestPayload["entities_projected"]; got != float64(4) {
		t.Fatalf("entities_projected = %#v, want 4", got)
	}
	if got := ingestPayload["links_projected"]; got != float64(8) {
		t.Fatalf("links_projected = %#v, want 8", got)
	}
	if !sawAuth.Load() {
		t.Fatal("Archetype API did not receive bearer token")
	}

	repoURN := "urn:cerebro:writer:github_code_repository:WriterInternal/Archetype"
	scanURN := "urn:cerebro:writer:archetype_scan:1"
	findingURN := "urn:cerebro:writer:archetype_finding:10"
	noteURN := "urn:cerebro:writer:archetype_library_note:WriterInternal/Archetype:repository-commit-learning"
	if entity := graphStore.entities[findingURN]; entity == nil || entity.EntityType != "archetype.finding" {
		t.Fatalf("projected finding entity = %#v, want archetype.finding", entity)
	}
	if entity := graphStore.entities[scanURN]; entity == nil || entity.EntityType != "archetype.scan" {
		t.Fatalf("projected scan entity = %#v, want archetype.scan", entity)
	}
	if entity := graphStore.entities[noteURN]; entity == nil || entity.EntityType != "archetype.library_note" {
		t.Fatalf("projected library note entity = %#v, want archetype.library_note", entity)
	}
	if entity := graphStore.entities[repoURN]; entity == nil || entity.EntityType != "github.code.repository" {
		t.Fatalf("projected repository entity = %#v, want github.code.repository", entity)
	}
	assertBootstrapProjectedLink(t, graphStore, repoURN, "has_evidence", scanURN)
	assertBootstrapProjectedLink(t, graphStore, repoURN, "has_evidence", findingURN)
	assertBootstrapProjectedLink(t, graphStore, repoURN, "has_evidence", noteURN)
	assertBootstrapProjectedLink(t, graphStore, repoURN, "has_context", noteURN)
	assertBootstrapProjectedLink(t, graphStore, findingURN, "belongs_to", scanURN)
	assertBootstrapProjectedLink(t, graphStore, findingURN, "affects", repoURN)
	assertBootstrapProjectedLink(t, graphStore, noteURN, "belongs_to", scanURN)

	neighborhoodResp, err := server.Client().Get(server.URL + "/platform/graph/neighborhood?root_urn=" + url.QueryEscape(findingURN) + "&limit=10")
	if err != nil {
		t.Fatalf("GET /platform/graph/neighborhood error = %v", err)
	}
	defer func() { _ = neighborhoodResp.Body.Close() }()
	if neighborhoodResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(neighborhoodResp.Body)
		t.Fatalf("graph neighborhood status = %d, want 200: %s", neighborhoodResp.StatusCode, body)
	}
	if graphStore.neighborhoodRootURN != findingURN {
		t.Fatalf("graph neighborhood root = %q, want %q", graphStore.neighborhoodRootURN, findingURN)
	}
}

func TestGraphIngestResolvesConnectorCredentialRuntimeConfig(t *testing.T) {
	source := &bootstrapTokenSource{id: "bootstrap_token"}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &connectorTestStore{stubRuntimeStore: &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{}}}
	vault, err := connectorcredentials.NewVault(store, "test-connector-vault-key")
	if err != nil {
		t.Fatalf("NewVault() error = %v", err)
	}
	record, err := vault.Put(context.Background(), connectorcredentials.PlainCredential{
		TenantID:  "writer",
		SourceID:  "bootstrap_token",
		RuntimeID: "runtime-token",
		Fields: map[string]string{
			"token": "secret-token",
		},
	})
	if err != nil {
		t.Fatalf("Put() credential error = %v", err)
	}
	store.runtimes["runtime-token"] = &cerebrov1.SourceRuntime{
		Id:       "runtime-token",
		SourceId: "bootstrap_token",
		TenantId: "writer",
		Config: map[string]string{
			"token": connectorcredentials.Reference(record.ID, "token"),
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		ConnectorCredentials: config.ConnectorCredentialConfig{
			Key: "test-connector-vault-key",
		},
	}, Dependencies{
		StateStore: store,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/source-runtimes/runtime-token/graph-ingest-runs?page_limit=1", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("graph ingest status = %d, want 200", resp.StatusCode)
	}
	if source.readToken != "secret-token" {
		t.Fatalf("source read token = %q, want decrypted credential", source.readToken)
	}
	if got := store.runtimes["runtime-token"].GetConfig()["token"]; strings.Contains(got, "secret-token") {
		t.Fatalf("runtime config leaked secret: %q", got)
	}
}

func TestFindingRuleEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/finding-rules")
	if err != nil {
		t.Fatalf("GET /finding-rules error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /finding-rules response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /finding-rules response: %v", err)
	}
	rulesPayload, ok := payload["rules"].([]any)
	if !ok || len(rulesPayload) < 10 {
		t.Fatalf("/finding-rules payload = %#v, want at least 10 rules", payload["rules"])
	}
	ruleIDs := map[string]struct{}{}
	for _, rawRule := range rulesPayload {
		rulePayload, ok := rawRule.(map[string]any)
		if !ok {
			t.Fatalf("/finding-rules rule entry = %#v, want object", rawRule)
		}
		ruleID, ok := rulePayload["id"].(string)
		if !ok {
			t.Fatalf("/finding-rules rule id = %#v, want string", rulePayload["id"])
		}
		ruleIDs[ruleID] = struct{}{}
	}
	for _, ruleID := range []string{"github-dependabot-open-alert", "github-secret-scanning-alert-created", "identity-okta-policy-rule-lifecycle-tampering"} {
		if _, ok := ruleIDs[ruleID]; !ok {
			t.Fatalf("/finding-rules missing %q in %#v", ruleID, ruleIDs)
		}
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listResp, err := client.ListFindingRules(context.Background(), connect.NewRequest(&cerebrov1.ListFindingRulesRequest{}))
	if err != nil {
		t.Fatalf("ListFindingRules() error = %v", err)
	}
	if got := len(listResp.Msg.GetRules()); got < 10 {
		t.Fatalf("len(ListFindingRules().Rules) = %d, want at least 10", got)
	}
	connectRuleIDs := map[string]struct{}{}
	for _, rule := range listResp.Msg.GetRules() {
		connectRuleIDs[rule.GetId()] = struct{}{}
	}
	for _, ruleID := range []string{"github-dependabot-open-alert", "github-secret-scanning-alert-created", "identity-okta-policy-rule-lifecycle-tampering"} {
		if _, ok := connectRuleIDs[ruleID]; !ok {
			t.Fatalf("ListFindingRules() missing %q in %#v", ruleID, connectRuleIDs)
		}
	}
}

func TestBootstrapServiceFindingCoreServicePreparesRuntimeIndexReplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service func(*bootstrapService) *findings.Service
	}{
		{name: "core", service: (*bootstrapService).findingCoreService},
		{name: "candidate", service: (*bootstrapService).findingCandidateService},
		{name: "workflow", service: (*bootstrapService).findingWorkflowService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appendLog := &recordingAppendLog{
				replayEvents: []*cerebrov1.EventEnvelope{
					findingPolicyRuleTestEvent("okta-policy-rule-inactive", "INACTIVE"),
				},
				indexScans:   []ports.RuntimeIndexScan{{Watermark: 1, CaughtUp: true}},
				enforceIndex: true,
			}
			store := &stubRuntimeStore{
				runtimes: map[string]*cerebrov1.SourceRuntime{
					"writer-okta-policy-rule": {
						Id:       "writer-okta-policy-rule",
						SourceId: "okta",
						TenantId: "writer",
						Config:   map[string]string{"family": "policy_rule"},
					},
				},
				claims:                map[string]*ports.ClaimRecord{},
				findings:              map[string]*ports.FindingRecord{},
				findingEvidence:       map[string]*cerebrov1.FindingEvidence{},
				findingEvaluationRuns: map[string]*cerebrov1.FindingEvaluationRun{},
			}
			service := tc.service(&bootstrapService{
				cfg: config.Config{AppendLog: config.AppendLogConfig{JetStreamRuntimeIndexEnabled: true}},
				deps: Dependencies{
					AppendLog:  appendLog,
					StateStore: store,
				},
			})

			_, err := service.EvaluateSourceRuntimeRules(context.Background(), findings.EvaluateRulesRequest{
				RuntimeID: "writer-okta-policy-rule",
				RuleIDs:   []string{"identity-okta-policy-rule-lifecycle-tampering"},
			})
			if err != nil {
				t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
			}
			if appendLog.indexScanCalls != 1 {
				t.Fatalf("runtime index scan calls = %d, want 1", appendLog.indexScanCalls)
			}
			if got := store.runtimeIndexWatermarks; len(got) != 1 || got[0] != 1 {
				t.Fatalf("runtime index watermarks = %#v, want [1]", got)
			}
			if len(appendLog.replayRequests) != 1 {
				t.Fatalf("replay requests = %d, want 1", len(appendLog.replayRequests))
			}
			if !appendLog.replayRequests[0].RequireRuntimeIndex {
				t.Fatal("replay request RequireRuntimeIndex = false, want true")
			}
		})
	}
}

func TestBootstrapServiceFindingCoreServiceAllowsReplayWhenRuntimeIndexDisabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service func(*bootstrapService) *findings.Service
	}{
		{name: "core", service: (*bootstrapService).findingCoreService},
		{name: "candidate", service: (*bootstrapService).findingCandidateService},
		{name: "workflow", service: (*bootstrapService).findingWorkflowService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appendLog := &recordingAppendLog{
				replayEvents: []*cerebrov1.EventEnvelope{
					findingPolicyRuleTestEvent("okta-policy-rule-inactive", "INACTIVE"),
				},
				enforceIndex: true,
			}
			store := &stubRuntimeStore{
				runtimes: map[string]*cerebrov1.SourceRuntime{
					"writer-okta-policy-rule": {
						Id:       "writer-okta-policy-rule",
						SourceId: "okta",
						TenantId: "writer",
						Config:   map[string]string{"family": "policy_rule"},
					},
				},
				claims:                map[string]*ports.ClaimRecord{},
				findings:              map[string]*ports.FindingRecord{},
				findingEvidence:       map[string]*cerebrov1.FindingEvidence{},
				findingEvaluationRuns: map[string]*cerebrov1.FindingEvaluationRun{},
			}
			service := tc.service(&bootstrapService{
				cfg: config.Config{AppendLog: config.AppendLogConfig{JetStreamRuntimeIndexEnabled: false}},
				deps: Dependencies{
					AppendLog:  appendLog,
					StateStore: store,
				},
			})

			_, err := service.EvaluateSourceRuntimeRules(context.Background(), findings.EvaluateRulesRequest{
				RuntimeID: "writer-okta-policy-rule",
				RuleIDs:   []string{"identity-okta-policy-rule-lifecycle-tampering"},
			})
			if err != nil {
				t.Fatalf("EvaluateSourceRuntimeRules() error = %v", err)
			}
			if appendLog.indexScanCalls != 0 {
				t.Fatalf("runtime index scan calls = %d, want 0 when disabled", appendLog.indexScanCalls)
			}
			if len(appendLog.replayRequests) != 1 {
				t.Fatalf("replay requests = %d, want 1", len(appendLog.replayRequests))
			}
			if appendLog.replayRequests[0].RequireRuntimeIndex {
				t.Fatal("replay request RequireRuntimeIndex = true, want false when runtime index is disabled")
			}
		})
	}
}

func TestFindingEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{
		replayEvents: []*cerebrov1.EventEnvelope{
			findingPolicyRuleTestEvent("okta-policy-rule-active", "ACTIVE"),
			findingPolicyRuleTestEvent("okta-policy-rule-inactive", "INACTIVE"),
		},
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"family": "policy_rule", "token": "super-secret"},
			},
		},
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-policy-rule",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1",
				Predicate:     "status",
				ObjectValue:   "INACTIVE",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "okta-policy-rule-inactive",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	evaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-policy-rule/findings/evaluate?event_limit=2&rule_id=identity-okta-policy-rule-lifecycle-tampering", nil)
	if err != nil {
		t.Fatalf("new evaluate findings request: %v", err)
	}
	evaluateResp, err := server.Client().Do(evaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := evaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close evaluate findings response body: %v", closeErr)
		}
	}()
	var evaluatePayload map[string]any
	if err := json.NewDecoder(evaluateResp.Body).Decode(&evaluatePayload); err != nil {
		t.Fatalf("decode evaluate findings response: %v", err)
	}
	if got := evaluatePayload["events_evaluated"]; got != float64(2) {
		t.Fatalf("evaluate findings events_evaluated = %#v, want 2", got)
	}
	if got := evaluatePayload["findings_upserted"]; got != float64(1) {
		t.Fatalf("evaluate findings findings_upserted = %#v, want 1", got)
	}
	evaluateRuntime, ok := evaluatePayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate runtime payload = %#v, want object", evaluatePayload["runtime"])
	}
	evaluateConfig, ok := evaluateRuntime["config"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate runtime config = %#v, want object", evaluateRuntime["config"])
	}
	if got := evaluateConfig["token"]; got != "[redacted]" {
		t.Fatalf("evaluate runtime config token = %#v, want [redacted]", got)
	}
	findingsPayload, ok := evaluatePayload["findings"].([]any)
	if !ok || len(findingsPayload) != 1 {
		t.Fatalf("evaluate findings payload = %#v, want 1 entry", evaluatePayload["findings"])
	}
	findingPayload, ok := findingsPayload[0].(map[string]any)
	if !ok {
		t.Fatalf("evaluate finding payload = %#v, want object", findingsPayload[0])
	}
	if got := findingPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := findingPayload["summary"]; got != "Okta policy rule Require MFA is INACTIVE" {
		t.Fatalf("evaluate finding summary = %#v, want current-state summary", got)
	}
	if got := findingPayload["policy_id"]; got != "pol-1" {
		t.Fatalf("evaluate finding policy_id = %#v, want pol-1", got)
	}
	if got := findingPayload["policy_name"]; got != "Require MFA" {
		t.Fatalf("evaluate finding policy_name = %#v, want Require MFA", got)
	}
	if got := findingPayload["check_id"]; got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("evaluate finding check_id = %#v, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := findingPayload["check_name"]; got != "Okta Policy Rule Lifecycle Tampering (30 days)" {
		t.Fatalf("evaluate finding check_name = %#v, want check name", got)
	}
	controlRefs, ok := findingPayload["control_refs"].([]any)
	if !ok || len(controlRefs) != 2 {
		t.Fatalf("evaluate finding control_refs = %#v, want 2 entries", findingPayload["control_refs"])
	}
	runPayload, ok := evaluatePayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate run payload = %#v, want object", evaluatePayload["run"])
	}
	runID, ok := runPayload["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("evaluate run id = %#v, want non-empty string", runPayload["id"])
	}
	if got := runPayload["status"]; got != "completed" {
		t.Fatalf("evaluate run status = %#v, want completed", got)
	}
	if got := runPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate run rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runPayload["events_processed"]; got != float64(2) {
		t.Fatalf("evaluate run events_processed = %#v, want 2", got)
	}
	if got := runPayload["events_matched"]; got != float64(1) {
		t.Fatalf("evaluate run events_matched = %#v, want 1", got)
	}
	if got := runPayload["findings_emitted"]; got != float64(1) {
		t.Fatalf("evaluate run findings_emitted = %#v, want 1", got)
	}
	evidencePayload, ok := evaluatePayload["evidence"].([]any)
	if !ok || len(evidencePayload) != 1 {
		t.Fatalf("evaluate evidence payload = %#v, want 1 entry", evaluatePayload["evidence"])
	}
	evidenceEntry, ok := evidencePayload[0].(map[string]any)
	if !ok {
		t.Fatalf("evaluate evidence entry = %#v, want object", evidencePayload[0])
	}
	evidenceID, ok := evidenceEntry["id"].(string)
	if !ok || evidenceID == "" {
		t.Fatalf("evaluate evidence id = %#v, want non-empty string", evidenceEntry["id"])
	}
	if got := evidenceEntry["finding_id"]; got != findingPayload["id"] {
		t.Fatalf("evaluate evidence finding_id = %#v, want finding id %#v", got, findingPayload["id"])
	}
	eventIDs, ok := evidenceEntry["event_ids"].([]any)
	if !ok || len(eventIDs) != 1 || eventIDs[0] != "okta-policy-rule-inactive" {
		t.Fatalf("evaluate evidence event_ids = %#v, want [okta-policy-rule-inactive]", evidenceEntry["event_ids"])
	}
	evidenceAttributes, ok := evidenceEntry["attributes"].(map[string]any)
	if !ok || evidenceAttributes["policy_rule_status"] != "inactive" {
		t.Fatalf("evaluate evidence attributes = %#v, want policy_rule_status snapshot", evidenceEntry["attributes"])
	}
	if _, ok := evidenceEntry["last_observed_at"].(string); !ok {
		t.Fatalf("evaluate evidence last_observed_at = %#v, want timestamp", evidenceEntry["last_observed_at"])
	}
	claimIDs, ok := evidenceEntry["claim_ids"].([]any)
	if !ok || len(claimIDs) != 1 || claimIDs[0] != "claim-1" {
		t.Fatalf("evaluate evidence claim_ids = %#v, want [claim-1]", evidenceEntry["claim_ids"])
	}
	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-policy-rule/findings?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=open&event_id=okta-policy-rule-inactive&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/findings error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list findings response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list findings response: %v", err)
	}
	listedFindings, ok := listPayload["findings"].([]any)
	if !ok || len(listedFindings) != 1 {
		t.Fatalf("list findings payload = %#v, want 1 entry", listPayload["findings"])
	}
	listedFinding, ok := listedFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("list findings entry = %#v, want object", listedFindings[0])
	}
	if got := listedFinding["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("list finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	runListResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-policy-rule/finding-evaluation-runs?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=completed&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-evaluation-runs error = %v", err)
	}
	defer func() {
		if closeErr := runListResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list evaluation runs response body: %v", closeErr)
		}
	}()
	var runListPayload map[string]any
	if err := json.NewDecoder(runListResp.Body).Decode(&runListPayload); err != nil {
		t.Fatalf("decode list evaluation runs response: %v", err)
	}
	runEntries, ok := runListPayload["runs"].([]any)
	if !ok || len(runEntries) != 1 {
		t.Fatalf("list evaluation runs payload = %#v, want 1 entry", runListPayload["runs"])
	}
	runEntry, ok := runEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("list evaluation run entry = %#v, want object", runEntries[0])
	}
	if got := runEntry["id"]; got != runID {
		t.Fatalf("list evaluation run id = %#v, want %q", got, runID)
	}
	if got := runEntry["events_processed"]; got != float64(2) {
		t.Fatalf("list evaluation run events_processed = %#v, want 2", got)
	}
	if got := runEntry["events_matched"]; got != float64(1) {
		t.Fatalf("list evaluation run events_matched = %#v, want 1", got)
	}
	if got := runEntry["findings_emitted"]; got != float64(1) {
		t.Fatalf("list evaluation run findings_emitted = %#v, want 1", got)
	}
	if got, present := runEntry["graph_rule"]; !present || got != false {
		t.Fatalf("list evaluation run graph_rule = %#v (present=%t), want false present (zero-value scalars must surface for operator triage)", got, present)
	}
	if got, present := runEntry["graph_rows_read"]; !present || got != float64(0) {
		t.Fatalf("list evaluation run graph_rows_read = %#v (present=%t), want 0 present", got, present)
	}
	evidenceListResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-policy-rule/finding-evidence?finding_id=" + findingPayload["id"].(string) + "&run_id=" + runID + "&claim_id=claim-1&event_id=okta-policy-rule-inactive&graph_root_urn=urn:cerebro:writer:okta_policy_rule:pol-1:rul-1&graph_path_urn=urn:cerebro:writer:okta_user:00u2&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-evidence error = %v", err)
	}
	defer func() {
		if closeErr := evidenceListResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list finding evidence response body: %v", closeErr)
		}
	}()
	var evidenceListPayload map[string]any
	if err := json.NewDecoder(evidenceListResp.Body).Decode(&evidenceListPayload); err != nil {
		t.Fatalf("decode list finding evidence response: %v", err)
	}
	evidenceEntries, ok := evidenceListPayload["evidence"].([]any)
	if !ok || len(evidenceEntries) != 1 {
		t.Fatalf("list finding evidence payload = %#v, want 1 entry", evidenceListPayload["evidence"])
	}
	listedEvidence, ok := evidenceEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("list finding evidence entry = %#v, want object", evidenceEntries[0])
	}
	if got := listedEvidence["id"]; got != evidenceID {
		t.Fatalf("list finding evidence id = %#v, want %q", got, evidenceID)
	}
	if got := runtimeStore.findingEvidenceListRequest.GraphPathURN; got != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("runtimeStore.findingEvidenceListRequest.GraphPathURN = %q, want graph path urn", got)
	}
	getEvidenceResp, err := server.Client().Get(server.URL + "/finding-evidence/" + evidenceID)
	if err != nil {
		t.Fatalf("GET /finding-evidence/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getEvidenceResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get finding evidence response body: %v", closeErr)
		}
	}()
	var getEvidencePayload map[string]any
	if err := json.NewDecoder(getEvidenceResp.Body).Decode(&getEvidencePayload); err != nil {
		t.Fatalf("decode get finding evidence response: %v", err)
	}
	getEvidenceBody, ok := getEvidencePayload["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("get finding evidence payload = %#v, want object", getEvidencePayload["evidence"])
	}
	if got := getEvidenceBody["id"]; got != evidenceID {
		t.Fatalf("get finding evidence id = %#v, want %q", got, evidenceID)
	}
	getRunResp, err := server.Client().Get(server.URL + "/finding-evaluation-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /finding-evaluation-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getRunResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get evaluation run response body: %v", closeErr)
		}
	}()
	var getRunPayload map[string]any
	if err := json.NewDecoder(getRunResp.Body).Decode(&getRunPayload); err != nil {
		t.Fatalf("decode get evaluation run response: %v", err)
	}
	getRunBody, ok := getRunPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get evaluation run payload = %#v, want object", getRunPayload["run"])
	}
	if got := getRunBody["id"]; got != runID {
		t.Fatalf("get evaluation run id = %#v, want %q", got, runID)
	}
	if got, present := getRunBody["graph_rule"]; !present || got != false {
		t.Fatalf("get evaluation run graph_rule = %#v (present=%t), want false present (operator triage requires explicit zeros)", got, present)
	}
	if got, present := getRunBody["graph_rows_read"]; !present || got != float64(0) {
		t.Fatalf("get evaluation run graph_rows_read = %#v (present=%t), want 0 present", got, present)
	}
	missingRuleResp, err := server.Client().Post(server.URL+"/source-runtimes/writer-okta-policy-rule/findings/evaluate?rule_id=does-not-exist", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate unknown rule error = %v", err)
	}
	defer func() {
		if closeErr := missingRuleResp.Body.Close(); closeErr != nil {
			t.Fatalf("close unknown rule response body: %v", closeErr)
		}
	}()
	if got := missingRuleResp.StatusCode; got != http.StatusNotFound {
		t.Fatalf("unknown rule status = %d, want %d", got, http.StatusNotFound)
	}
	batchEvaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-policy-rule/finding-rules/evaluate?event_limit=2", nil)
	if err != nil {
		t.Fatalf("new batch evaluate request: %v", err)
	}
	batchEvaluateResp, err := server.Client().Do(batchEvaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/finding-rules/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := batchEvaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close batch evaluate response body: %v", closeErr)
		}
	}()
	var batchEvaluatePayload map[string]any
	if err := json.NewDecoder(batchEvaluateResp.Body).Decode(&batchEvaluatePayload); err != nil {
		t.Fatalf("decode batch evaluate response: %v", err)
	}
	if got := batchEvaluatePayload["events_evaluated"]; got != float64(2) {
		t.Fatalf("batch evaluate events_evaluated = %#v, want 2", got)
	}
	batchRuntime, ok := batchEvaluatePayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("batch runtime payload = %#v, want object", batchEvaluatePayload["runtime"])
	}
	batchConfig, ok := batchRuntime["config"].(map[string]any)
	if !ok {
		t.Fatalf("batch runtime config = %#v, want object", batchRuntime["config"])
	}
	if got := batchConfig["token"]; got != "[redacted]" {
		t.Fatalf("batch runtime config token = %#v, want [redacted]", got)
	}
	batchEvaluations, ok := batchEvaluatePayload["evaluations"].([]any)
	if !ok || len(batchEvaluations) == 0 {
		t.Fatalf("batch evaluate payload = %#v, want evaluations", batchEvaluatePayload["evaluations"])
	}
	var batchEvaluation map[string]any
	for _, candidate := range batchEvaluations {
		entry, ok := candidate.(map[string]any)
		if !ok {
			t.Fatalf("batch evaluation entry = %#v, want object", candidate)
		}
		batchRule, ok := entry["rule"].(map[string]any)
		if ok && batchRule["id"] == "identity-okta-policy-rule-lifecycle-tampering" {
			batchEvaluation = entry
			break
		}
	}
	if batchEvaluation == nil {
		t.Fatalf("batch evaluations = %#v, want lifecycle tampering rule", batchEvaluations)
	}
	batchEvidence, ok := batchEvaluation["evidence"].([]any)
	if !ok || len(batchEvidence) != 1 {
		t.Fatalf("batch evaluation evidence = %#v, want 1 entry", batchEvaluation["evidence"])
	}

	batchBody, err := protojson.Marshal(&cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{
		RuleIds: []string{"identity-okta-policy-rule-lifecycle-tampering"},
	})
	if err != nil {
		t.Fatalf("marshal batch evaluate body: %v", err)
	}
	batchBodyReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-policy-rule/finding-rules/evaluate?event_limit=2", bytes.NewReader(batchBody))
	if err != nil {
		t.Fatalf("new body batch evaluate request: %v", err)
	}
	batchBodyReq.Header.Set("Content-Type", "application/json")
	batchBodyResp, err := server.Client().Do(batchBodyReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/finding-rules/evaluate body error = %v", err)
	}
	defer func() {
		if closeErr := batchBodyResp.Body.Close(); closeErr != nil {
			t.Fatalf("close body batch evaluate response body: %v", closeErr)
		}
	}()
	var batchBodyPayload map[string]any
	if err := json.NewDecoder(batchBodyResp.Body).Decode(&batchBodyPayload); err != nil {
		t.Fatalf("decode body batch evaluate response: %v", err)
	}
	batchBodyEvaluations, ok := batchBodyPayload["evaluations"].([]any)
	if !ok || len(batchBodyEvaluations) != 1 {
		t.Fatalf("body batch evaluations = %#v, want exactly one selected rule", batchBodyPayload["evaluations"])
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	evaluateFindingsResp, err := client.EvaluateSourceRuntimeFindings(context.Background(), connect.NewRequest(&cerebrov1.EvaluateSourceRuntimeFindingsRequest{
		Id:         "writer-okta-policy-rule",
		RuleId:     "identity-okta-policy-rule-lifecycle-tampering",
		EventLimit: 5,
	}))
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeFindings() error = %v", err)
	}
	if got := evaluateFindingsResp.Msg.GetEventsEvaluated(); got != 2 {
		t.Fatalf("EvaluateSourceRuntimeFindings events_evaluated = %d, want 2", got)
	}
	if got := evaluateFindingsResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("EvaluateSourceRuntimeFindings runtime token = %q, want [redacted]", got)
	}
	if got := evaluateFindingsResp.Msg.GetFindingsUpserted(); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeFindings findings_upserted = %d, want 1", got)
	}
	if len(evaluateFindingsResp.Msg.GetFindings()) != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindings.Findings) = %d, want 1", len(evaluateFindingsResp.Msg.GetFindings()))
	}
	if got := evaluateFindingsResp.Msg.GetRule().GetId(); got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("EvaluateSourceRuntimeFindings rule id = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := evaluateFindingsResp.Msg.GetRun().GetId(); got == "" {
		t.Fatal("EvaluateSourceRuntimeFindings run id = empty, want non-empty")
	}
	if got := len(evaluateFindingsResp.Msg.GetEvidence()); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindings.Evidence) = %d, want 1", got)
	}
	if got := evaluateFindingsResp.Msg.GetEvidence()[0].GetClaimIds(); len(got) != 1 || got[0] != "claim-1" {
		t.Fatalf("EvaluateSourceRuntimeFindings evidence claim ids = %#v, want [claim-1]", got)
	}
	evaluatedFindingID := evaluateFindingsResp.Msg.GetFindings()[0].GetId()
	storedFinding, ok := runtimeStore.findings[evaluatedFindingID]
	if !ok {
		t.Fatalf("stored finding %q missing", evaluatedFindingID)
	}
	if storedFinding.Attributes == nil {
		storedFinding.Attributes = map[string]string{}
	}
	storedFinding.Attributes["api_key"] = "finding-secret"
	storedFinding.Attributes["environment"] = "prod"
	evaluatedEvidenceID := evaluateFindingsResp.Msg.GetEvidence()[0].GetId()
	storedEvidence, ok := runtimeStore.findingEvidence[evaluatedEvidenceID]
	if !ok {
		t.Fatalf("stored evidence %q missing", evaluatedEvidenceID)
	}
	seedFindingEvidenceSecrets := func() {
		for _, evidence := range runtimeStore.findingEvidence {
			if evidence.Attributes == nil {
				evidence.Attributes = map[string]string{}
			}
			evidence.Attributes["token"] = "evidence-secret"
			evidence.Attributes["policy_rule_status"] = "inactive"
			evidence.GraphRows = []*cerebrov1.GraphEvidenceRow{{
				Label:      "policy-rule",
				Attributes: map[string]string{"private_key": "row-secret", "resource_id": "rul-1"},
				Paths: []*cerebrov1.GraphEvidencePath{{
					Attributes: map[string]string{"password": "path-secret", "relation": "member"},
				}},
			}}
		}
	}
	seedFindingEvidenceSecrets()
	if got := storedEvidence.GetAttributes()["token"]; got != "evidence-secret" {
		t.Fatalf("stored evaluated evidence token = %q, want original value", got)
	}
	listFindingsResp, err := client.ListFindings(context.Background(), connect.NewRequest(&cerebrov1.ListFindingsRequest{
		RuntimeId:   "writer-okta-policy-rule",
		RuleId:      "identity-okta-policy-rule-lifecycle-tampering",
		Severity:    "HIGH",
		Status:      cerebrov1.FindingStatus_FINDING_STATUS_OPEN,
		PolicyId:    "pol-1",
		ResourceUrn: "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1",
		EventId:     "okta-policy-rule-inactive",
		Limit:       1,
	}))
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}
	if got := len(listFindingsResp.Msg.GetFindings()); got != 1 {
		t.Fatalf("len(ListFindings().Findings) = %d, want 1", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetId(); got == "" {
		t.Fatal("ListFindings().Findings[0].ID = empty, want non-empty")
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetPolicyId(); got != "pol-1" {
		t.Fatalf("ListFindings().Findings[0].PolicyId = %q, want pol-1", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetCheckId(); got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("ListFindings().Findings[0].CheckId = %q, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := len(listFindingsResp.Msg.GetFindings()[0].GetControlRefs()); got != 2 {
		t.Fatalf("len(ListFindings().Findings[0].ControlRefs) = %d, want 2", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("ListFindings().Findings[0].Attributes[api_key] = %q, want [redacted]", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetAttributes()["environment"]; got != "prod" {
		t.Fatalf("ListFindings().Findings[0].Attributes[environment] = %q, want prod", got)
	}
	if got := runtimeStore.findings[evaluatedFindingID].Attributes["api_key"]; got != "finding-secret" {
		t.Fatalf("stored finding api_key = %q, want original value", got)
	}
	if got := runtimeStore.findingListRequest.TenantID; got != "writer" {
		t.Fatalf("runtimeStore.findingListRequest.TenantID = %q, want writer", got)
	}
	if got := runtimeStore.findingListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingListRequest.ResourceURN; got != "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1" {
		t.Fatalf("runtimeStore.findingListRequest.ResourceURN = %q, want policy rule urn", got)
	}
	if got := runtimeStore.findingListRequest.EventID; got != "okta-policy-rule-inactive" {
		t.Fatalf("runtimeStore.findingListRequest.EventID = %q, want okta-policy-rule-inactive", got)
	}
	if got := runtimeStore.findingListRequest.PolicyID; got != "pol-1" {
		t.Fatalf("runtimeStore.findingListRequest.PolicyID = %q, want pol-1", got)
	}
	listRunsResp, err := client.ListFindingEvaluationRuns(context.Background(), connect.NewRequest(&cerebrov1.ListFindingEvaluationRunsRequest{
		RuntimeId: "writer-okta-policy-rule",
		RuleId:    "identity-okta-policy-rule-lifecycle-tampering",
		Status:    "completed",
		Limit:     1,
	}))
	if err != nil {
		t.Fatalf("ListFindingEvaluationRuns() error = %v", err)
	}
	if got := len(listRunsResp.Msg.GetRuns()); got != 1 {
		t.Fatalf("len(ListFindingEvaluationRuns().Runs) = %d, want 1", got)
	}
	evaluateFindingRulesResp, err := client.EvaluateSourceRuntimeFindingRules(context.Background(), connect.NewRequest(&cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{
		Id:         "writer-okta-policy-rule",
		EventLimit: 2,
	}))
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeFindingRules() error = %v", err)
	}
	if got := evaluateFindingRulesResp.Msg.GetEventsEvaluated(); got != 2 {
		t.Fatalf("EvaluateSourceRuntimeFindingRules events_evaluated = %d, want 2", got)
	}
	if got := evaluateFindingRulesResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("EvaluateSourceRuntimeFindingRules runtime token = %q, want [redacted]", got)
	}
	var lifecycleEvaluation *cerebrov1.FindingRuleEvaluation
	for _, evaluation := range evaluateFindingRulesResp.Msg.GetEvaluations() {
		if evaluation.GetRule().GetId() == "identity-okta-policy-rule-lifecycle-tampering" {
			lifecycleEvaluation = evaluation
			break
		}
	}
	if lifecycleEvaluation == nil {
		t.Fatalf("EvaluateSourceRuntimeFindingRules evaluations = %v, want lifecycle tampering rule", evaluateFindingRulesResp.Msg.GetEvaluations())
	}
	if got := len(lifecycleEvaluation.GetEvidence()); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindingRules().Evaluations[0].Evidence) = %d, want 1", got)
	}
	seedFindingEvidenceSecrets()
	listEvidenceResp, err := client.ListFindingEvidence(context.Background(), connect.NewRequest(&cerebrov1.ListFindingEvidenceRequest{
		RuntimeId:    "writer-okta-policy-rule",
		FindingId:    evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		RunId:        lifecycleEvaluation.GetRun().GetId(),
		RuleId:       "identity-okta-policy-rule-lifecycle-tampering",
		ClaimId:      "claim-1",
		EventId:      "okta-policy-rule-inactive",
		GraphRootUrn: "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1",
		Limit:        1,
	}))
	if err != nil {
		t.Fatalf("ListFindingEvidence() error = %v", err)
	}
	if got := len(listEvidenceResp.Msg.GetEvidence()); got != 1 {
		t.Fatalf("len(ListFindingEvidence().Evidence) = %d, want 1", got)
	}
	listedConnectEvidence := listEvidenceResp.Msg.GetEvidence()[0]
	if got := listedConnectEvidence.GetAttributes()["token"]; got != "[redacted]" {
		t.Fatalf("ListFindingEvidence().Evidence[0].Attributes[token] = %q, want [redacted]", got)
	}
	if got := listedConnectEvidence.GetAttributes()["policy_rule_status"]; got != "inactive" {
		t.Fatalf("ListFindingEvidence().Evidence[0].Attributes[policy_rule_status] = %q, want inactive", got)
	}
	if got := listedConnectEvidence.GetGraphRows()[0].GetAttributes()["private_key"]; got != "[redacted]" {
		t.Fatalf("ListFindingEvidence().Evidence[0].GraphRows[0].Attributes[private_key] = %q, want [redacted]", got)
	}
	if got := listedConnectEvidence.GetGraphRows()[0].GetPaths()[0].GetAttributes()["password"]; got != "[redacted]" {
		t.Fatalf("ListFindingEvidence().Evidence[0].GraphRows[0].Paths[0].Attributes[password] = %q, want [redacted]", got)
	}
	if got := runtimeStore.findingEvidence[listedConnectEvidence.GetId()].GetAttributes()["token"]; got != "evidence-secret" {
		t.Fatalf("stored evidence token = %q, want original value", got)
	}
	getFindingEvidenceResp, err := client.GetFindingEvidence(context.Background(), connect.NewRequest(&cerebrov1.GetFindingEvidenceRequest{
		Id: listEvidenceResp.Msg.GetEvidence()[0].GetId(),
	}))
	if err != nil {
		t.Fatalf("GetFindingEvidence() error = %v", err)
	}
	if got := getFindingEvidenceResp.Msg.GetEvidence().GetId(); got != listEvidenceResp.Msg.GetEvidence()[0].GetId() {
		t.Fatalf("GetFindingEvidence().Evidence.Id = %q, want %q", got, listEvidenceResp.Msg.GetEvidence()[0].GetId())
	}
	if got := getFindingEvidenceResp.Msg.GetEvidence().GetAttributes()["token"]; got != "[redacted]" {
		t.Fatalf("GetFindingEvidence().Evidence.Attributes[token] = %q, want [redacted]", got)
	}
	getEvaluationRunResp, err := client.GetFindingEvaluationRun(context.Background(), connect.NewRequest(&cerebrov1.GetFindingEvaluationRunRequest{
		Id: evaluateFindingsResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetFindingEvaluationRun() error = %v", err)
	}
	if got := getEvaluationRunResp.Msg.GetRun().GetId(); got != evaluateFindingsResp.Msg.GetRun().GetId() {
		t.Fatalf("GetFindingEvaluationRun().Run.Id = %q, want %q", got, evaluateFindingsResp.Msg.GetRun().GetId())
	}
	assignBody, err := protojson.Marshal(&cerebrov1.AssignFindingRequest{Assignee: "secops"})
	if err != nil {
		t.Fatalf("marshal assign finding body: %v", err)
	}
	assignReq, err := http.NewRequest(http.MethodPut, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/assign", bytes.NewReader(assignBody))
	if err != nil {
		t.Fatalf("new assign finding request: %v", err)
	}
	assignReq.Header.Set("Content-Type", "application/json")
	assignResp, err := server.Client().Do(assignReq)
	if err != nil {
		t.Fatalf("PUT /findings/{id}/assign error = %v", err)
	}
	defer func() {
		if closeErr := assignResp.Body.Close(); closeErr != nil {
			t.Fatalf("close assign finding response body: %v", closeErr)
		}
	}()
	var assignPayload map[string]any
	if err := json.NewDecoder(assignResp.Body).Decode(&assignPayload); err != nil {
		t.Fatalf("decode assign finding response: %v", err)
	}
	assignFinding, ok := assignPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("assign finding payload = %#v, want object", assignPayload["finding"])
	}
	if got := assignFinding["assignee"]; got != "secops" {
		t.Fatalf("assign finding assignee = %#v, want secops", got)
	}
	assignAttributes, ok := assignFinding["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("assign finding attributes = %#v, want object", assignFinding["attributes"])
	}
	if got := assignAttributes["api_key"]; got != "[redacted]" {
		t.Fatalf("assign finding api_key = %#v, want [redacted]", got)
	}
	httpDueAt := "2026-05-01T12:00:00Z"
	dueBody, err := protojson.Marshal(&cerebrov1.SetFindingDueDateRequest{DueAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatalf("marshal due date body: %v", err)
	}
	dueReq, err := http.NewRequest(http.MethodPut, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/due", bytes.NewReader(dueBody))
	if err != nil {
		t.Fatalf("new due date request: %v", err)
	}
	dueReq.Header.Set("Content-Type", "application/json")
	dueResp, err := server.Client().Do(dueReq)
	if err != nil {
		t.Fatalf("PUT /findings/{id}/due error = %v", err)
	}
	defer func() {
		if closeErr := dueResp.Body.Close(); closeErr != nil {
			t.Fatalf("close due date response body: %v", closeErr)
		}
	}()
	var duePayload map[string]any
	if err := json.NewDecoder(dueResp.Body).Decode(&duePayload); err != nil {
		t.Fatalf("decode due date response: %v", err)
	}
	dueFinding, ok := duePayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("due finding payload = %#v, want object", duePayload["finding"])
	}
	if got := dueFinding["due_at"]; got != httpDueAt {
		t.Fatalf("due finding due_at = %#v, want %q", got, httpDueAt)
	}
	noteBody, err := protojson.Marshal(&cerebrov1.AddFindingNoteRequest{Note: "Escalate to identity engineering."})
	if err != nil {
		t.Fatalf("marshal add finding note body: %v", err)
	}
	noteReq, err := http.NewRequest(http.MethodPost, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/notes", bytes.NewReader(noteBody))
	if err != nil {
		t.Fatalf("new add note request: %v", err)
	}
	noteReq.Header.Set("Content-Type", "application/json")
	noteResp, err := server.Client().Do(noteReq)
	if err != nil {
		t.Fatalf("POST /findings/{id}/notes error = %v", err)
	}
	defer func() {
		if closeErr := noteResp.Body.Close(); closeErr != nil {
			t.Fatalf("close note response body: %v", closeErr)
		}
	}()
	var notePayload map[string]any
	if err := json.NewDecoder(noteResp.Body).Decode(&notePayload); err != nil {
		t.Fatalf("decode note response: %v", err)
	}
	noteFinding, ok := notePayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("note finding payload = %#v, want object", notePayload["finding"])
	}
	noteEntries, ok := noteFinding["notes"].([]any)
	if !ok || len(noteEntries) != 1 {
		t.Fatalf("note finding notes = %#v, want 1 entry", noteFinding["notes"])
	}
	addNoteResp, err := client.AddFindingNote(context.Background(), connect.NewRequest(&cerebrov1.AddFindingNoteRequest{
		Id:   evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Note: "Create follow-up review task.",
	}))
	if err != nil {
		t.Fatalf("AddFindingNote() error = %v", err)
	}
	if got := len(addNoteResp.Msg.GetFinding().GetNotes()); got != 2 {
		t.Fatalf("len(AddFindingNote().Finding.Notes) = %d, want 2", got)
	}
	if got := addNoteResp.Msg.GetFinding().GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("AddFindingNote().Finding.Attributes[api_key] = %q, want [redacted]", got)
	}
	ticketBody, err := protojson.Marshal(&cerebrov1.LinkFindingTicketRequest{
		Url:        "https://jira.writer.com/browse/ENG-123",
		Name:       "ENG-123",
		ExternalId: "ENG-123",
	})
	if err != nil {
		t.Fatalf("marshal finding ticket body: %v", err)
	}
	ticketReq, err := http.NewRequest(http.MethodPost, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/tickets", bytes.NewReader(ticketBody))
	if err != nil {
		t.Fatalf("new finding ticket request: %v", err)
	}
	ticketReq.Header.Set("Content-Type", "application/json")
	ticketResp, err := server.Client().Do(ticketReq)
	if err != nil {
		t.Fatalf("POST /findings/{id}/tickets error = %v", err)
	}
	defer func() {
		if closeErr := ticketResp.Body.Close(); closeErr != nil {
			t.Fatalf("close ticket response body: %v", closeErr)
		}
	}()
	var ticketPayload map[string]any
	if err := json.NewDecoder(ticketResp.Body).Decode(&ticketPayload); err != nil {
		t.Fatalf("decode ticket response: %v", err)
	}
	ticketFinding, ok := ticketPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("ticket finding payload = %#v, want object", ticketPayload["finding"])
	}
	ticketEntries, ok := ticketFinding["tickets"].([]any)
	if !ok || len(ticketEntries) != 1 {
		t.Fatalf("ticket finding tickets = %#v, want 1 entry", ticketFinding["tickets"])
	}
	linkTicketResp, err := client.LinkFindingTicket(context.Background(), connect.NewRequest(&cerebrov1.LinkFindingTicketRequest{
		Id:         evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Url:        "https://linear.app/writer/issue/SEC-42",
		Name:       "SEC-42",
		ExternalId: "SEC-42",
	}))
	if err != nil {
		t.Fatalf("LinkFindingTicket() error = %v", err)
	}
	if got := len(linkTicketResp.Msg.GetFinding().GetTickets()); got != 2 {
		t.Fatalf("len(LinkFindingTicket().Finding.Tickets) = %d, want 2", got)
	}
	connectDueAt := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	setDueDateResp, err := client.SetFindingDueDate(context.Background(), connect.NewRequest(&cerebrov1.SetFindingDueDateRequest{
		Id:    evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		DueAt: timestamppb.New(connectDueAt),
	}))
	if err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if got := setDueDateResp.Msg.GetFinding().GetDueAt().AsTime(); !got.Equal(connectDueAt) {
		t.Fatalf("SetFindingDueDate().Finding.DueAt = %v, want %v", got, connectDueAt)
	}
	resolveFindingResp, err := client.ResolveFinding(context.Background(), connect.NewRequest(&cerebrov1.ResolveFindingRequest{
		Id:     evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Reason: "verified remediation",
	}))
	if err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}
	if got := resolveFindingResp.Msg.GetFinding().GetStatus(); got != cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED {
		t.Fatalf("ResolveFinding().Finding.Status = %v, want FINDING_STATUS_RESOLVED", got)
	}
	if got := resolveFindingResp.Msg.GetFinding().GetStatusReason(); got != "verified remediation" {
		t.Fatalf("ResolveFinding().Finding.StatusReason = %q, want verified remediation", got)
	}
	getFindingResp, err := server.Client().Get(server.URL + "/findings/" + evaluateFindingsResp.Msg.GetFindings()[0].GetId())
	if err != nil {
		t.Fatalf("GET /findings/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getFindingResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get finding response body: %v", closeErr)
		}
	}()
	var getFindingPayload map[string]any
	if err := json.NewDecoder(getFindingResp.Body).Decode(&getFindingPayload); err != nil {
		t.Fatalf("decode get finding response: %v", err)
	}
	getFindingBody, ok := getFindingPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("get finding payload = %#v, want object", getFindingPayload["finding"])
	}
	if got := getFindingBody["status"]; got != "FINDING_STATUS_RESOLVED" {
		t.Fatalf("get finding status = %#v, want FINDING_STATUS_RESOLVED", got)
	}
	if got := getFindingBody["assignee"]; got != "secops" {
		t.Fatalf("get finding assignee = %#v, want secops", got)
	}
	if got := getFindingBody["due_at"]; got != "2026-05-02T12:00:00Z" {
		t.Fatalf("get finding due_at = %#v, want 2026-05-02T12:00:00Z", got)
	}
	getFindingAttributes, ok := getFindingBody["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("get finding attributes = %#v, want object", getFindingBody["attributes"])
	}
	if got := getFindingAttributes["api_key"]; got != "[redacted]" {
		t.Fatalf("get finding api_key = %#v, want [redacted]", got)
	}
	if got := getFindingAttributes["environment"]; got != "prod" {
		t.Fatalf("get finding environment = %#v, want prod", got)
	}
	getFindingNotes, ok := getFindingBody["notes"].([]any)
	if !ok || len(getFindingNotes) != 2 {
		t.Fatalf("get finding notes = %#v, want 2 entries", getFindingBody["notes"])
	}
	getFindingTickets, ok := getFindingBody["tickets"].([]any)
	if !ok || len(getFindingTickets) != 2 {
		t.Fatalf("get finding tickets = %#v, want 2 entries", getFindingBody["tickets"])
	}
	suppressFindingResp, err := client.SuppressFinding(context.Background(), connect.NewRequest(&cerebrov1.SuppressFindingRequest{
		Id:     evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Reason: "accepted risk",
	}))
	if err != nil {
		t.Fatalf("SuppressFinding() error = %v", err)
	}
	if got := suppressFindingResp.Msg.GetFinding().GetStatus(); got != cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED {
		t.Fatalf("SuppressFinding().Finding.Status = %v, want FINDING_STATUS_SUPPRESSED", got)
	}
	if got := runtimeStore.findingEvaluationRunListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingEvaluationRunListRequest.Status; got != "completed" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.Status = %q, want completed", got)
	}
	if got := runtimeStore.findingEvidenceListRequest.ClaimID; got != "claim-1" {
		t.Fatalf("runtimeStore.findingEvidenceListRequest.ClaimID = %q, want claim-1", got)
	}
	if got := runtimeStore.findingEvidenceListRequest.EventID; got != "okta-policy-rule-inactive" {
		t.Fatalf("runtimeStore.findingEvidenceListRequest.EventID = %q, want okta-policy-rule-inactive", got)
	}
	if len(runtimeStore.findingEvaluationRuns) < 4 {
		t.Fatalf("len(runtimeStore.findingEvaluationRuns) = %d, want at least 4", len(runtimeStore.findingEvaluationRuns))
	}
	if len(runtimeStore.findings) < 1 {
		t.Fatalf("len(runtimeStore.findings) = %d, want at least 1", len(runtimeStore.findings))
	}
	if len(runtimeStore.findingEvidence) < 1 {
		t.Fatalf("len(runtimeStore.findingEvidence) = %d, want at least 1", len(runtimeStore.findingEvidence))
	}
	if got := len(graphStore.entities); got < 9 {
		t.Fatalf("len(graphStore.entities) = %d, want at least 9", got)
	}
	if got := len(graphStore.links); got < 15 {
		t.Fatalf("len(graphStore.links) = %d, want at least 15", got)
	}
	decisionCount := 0
	outcomeCount := 0
	for _, entity := range graphStore.entities {
		if entity == nil {
			continue
		}
		switch entity.EntityType {
		case "decision":
			decisionCount++
		case "outcome":
			outcomeCount++
		}
	}
	if decisionCount != 2 {
		t.Fatalf("decision entity count = %d, want 2", decisionCount)
	}
	if outcomeCount != 2 {
		t.Fatalf("outcome entity count = %d, want 2", outcomeCount)
	}
}

func TestFindingCandidateEndpointsEvaluateListGetAndPromote(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{
		replayEvents: []*cerebrov1.EventEnvelope{
			findingPolicyRuleTestEvent("okta-policy-rule-active", "ACTIVE"),
			findingPolicyRuleTestEvent("okta-policy-rule-inactive", "INACTIVE"),
		},
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-policy-rule": {
				Id:       "writer-okta-policy-rule",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"family": "policy_rule", "token": "super-secret"},
			},
		},
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-policy-rule",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1",
				Predicate:     "status",
				ObjectValue:   "INACTIVE",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "okta-policy-rule-inactive",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: &stubGraphStore{},
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	evaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-policy-rule/finding-candidates/evaluate?event_limit=2&rule_id=identity-okta-policy-rule-lifecycle-tampering", nil)
	if err != nil {
		t.Fatalf("new candidate evaluate request: %v", err)
	}
	evaluateResp, err := server.Client().Do(evaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/finding-candidates/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := evaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close candidate evaluate response body: %v", closeErr)
		}
	}()
	if evaluateResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(evaluateResp.Body)
		t.Fatalf("candidate evaluate status = %d body=%s", evaluateResp.StatusCode, string(body))
	}
	var evaluatePayload map[string]any
	if err := json.NewDecoder(evaluateResp.Body).Decode(&evaluatePayload); err != nil {
		t.Fatalf("decode candidate evaluate response: %v", err)
	}
	evaluations := evaluatePayload["evaluations"].([]any)
	candidates := evaluations[0].(map[string]any)["candidates"].([]any)
	candidatePayload := candidates[0].(map[string]any)
	candidateID := candidatePayload["id"].(string)
	if candidateID == "" {
		t.Fatal("candidate id is empty")
	}
	storedCandidate, ok := runtimeStore.findingCandidates[candidateID]
	if !ok {
		t.Fatalf("stored candidate %q missing", candidateID)
	}
	if storedCandidate.Finding == nil {
		t.Fatal("stored candidate finding is nil")
	}
	if storedCandidate.Finding.Attributes == nil {
		storedCandidate.Finding.Attributes = map[string]string{}
	}
	storedCandidate.Finding.Attributes["api_key"] = "candidate-finding-secret"
	storedCandidate.Finding.Attributes["environment"] = "prod"
	if len(storedCandidate.Evidence) != 1 {
		t.Fatalf("len(stored candidate evidence) = %d, want 1", len(storedCandidate.Evidence))
	}
	if storedCandidate.Evidence[0].Attributes == nil {
		storedCandidate.Evidence[0].Attributes = map[string]string{}
	}
	storedCandidate.Evidence[0].Attributes["token"] = "candidate-evidence-secret"
	storedCandidate.Evidence[0].Attributes["resource_id"] = "rul-1"
	storedCandidate.Evidence[0].GraphRows = []*cerebrov1.GraphEvidenceRow{{
		Label:      "candidate-policy-rule",
		Attributes: map[string]string{"private_key": "candidate-row-secret", "resource_id": "rul-1"},
		Paths: []*cerebrov1.GraphEvidencePath{{
			Attributes: map[string]string{"password": "candidate-path-secret", "relation": "member"},
		}},
	}}
	if got := len(runtimeStore.findings); got != 0 {
		t.Fatalf("production findings after candidate evaluate = %d, want 0", got)
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-policy-rule/finding-candidates?status=candidate&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-candidates error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close candidate list response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode candidate list response: %v", err)
	}
	listCandidates := listPayload["candidates"].([]any)
	if got := len(listCandidates); got != 1 {
		t.Fatalf("listed candidates = %d, want 1", got)
	}
	listedCandidate, ok := listCandidates[0].(map[string]any)
	if !ok {
		t.Fatalf("listed candidate = %#v, want object", listCandidates[0])
	}
	listedCandidateFinding, ok := listedCandidate["finding"].(map[string]any)
	if !ok {
		t.Fatalf("listed candidate finding = %#v, want object", listedCandidate["finding"])
	}
	listedCandidateAttributes, ok := listedCandidateFinding["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("listed candidate finding attributes = %#v, want object", listedCandidateFinding["attributes"])
	}
	if got := listedCandidateAttributes["api_key"]; got != "[redacted]" {
		t.Fatalf("listed candidate finding api_key = %#v, want [redacted]", got)
	}
	listedCandidateEvidence := listedCandidate["evidence"].([]any)[0].(map[string]any)
	listedEvidenceAttributes := listedCandidateEvidence["attributes"].(map[string]any)
	if got := listedEvidenceAttributes["token"]; got != "[redacted]" {
		t.Fatalf("listed candidate evidence token = %#v, want [redacted]", got)
	}
	listedGraphRow := listedCandidateEvidence["graph_rows"].([]any)[0].(map[string]any)
	if got := listedGraphRow["attributes"].(map[string]any)["private_key"]; got != "[redacted]" {
		t.Fatalf("listed candidate graph row private_key = %#v, want [redacted]", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getResp, err := client.GetFindingCandidate(context.Background(), connect.NewRequest(&cerebrov1.GetFindingCandidateRequest{Id: candidateID}))
	if err != nil {
		t.Fatalf("GetFindingCandidate() error = %v", err)
	}
	if got := getResp.Msg.GetCandidate().GetId(); got != candidateID {
		t.Fatalf("GetFindingCandidate().Candidate.Id = %q, want %q", got, candidateID)
	}
	if got := getResp.Msg.GetCandidate().GetFinding().GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("GetFindingCandidate().Candidate.Finding.Attributes[api_key] = %q, want [redacted]", got)
	}
	if got := getResp.Msg.GetCandidate().GetEvidence()[0].GetAttributes()["token"]; got != "[redacted]" {
		t.Fatalf("GetFindingCandidate().Candidate.Evidence[0].Attributes[token] = %q, want [redacted]", got)
	}

	promoteBody, err := protojson.Marshal(&cerebrov1.PromoteFindingCandidateRequest{
		PromotedBy:            "analyst@example.com",
		Rationale:             "Validated against source data.",
		ChangeTicket:          "SEC-123",
		FalsePositiveReviewed: true,
		GraphCoverageReviewed: true,
	})
	if err != nil {
		t.Fatalf("marshal promote request: %v", err)
	}
	promoteResp, err := server.Client().Post(server.URL+"/finding-candidates/"+candidateID+"/promote", "application/json", bytes.NewReader(promoteBody))
	if err != nil {
		t.Fatalf("POST /finding-candidates/{id}/promote error = %v", err)
	}
	defer func() {
		if closeErr := promoteResp.Body.Close(); closeErr != nil {
			t.Fatalf("close candidate promote response body: %v", closeErr)
		}
	}()
	if promoteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(promoteResp.Body)
		t.Fatalf("candidate promote status = %d body=%s", promoteResp.StatusCode, string(body))
	}
	var promotePayload map[string]any
	if err := json.NewDecoder(promoteResp.Body).Decode(&promotePayload); err != nil {
		t.Fatalf("decode candidate promote response: %v", err)
	}
	promotedCandidate := promotePayload["candidate"].(map[string]any)
	if got := promotedCandidate["status"]; got != "promoted" {
		t.Fatalf("promoted candidate status = %#v, want promoted", got)
	}
	promotedFinding := promotePayload["finding"].(map[string]any)
	if got := promotedFinding["attributes"].(map[string]any)["api_key"]; got != "[redacted]" {
		t.Fatalf("promoted finding api_key = %#v, want [redacted]", got)
	}
	promotedCandidateEvidence := promotedCandidate["evidence"].([]any)[0].(map[string]any)
	if got := promotedCandidateEvidence["attributes"].(map[string]any)["token"]; got != "[redacted]" {
		t.Fatalf("promoted candidate evidence token = %#v, want [redacted]", got)
	}
	if got := promotedCandidateEvidence["graph_rows"].([]any)[0].(map[string]any)["paths"].([]any)[0].(map[string]any)["attributes"].(map[string]any)["password"]; got != "[redacted]" {
		t.Fatalf("promoted candidate graph path password = %#v, want [redacted]", got)
	}
	if got := len(runtimeStore.findings); got != 1 {
		t.Fatalf("production findings after promote = %d, want 1", got)
	}
	if got := len(runtimeStore.findingEvidence); got != 1 {
		t.Fatalf("production finding evidence after promote = %d, want 1", got)
	}
	if promotePayload["decision_id"] == "" {
		t.Fatal("promotion decision_id is empty")
	}

	rejectCandidateID := candidateID + "-reject"
	rejectCandidate := cloneFindingCandidate(runtimeStore.findingCandidates[candidateID])
	rejectCandidate.ID = rejectCandidateID
	rejectCandidate.Status = "candidate"
	rejectCandidate.DecisionID = ""
	rejectCandidate.PromotedFindingID = ""
	rejectCandidate.PromotedBy = ""
	rejectCandidate.PromotionRationale = ""
	rejectCandidate.ChangeTicket = ""
	rejectCandidate.PromotedAt = time.Time{}
	runtimeStore.findingCandidates[rejectCandidateID] = rejectCandidate
	rejectResp, err := client.RejectFindingCandidate(context.Background(), connect.NewRequest(&cerebrov1.RejectFindingCandidateRequest{
		Id:         rejectCandidateID,
		RejectedBy: "analyst@example.com",
		Rationale:  "Expected inactive policy rule fixture.",
	}))
	if err != nil {
		t.Fatalf("RejectFindingCandidate() error = %v", err)
	}
	if got := rejectResp.Msg.GetCandidate().GetStatus(); got != "rejected" {
		t.Fatalf("RejectFindingCandidate().Candidate.Status = %q, want rejected", got)
	}
	if got := rejectResp.Msg.GetCandidate().GetFinding().GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("RejectFindingCandidate().Candidate.Finding.Attributes[api_key] = %q, want [redacted]", got)
	}
	if got := rejectResp.Msg.GetCandidate().GetEvidence()[0].GetGraphRows()[0].GetAttributes()["private_key"]; got != "[redacted]" {
		t.Fatalf("RejectFindingCandidate().Candidate.Evidence[0].GraphRows[0].Attributes[private_key] = %q, want [redacted]", got)
	}
	if rejectResp.Msg.GetDecisionId() == "" {
		t.Fatal("RejectFindingCandidate().DecisionId is empty")
	}
	if got := len(runtimeStore.findings); got != 1 {
		t.Fatalf("production findings after reject = %d, want 1", got)
	}
}

func TestEndpointVulnerabilityFindingsHTTPRoute(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{findings: map[string]*ports.FindingRecord{
		"endpoint-vuln-1": {
			ID:              "endpoint-vuln-1",
			TenantID:        "writer",
			RuntimeID:       "kandji-runtime",
			RuleID:          "endpoint-vulnerability-kandji",
			Title:           "Endpoint vulnerability detected",
			Severity:        "HIGH",
			Status:          "open",
			EventIDs:        []string{"event-1"},
			ResourceURNs:    []string{"urn:cerebro:writer:kandji_device:dev-1"},
			Attributes:      map[string]string{"device_id": "dev-1", "vulnerability_id": "CVE-2026-0001", "package_name": "openssl", "installed_version": "3.0.1", "fixed_version": "3.0.12", "source_provider": "kandji"},
			FirstObservedAt: now.Add(-time.Hour),
			LastObservedAt:  now,
		},
		"endpoint-vuln-2": {
			ID:              "endpoint-vuln-2",
			TenantID:        "writer",
			RuntimeID:       "sentinelone-runtime",
			RuleID:          "endpoint-vulnerability-sentinelone",
			Title:           "Endpoint vulnerability detected",
			Severity:        "CRITICAL",
			Status:          "open",
			EventIDs:        []string{"event-2"},
			ResourceURNs:    []string{"urn:cerebro:writer:sentinelone_agent:agent-1"},
			Attributes:      map[string]string{"device_id": "dev-1", "vulnerability_id": "CVE-2026-0001", "package_name": "openssl", "installed_version": "3.0.1", "known_exploited": "true", "source_provider": "sentinelone"},
			FirstObservedAt: now.Add(-time.Hour),
			LastObservedAt:  now.Add(time.Minute),
		},
		"endpoint-vuln-stale": {
			ID:              "endpoint-vuln-stale",
			TenantID:        "writer",
			RuntimeID:       "vulnview-runtime",
			RuleID:          "endpoint-vulnerability-vulnview",
			Title:           "Stale endpoint vulnerability source",
			Severity:        "MEDIUM",
			Status:          "open",
			EventIDs:        []string{"event-stale"},
			ResourceURNs:    []string{"urn:cerebro:writer:kandji_device:dev-1"},
			Attributes:      map[string]string{"device_id": "dev-1", "serial_number": "serial-1", "vulnerability_id": "CVE-2026-0002", "package_name": "zlib", "installed_version": "1.2.11", "source_freshness": "stale", "source_provider": "vulnview"},
			FirstObservedAt: now.Add(-2 * time.Hour),
			LastObservedAt:  now.Add(2 * time.Minute),
		},
		"endpoint-vuln-other-device": {
			ID:              "endpoint-vuln-other-device",
			TenantID:        "writer",
			RuntimeID:       "kandji-runtime",
			RuleID:          "endpoint-vulnerability-kandji",
			Title:           "Other endpoint vulnerability",
			Severity:        "LOW",
			Status:          "open",
			EventIDs:        []string{"event-other"},
			ResourceURNs:    []string{"urn:cerebro:writer:kandji_device:dev-2"},
			Attributes:      map[string]string{"device_id": "dev-2", "vulnerability_id": "CVE-2026-9999", "package_name": "curl", "installed_version": "8.1.0", "source_provider": "kandji"},
			FirstObservedAt: now.Add(-time.Hour),
			LastObservedAt:  now,
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/endpoint-vulnerability-findings?tenant_id=writer&device_id=dev-1")
	if err != nil {
		t.Fatalf("GET /endpoint-vulnerability-findings error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close endpoint vulnerability response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /endpoint-vulnerability-findings status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	type endpointFindingResponse struct {
		Findings []struct {
			VulnerabilityID string `json:"vulnerability_id"`
			Severity        string `json:"severity"`
			Sources         []struct {
				SourceProvider string `json:"source_provider"`
			} `json:"sources"`
			KEV *struct {
				Listed bool `json:"listed"`
			} `json:"kev"`
		} `json:"findings"`
	}
	var body endpointFindingResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode endpoint vulnerability response: %v", err)
	}
	if got := len(body.Findings); got != 1 {
		t.Fatalf("len(findings) = %d, want 1", got)
	}
	if body.Findings[0].VulnerabilityID != "CVE-2026-0001" || body.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("finding = %#v, want merged critical CVE-2026-0001", body.Findings[0])
	}
	if got := len(body.Findings[0].Sources); got != 2 {
		t.Fatalf("len(sources) = %d, want 2", got)
	}
	if body.Findings[0].KEV == nil || !body.Findings[0].KEV.Listed {
		t.Fatalf("KEV = %#v, want listed KEV", body.Findings[0].KEV)
	}

	platformResp, err := server.Client().Get(server.URL + "/platform/endpoints/dev-1/vulnerability-findings?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /platform/endpoints/{deviceKey}/vulnerability-findings error = %v", err)
	}
	defer func() {
		if closeErr := platformResp.Body.Close(); closeErr != nil {
			t.Fatalf("close platform endpoint vulnerability response body: %v", closeErr)
		}
	}()
	if platformResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/endpoints/{deviceKey}/vulnerability-findings status = %d, want %d", platformResp.StatusCode, http.StatusOK)
	}
	var platformBody endpointFindingResponse
	if err := json.NewDecoder(platformResp.Body).Decode(&platformBody); err != nil {
		t.Fatalf("decode platform endpoint vulnerability response: %v", err)
	}
	if got := len(platformBody.Findings); got != 1 {
		t.Fatalf("len(platform findings) = %d, want 1", got)
	}
	if platformBody.Findings[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("platform finding = %#v, want path device dev-1 despite query overrides", platformBody.Findings[0])
	}

	platformConflictResp, err := server.Client().Get(server.URL + "/platform/endpoints/dev-1/vulnerability-findings?tenant_id=writer&device_id=dev-2")
	if err != nil {
		t.Fatalf("GET /platform/endpoints/{deviceKey}/vulnerability-findings conflicting query error = %v", err)
	}
	defer func() {
		if closeErr := platformConflictResp.Body.Close(); closeErr != nil {
			t.Fatalf("close platform conflict endpoint vulnerability response body: %v", closeErr)
		}
	}()
	if platformConflictResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/endpoints/{deviceKey}/vulnerability-findings conflicting query status = %d, want %d", platformConflictResp.StatusCode, http.StatusOK)
	}
	var platformConflictBody endpointFindingResponse
	if err := json.NewDecoder(platformConflictResp.Body).Decode(&platformConflictBody); err != nil {
		t.Fatalf("decode platform conflict endpoint vulnerability response: %v", err)
	}
	if got := len(platformConflictBody.Findings); got != 1 {
		t.Fatalf("len(platform conflict findings) = %d, want path-scoped dev-1 findings only", got)
	}
	if platformConflictBody.Findings[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("platform conflict finding = %#v, want path-scoped dev-1 finding", platformConflictBody.Findings[0])
	}

	staleResp, err := server.Client().Get(server.URL + "/endpoint-vulnerability-findings?tenant_id=writer&device_id=dev-1&include_stale=true")
	if err != nil {
		t.Fatalf("GET /endpoint-vulnerability-findings include_stale error = %v", err)
	}
	defer func() {
		if closeErr := staleResp.Body.Close(); closeErr != nil {
			t.Fatalf("close endpoint vulnerability stale response body: %v", closeErr)
		}
	}()
	if staleResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /endpoint-vulnerability-findings include_stale status = %d, want %d", staleResp.StatusCode, http.StatusOK)
	}
	var staleBody endpointFindingResponse
	if err := json.NewDecoder(staleResp.Body).Decode(&staleBody); err != nil {
		t.Fatalf("decode endpoint vulnerability stale response: %v", err)
	}
	if got := len(staleBody.Findings); got != 2 {
		t.Fatalf("len(include_stale findings) = %d, want active plus stale source", got)
	}

	emptyResp, err := server.Client().Get(server.URL + "/endpoint-vulnerability-findings?tenant_id=writer&serial_number=missing")
	if err != nil {
		t.Fatalf("GET /endpoint-vulnerability-findings empty error = %v", err)
	}
	defer func() {
		if closeErr := emptyResp.Body.Close(); closeErr != nil {
			t.Fatalf("close endpoint vulnerability empty response body: %v", closeErr)
		}
	}()
	if emptyResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /endpoint-vulnerability-findings empty status = %d, want %d", emptyResp.StatusCode, http.StatusOK)
	}
	var emptyBody endpointFindingResponse
	if err := json.NewDecoder(emptyResp.Body).Decode(&emptyBody); err != nil {
		t.Fatalf("decode endpoint vulnerability empty response: %v", err)
	}
	if got := len(emptyBody.Findings); got != 0 {
		t.Fatalf("len(empty findings) = %d, want 0", got)
	}
}

func TestPlatformKnowledgeDecisionAndOutcomeEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	graphStore := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	appendLog := &recordingAppendLog{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		GraphStore: graphStore,
		AppendLog:  appendLog,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)

	decisionBody, err := protojson.Marshal(&cerebrov1.WriteDecisionRequest{
		DecisionType: "finding-triage",
		Status:       "approved",
		MadeBy:       "secops",
		Rationale:    "accepted risk pending remediation",
		TargetIds:    []string{targetURN},
		EvidenceIds:  []string{"finding-evidence-1"},
	})
	if err != nil {
		t.Fatalf("marshal write decision body: %v", err)
	}
	decisionReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/knowledge/decisions", bytes.NewReader(decisionBody))
	if err != nil {
		t.Fatalf("new write decision request: %v", err)
	}
	decisionReq.Header.Set("Content-Type", "application/json")
	decisionResp, err := server.Client().Do(decisionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/decisions error = %v", err)
	}
	defer func() {
		if closeErr := decisionResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write decision response body: %v", closeErr)
		}
	}()
	if decisionResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /platform/knowledge/decisions status = %d, want %d", decisionResp.StatusCode, http.StatusCreated)
	}
	var decisionPayload map[string]any
	if err := json.NewDecoder(decisionResp.Body).Decode(&decisionPayload); err != nil {
		t.Fatalf("decode write decision response: %v", err)
	}
	decisionID, ok := decisionPayload["decision_id"].(string)
	if !ok || decisionID == "" {
		t.Fatalf("decision_id = %#v, want non-empty string", decisionPayload["decision_id"])
	}
	if got := decisionPayload["target_count"]; got != float64(1) {
		t.Fatalf("decision target_count = %#v, want 1", got)
	}
	if _, ok := graphStore.entities["urn:cerebro:writer:evidence:finding-evidence-1"]; !ok {
		t.Fatal("decision evidence entity missing")
	}
	if _, ok := graphStore.links[decisionID+"|targets|"+targetURN]; !ok {
		t.Fatal("decision target link missing")
	}
	actionBody, err := protojson.Marshal(&cerebrov1.WriteActionRequest{
		RecommendationId: "recommendation-1",
		InsightType:      "remediation",
		Title:            "Open remediation ticket",
		Summary:          "Track the fix in the owning team's backlog",
		DecisionId:       decisionID,
		TargetIds:        []string{targetURN},
		SourceSystem:     "platform.recommendations",
		SourceEventId:    "recommendation-evt-1",
		AutoGenerated:    true,
	})
	if err != nil {
		t.Fatalf("marshal write action body: %v", err)
	}
	actionReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/knowledge/actions", bytes.NewReader(actionBody))
	if err != nil {
		t.Fatalf("new write action request: %v", err)
	}
	actionReq.Header.Set("Content-Type", "application/json")
	actionResp, err := server.Client().Do(actionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/actions error = %v", err)
	}
	defer func() {
		if closeErr := actionResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write action response body: %v", closeErr)
		}
	}()
	if actionResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /platform/knowledge/actions status = %d, want %d", actionResp.StatusCode, http.StatusCreated)
	}
	var actionPayload map[string]any
	if err := json.NewDecoder(actionResp.Body).Decode(&actionPayload); err != nil {
		t.Fatalf("decode write action response: %v", err)
	}
	actionID, ok := actionPayload["action_id"].(string)
	if !ok || actionID == "" {
		t.Fatalf("action_id = %#v, want non-empty string", actionPayload["action_id"])
	}
	if got := actionPayload["decision_id"]; got != decisionID {
		t.Fatalf("action decision_id = %#v, want %q", got, decisionID)
	}
	if got := actionPayload["target_count"]; got != float64(1) {
		t.Fatalf("action target_count = %#v, want 1", got)
	}
	if _, ok := graphStore.entities[actionID]; !ok {
		t.Fatalf("action entity %q missing", actionID)
	}
	if _, ok := graphStore.links[actionID+"|targets|"+targetURN]; !ok {
		t.Fatal("action target link missing")
	}
	if _, ok := graphStore.links[decisionID+"|executed_by|"+actionID]; !ok {
		t.Fatal("decision action link missing")
	}

	outcomeResp, err := client.WriteOutcome(context.Background(), connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
		DecisionId:  decisionID,
		OutcomeType: "finding-resolution",
		Verdict:     "resolved",
		TargetIds:   []string{targetURN},
	}))
	if err != nil {
		t.Fatalf("WriteOutcome() error = %v", err)
	}
	if got := outcomeResp.Msg.GetDecisionId(); got != decisionID {
		t.Fatalf("WriteOutcome().DecisionId = %q, want %q", got, decisionID)
	}
	if got := outcomeResp.Msg.GetTargetCount(); got != 1 {
		t.Fatalf("WriteOutcome().TargetCount = %d, want 1", got)
	}
	outcomeID := outcomeResp.Msg.GetOutcomeId()
	if outcomeID == "" {
		t.Fatal("WriteOutcome().OutcomeId = empty, want non-empty")
	}
	if _, ok := graphStore.entities[outcomeID]; !ok {
		t.Fatalf("outcome entity %q missing", outcomeID)
	}
	if _, ok := graphStore.links[outcomeID+"|evaluates|"+decisionID]; !ok {
		t.Fatal("outcome evaluates link missing")
	}
	if _, ok := graphStore.links[outcomeID+"|targets|"+targetURN]; !ok {
		t.Fatal("outcome target link missing")
	}
	if len(appendLog.events) != 3 {
		t.Fatalf("len(appendLog.events) = %d, want 3", len(appendLog.events))
	}
}

func TestWorkflowReplayEndpoint(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	decisionID := "urn:cerebro:writer:decision:decision-1"
	decisionEvent, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:     "writer",
		DecisionID:   decisionID,
		DecisionType: "finding-triage",
		Status:       "approved",
		TargetIDs:    []string{targetURN},
		SourceSystem: "findings",
		ObservedAt:   "2026-04-27T12:00:00Z",
		ValidFrom:    "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	poisonEvent := &cerebrov1.EventEnvelope{
		Id:         "event-poison",
		TenantId:   "writer",
		Kind:       workflowevents.EventKindKnowledgeDecisionRecorded,
		Payload:    []byte("{not-json"),
		Attributes: map[string]string{"workflow_kind": "knowledge_decision"},
	}
	appendLog := &recordingAppendLog{replayEvents: []*cerebrov1.EventEnvelope{poisonEvent, decisionEvent}}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := protojson.Marshal(&cerebrov1.ReplayWorkflowEventsRequest{
		TenantId: "writer",
		AttributeEquals: map[string]string{
			"workflow_kind": "knowledge_decision",
		},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("marshal ReplayWorkflowEventsRequest: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/platform/workflow/replay", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /platform/workflow/replay error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /platform/workflow/replay response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /platform/workflow/replay status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var replayPayload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&replayPayload); err != nil {
		t.Fatalf("decode ReplayWorkflowEventsResponse: %v", err)
	}
	if replayPayload["events_read"] != float64(2) || replayPayload["events_projected"] != float64(1) {
		t.Fatalf("replay counts = read:%v projected:%v, want 1/1", replayPayload["events_read"], replayPayload["events_projected"])
	}
	if replayPayload["events_failed"] != float64(1) {
		t.Fatalf("events_failed = %v, want 1", replayPayload["events_failed"])
	}
	errorSamples, ok := replayPayload["errors"].([]any)
	if !ok || len(errorSamples) != 1 {
		t.Fatalf("errors = %#v, want one sample", replayPayload["errors"])
	}
	if _, ok := graphStore.entities[decisionID]; !ok {
		t.Fatalf("decision entity %q missing after replay", decisionID)
	}
	if _, ok := graphStore.links[decisionID+"|targets|"+targetURN]; !ok {
		t.Fatal("decision target link missing after replay")
	}
	if len(appendLog.replayRequests) != 1 {
		t.Fatalf("len(replayRequests) = %d, want 1", len(appendLog.replayRequests))
	}
	if got := appendLog.replayRequests[0].KindPrefix; got != "" {
		t.Fatalf("HTTP replay kind prefix = %q, want empty multi-prefix request", got)
	}
	if got := appendLog.replayRequests[0].KindPrefixes; len(got) != 2 || got[0] != "workflow.v1." || got[1] != "sec.findings.v1." {
		t.Fatalf("HTTP replay kind prefixes = %v, want workflow and sec finding prefixes", got)
	}
	if got := appendLog.replayRequests[0].AttributeEquals["workflow_kind"]; got != "knowledge_decision" {
		t.Fatalf("HTTP replay workflow_kind filter = %q, want knowledge_decision", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectResp, err := client.ReplayWorkflowEvents(context.Background(), connect.NewRequest(&cerebrov1.ReplayWorkflowEventsRequest{
		KindPrefix: "workflow.v1.knowledge.",
		TenantId:   "writer",
		Limit:      2,
	}))
	if err != nil {
		t.Fatalf("ReplayWorkflowEvents() error = %v", err)
	}
	if got := connectResp.Msg.GetEntitiesProjected(); got != 1 {
		t.Fatalf("ReplayWorkflowEvents().EntitiesProjected = %d, want 1", got)
	}
	if got := connectResp.Msg.GetEventsFailed(); got != 1 {
		t.Fatalf("ReplayWorkflowEvents().EventsFailed = %d, want 1", got)
	}
	if got := connectResp.Msg.GetErrors(); len(got) != 1 || got[0].GetEventId() != "event-poison" {
		t.Fatalf("ReplayWorkflowEvents().Errors = %+v, want event-poison sample", got)
	}
	if len(appendLog.replayRequests) != 2 {
		t.Fatalf("len(replayRequests) = %d, want 2", len(appendLog.replayRequests))
	}
	if got := appendLog.replayRequests[1].KindPrefix; got != "workflow.v1.knowledge." {
		t.Fatalf("Connect replay kind prefix = %q, want workflow.v1.knowledge.", got)
	}
}

func TestClaimEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config: map[string]string{
					"integration": "jira",
				},
			},
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	writeBody, err := protojson.Marshal(&cerebrov1.WriteClaimsRequest{
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate: "assigned_to",
				ObjectRef: &cerebrov1.EntityRef{
					Urn:        userURN,
					EntityType: "user",
					Label:      "Alice",
				},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal write claims body: %v", err)
	}
	writeReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-jira/claims", bytes.NewReader(writeBody))
	if err != nil {
		t.Fatalf("new write claims request: %v", err)
	}
	writeReq.Header.Set("Content-Type", "application/json")
	writeResp, err := server.Client().Do(writeReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := writeResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write claims response body: %v", closeErr)
		}
	}()
	var writePayload map[string]any
	if err := json.NewDecoder(writeResp.Body).Decode(&writePayload); err != nil {
		t.Fatalf("decode write claims response: %v", err)
	}
	if got := writePayload["claims_written"]; got != float64(2) {
		t.Fatalf("write claims claims_written = %#v, want 2", got)
	}
	if got := writePayload["entities_upserted"]; got != float64(2) {
		t.Fatalf("write claims entities_upserted = %#v, want 2", got)
	}
	if got := writePayload["relation_links_projected"]; got != float64(1) {
		t.Fatalf("write claims relation_links_projected = %#v, want 1", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	writeClaimsResp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:  "exists",
				ClaimType:  "existence",
				ObservedAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := writeClaimsResp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("WriteClaims claims_written = %d, want 1", got)
	}
	if len(runtimeStore.claims) != 3 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 3", len(runtimeStore.claims))
	}
	if len(runtimeStore.entities) != 2 {
		t.Fatalf("len(runtimeStore.entities) = %d, want 2", len(runtimeStore.entities))
	}
	if len(graphStore.links) != 1 {
		t.Fatalf("len(graphStore.links) = %d, want 1", len(graphStore.links))
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-jira/claims?predicate=assigned_to&source_event_id=jira-event-1&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list claims response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list claims response: %v", err)
	}
	listedClaims, ok := listPayload["claims"].([]any)
	if !ok || len(listedClaims) != 1 {
		t.Fatalf("list claims payload = %#v, want 1 claim", listPayload["claims"])
	}
	listedClaim, ok := listedClaims[0].(map[string]any)
	if !ok {
		t.Fatalf("list claims entry = %#v, want object", listedClaims[0])
	}
	if got := listedClaim["predicate"]; got != "assigned_to" {
		t.Fatalf("list claims predicate = %#v, want assigned_to", got)
	}

	listClaimsResp, err := client.ListClaims(context.Background(), connect.NewRequest(&cerebrov1.ListClaimsRequest{
		RuntimeId:     "writer-jira",
		Predicate:     "status",
		ObjectValue:   "in_progress",
		SourceEventId: "jira-event-1",
		Limit:         1,
	}))
	if err != nil {
		t.Fatalf("ListClaims() error = %v", err)
	}
	if got := len(listClaimsResp.Msg.GetClaims()); got != 1 {
		t.Fatalf("len(ListClaims().Claims) = %d, want 1", got)
	}
	if got := listClaimsResp.Msg.GetClaims()[0].GetObjectValue(); got != "in_progress" {
		t.Fatalf("ListClaims().Claims[0].ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.Predicate; got != "status" {
		t.Fatalf("runtimeStore.claimListRequest.Predicate = %q, want status", got)
	}
	if got := runtimeStore.claimListRequest.ObjectValue; got != "in_progress" {
		t.Fatalf("runtimeStore.claimListRequest.ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.SourceEventID; got != "jira-event-1" {
		t.Fatalf("runtimeStore.claimListRequest.SourceEventID = %q, want jira-event-1", got)
	}
}

func TestWriteClaimsReplaceExistingReportsRetractedClaims(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config:   map[string]string{"integration": "jira"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	if _, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "assigned_to",
				ObjectRef:     &cerebrov1.EntityRef{Urn: userURN, EntityType: "user", Label: "Alice"},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})); err != nil {
		t.Fatalf("seed WriteClaims() error = %v", err)
	}

	resp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId:       "writer-jira",
		ReplaceExisting: true,
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "done",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-2",
				ObservedAt:    timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("replace WriteClaims() error = %v", err)
	}
	if got := resp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("replace claims_written = %d, want 1", got)
	}
	if got := resp.Msg.GetClaimsRetracted(); got != 2 {
		t.Fatalf("replace claims_retracted = %d, want 2", got)
	}
	if len(runtimeStore.claims) != 3 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 3", len(runtimeStore.claims))
	}
	var retracted *ports.ClaimRecord
	for _, claim := range runtimeStore.claims {
		if claim != nil && claim.Predicate == "assigned_to" {
			retracted = claim
			break
		}
	}
	if retracted == nil {
		t.Fatal("retracted assigned_to claim = nil, want non-nil")
	}
	if got := retracted.Status; got != "retracted" {
		t.Fatalf("retracted claim status = %q, want retracted", got)
	}
	if got := retracted.SourceEventID; got != "jira-event-2" {
		t.Fatalf("retracted claim source_event_id = %q, want jira-event-2", got)
	}
}

func TestGraphNeighborhoodEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
				EntityType: "github.pull_request",
				Label:      "writer/cerebro#447",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:github_code_repository:writer/cerebro", EntityType: "github.code.repository", Label: "writer/cerebro"},
				{URN: "urn:cerebro:writer:github_user:alice", EntityType: "github.user", Label: "Alice"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:github_user:alice", Relation: "authored", ToURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447"},
				{FromURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447", Relation: "belongs_to", ToURN: "urn:cerebro:writer:github_code_repository:writer/cerebro"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: &stubRuntimeStore{},
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/neighborhood?root_urn=urn:cerebro:writer:github_pull_request:writer/cerebro%23447&limit=5")
	if err != nil {
		t.Fatalf("GET /platform/graph/neighborhood error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /platform/graph/neighborhood response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /platform/graph/neighborhood response: %v", err)
	}
	rootPayload, ok := payload["root"].(map[string]any)
	if !ok {
		t.Fatalf("graph root payload = %#v, want object", payload["root"])
	}
	if got := rootPayload["entity_type"]; got != "github.pull_request" {
		t.Fatalf("graph root entity_type = %#v, want github.pull_request", got)
	}
	neighborsPayload, ok := payload["neighbors"].([]any)
	if !ok || len(neighborsPayload) != 2 {
		t.Fatalf("graph neighbors payload = %#v, want 2 entries", payload["neighbors"])
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("graph neighborhood root urn = %q, want pull request urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 5 {
		t.Fatalf("graph neighborhood limit = %d, want 5", graphStore.neighborhoodLimit)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	neighborhoodResp, err := client.GetEntityNeighborhood(context.Background(), connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
		Limit:   2,
	}))
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got := neighborhoodResp.Msg.GetRoot().GetUrn(); got != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("GetEntityNeighborhood root urn = %q, want pull request urn", got)
	}
	if len(neighborhoodResp.Msg.GetNeighbors()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Neighbors) = %d, want 2", len(neighborhoodResp.Msg.GetNeighbors()))
	}
	if len(neighborhoodResp.Msg.GetRelations()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Relations) = %d, want 2", len(neighborhoodResp.Msg.GetRelations()))
	}
}

func TestLegacyGraphAliasesAreRemoved(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/graph/neighborhood"},
		{method: http.MethodGet, path: "/graph/impact/vulnerability/CVE-2026-1111"},
		{method: http.MethodGet, path: "/graph/impact/package"},
		{method: http.MethodGet, path: "/graph/impact/asset"},
		{method: http.MethodGet, path: "/graph/ingest-health"},
		{method: http.MethodGet, path: "/graph/ingest-runs"},
		{method: http.MethodGet, path: "/graph/ingest-runs/run-1"},
		{method: http.MethodPost, path: "/graph/actuate/recommendation"},
		{method: http.MethodPost, path: "/graph/write/outcome"},
	} {
		req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s %s): %v", tc.method, tc.path, err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s error = %v", tc.method, tc.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status = %d, want removed route status", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestReportEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
			"finding-2": {
				ID:           "finding-2",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "resolved",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:okta_user:00u2", EntityType: "okta.user", Label: "admin@writer.com"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:okta_user:00u2", Relation: "acted_on", ToURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	listResp, err := server.Client().Get(server.URL + "/reports")
	if err != nil {
		t.Fatalf("GET /reports error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode /reports response: %v", err)
	}
	reportsPayload, ok := listPayload["reports"].([]any)
	if !ok || len(reportsPayload) != 3 {
		t.Fatalf("/reports payload = %#v, want 3 entries", listPayload["reports"])
	}

	runReq, err := http.NewRequest(http.MethodPost, server.URL+"/reports/finding-summary/runs?tenant_id=writer&runtime_ids=writer-okta-audit&graph_limit=2", nil)
	if err != nil {
		t.Fatalf("new run report request: %v", err)
	}
	runReq.Header.Set("X-Cerebro-Source-Config", `{"token":"secret","api_key":"secret"}`)
	runResp, err := server.Client().Do(runReq)
	if err != nil {
		t.Fatalf("POST /reports/{id}/runs error = %v", err)
	}
	defer func() {
		if closeErr := runResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports/{id}/runs response body: %v", closeErr)
		}
	}()
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode /reports/{id}/runs response: %v", err)
	}
	runBody, ok := runPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("run payload = %#v, want object", runPayload["run"])
	}
	if got := runBody["report_id"]; got != "finding-summary" {
		t.Fatalf("run report_id = %#v, want finding-summary", got)
	}
	resultBody, ok := runBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("run result payload = %#v, want object", runBody["result"])
	}
	if got := resultBody["total_findings"]; got != float64(2) {
		t.Fatalf("run total_findings = %#v, want 2", got)
	}
	if got := resultBody["graph_evidence_status"]; got != "included" {
		t.Fatalf("run graph_evidence_status = %#v, want included", got)
	}
	graphEvidencePayload, ok := resultBody["graph_evidence"].([]any)
	if !ok || len(graphEvidencePayload) != 1 {
		t.Fatalf("run graph_evidence = %#v, want 1 entry", resultBody["graph_evidence"])
	}
	graphEvidenceEntry, ok := graphEvidencePayload[0].(map[string]any)
	if !ok {
		t.Fatalf("run graph evidence entry = %#v, want object", graphEvidencePayload[0])
	}
	if got := graphEvidenceEntry["resource_urn"]; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("run graph evidence resource_urn = %#v, want policy rule urn", got)
	}
	runID, ok := runBody["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("run id = %#v, want non-empty string", runBody["id"])
	}
	if len(runtimeStore.reportRuns) != 1 {
		t.Fatalf("len(runtimeStore.reportRuns) = %d, want 1", len(runtimeStore.reportRuns))
	}
	storedRun := runtimeStore.reportRuns[runID]
	if _, ok := storedRun.GetParameters()["token"]; ok {
		t.Fatalf("stored report parameters include token")
	}
	if _, ok := storedRun.GetParameters()["api_key"]; ok {
		t.Fatalf("stored report parameters include api_key")
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("graph evidence root urn = %q, want policy rule urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 2 {
		t.Fatalf("graph evidence limit = %d, want 2", graphStore.neighborhoodLimit)
	}

	getResp, err := server.Client().Get(server.URL + "/report-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /report-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /report-runs/{id} response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode /report-runs/{id} response: %v", err)
	}
	getRunPayload, ok := getPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get run payload = %#v, want object", getPayload["run"])
	}
	if got := getRunPayload["id"]; got != runID {
		t.Fatalf("get run id = %#v, want %q", got, runID)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listReportsResp, err := client.ListReportDefinitions(context.Background(), connect.NewRequest(&cerebrov1.ListReportDefinitionsRequest{}))
	if err != nil {
		t.Fatalf("ListReportDefinitions() error = %v", err)
	}
	if len(listReportsResp.Msg.GetReports()) != 3 {
		t.Fatalf("len(ListReportDefinitions.Reports) = %d, want 3", len(listReportsResp.Msg.GetReports()))
	}
	runReportResp, err := client.RunReport(context.Background(), connect.NewRequest(&cerebrov1.RunReportRequest{
		ReportId: "finding-summary",
		Parameters: map[string]string{
			"tenant_id":   "writer",
			"runtime_ids": "writer-okta-audit",
		},
	}))
	if err != nil {
		t.Fatalf("RunReport() error = %v", err)
	}
	if got := runReportResp.Msg.GetRun().GetReportId(); got != "finding-summary" {
		t.Fatalf("RunReport report id = %q, want finding-summary", got)
	}
	getRunResp, err := client.GetReportRun(context.Background(), connect.NewRequest(&cerebrov1.GetReportRunRequest{
		Id: runReportResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetReportRun() error = %v", err)
	}
	if got := getRunResp.Msg.GetRun().GetId(); got != runReportResp.Msg.GetRun().GetId() {
		t.Fatalf("GetReportRun id = %q, want %q", got, runReportResp.Msg.GetRun().GetId())
	}
}

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	auth0, err := auth0source.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	pagerDuty, err := pagerdutysource.NewFixture()
	if err != nil {
		return nil, err
	}
	datadog, err := datadogsource.NewFixture()
	if err != nil {
		return nil, err
	}
	sdk, err := sdksource.New()
	if err != nil {
		return nil, err
	}
	slack, err := slacksource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, auth0, datadog, okta, pagerDuty, sdk, slack)
}

func assertBootstrapProjectedLink(t *testing.T, graph *stubGraphStore, fromURN string, relation string, toURN string) {
	t.Helper()
	if graph == nil {
		t.Fatal("graph store is nil")
	}
	key := fromURN + "|" + relation + "|" + toURN
	if _, ok := graph.links[key]; !ok {
		t.Fatalf("missing projected link %s; links = %#v", key, graph.links)
	}
}

func TestFindingMessageIncludesRiskFactors(t *testing.T) {
	observedAt := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	message := findingMessage(&ports.FindingRecord{
		ID: "finding-risk-factor",
		FindingRisk: ports.FindingRisk{
			RiskFactors: []ports.FindingRiskFactor{{
				FactorID:             "external_exposure",
				Category:             "likelihood",
				Weight:               35,
				SeverityContribution: "high",
				EvidenceRefs:         []string{"attribute:internet_exposed"},
				ObservedAt:           observedAt,
				SuppressionScope:     "factor:external_exposure",
			}},
		},
	})

	if len(message.GetRiskFactors()) != 1 {
		t.Fatalf("len(RiskFactors) = %d, want 1", len(message.GetRiskFactors()))
	}
	factor := message.GetRiskFactors()[0]
	if factor.GetFactorId() != "external_exposure" || factor.GetWeight() != 35 {
		t.Fatalf("risk factor = %#v, want external_exposure weight 35", factor)
	}
	if factor.GetObservedAt().AsTime() != observedAt {
		t.Fatalf("ObservedAt = %v, want %v", factor.GetObservedAt().AsTime(), observedAt)
	}
}

func TestSafeFindingMessageRedactsSensitiveAttributes(t *testing.T) {
	record := &ports.FindingRecord{
		ID:         "finding-redaction",
		Attributes: map[string]string{"api_key": "finding-secret", "environment": "prod"},
	}

	message := safeFindingMessage(record)
	if got := message.GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("safe finding api_key = %q, want [redacted]", got)
	}
	if got := message.GetAttributes()["environment"]; got != "prod" {
		t.Fatalf("safe finding environment = %q, want prod", got)
	}
	if got := record.Attributes["api_key"]; got != "finding-secret" {
		t.Fatalf("source finding api_key = %q, want original value", got)
	}
}

func TestSafeFindingEvidenceRedactsSensitiveAttributes(t *testing.T) {
	evidence := &cerebrov1.FindingEvidence{
		Id:         "evidence-redaction",
		Attributes: map[string]string{"token": "evidence-secret", "resource_id": "asset-1"},
		GraphRows: []*cerebrov1.GraphEvidenceRow{{
			Label:      "root",
			Attributes: map[string]string{"private_key": "row-secret", "asset_type": "service"},
			Paths: []*cerebrov1.GraphEvidencePath{{
				Attributes: map[string]string{"password": "path-secret", "relation": "owns"},
			}},
		}},
		Observations: []*cerebrov1.FindingEvidenceObservation{{
			GraphRows: []*cerebrov1.GraphEvidenceRow{{
				Label:      "observation",
				Attributes: map[string]string{"signing_key": "observation-secret", "asset_type": "user"},
				Paths: []*cerebrov1.GraphEvidencePath{{
					Attributes: map[string]string{"secret_access_key": "observation-path-secret", "relation": "member"},
				}},
			}},
		}},
	}

	safe := safeFindingEvidence(evidence)
	if got := safe.GetAttributes()["token"]; got != "[redacted]" {
		t.Fatalf("safe evidence token = %q, want [redacted]", got)
	}
	if got := safe.GetAttributes()["resource_id"]; got != "asset-1" {
		t.Fatalf("safe evidence resource_id = %q, want asset-1", got)
	}
	if got := safe.GetGraphRows()[0].GetAttributes()["private_key"]; got != "[redacted]" {
		t.Fatalf("safe graph row private_key = %q, want [redacted]", got)
	}
	if got := safe.GetGraphRows()[0].GetPaths()[0].GetAttributes()["password"]; got != "[redacted]" {
		t.Fatalf("safe graph path password = %q, want [redacted]", got)
	}
	if got := safe.GetObservations()[0].GetGraphRows()[0].GetAttributes()["signing_key"]; got != "[redacted]" {
		t.Fatalf("safe observation graph row signing_key = %q, want [redacted]", got)
	}
	if got := safe.GetObservations()[0].GetGraphRows()[0].GetPaths()[0].GetAttributes()["secret_access_key"]; got != "[redacted]" {
		t.Fatalf("safe observation graph path secret_access_key = %q, want [redacted]", got)
	}
	if got := evidence.GetAttributes()["token"]; got != "evidence-secret" {
		t.Fatalf("source evidence token = %q, want original value", got)
	}
	if got := evidence.GetGraphRows()[0].GetAttributes()["private_key"]; got != "row-secret" {
		t.Fatalf("source graph row private_key = %q, want original value", got)
	}
}

func TestFindingCandidateResponsesRedactNestedAttributes(t *testing.T) {
	candidate := &ports.FindingCandidateRecord{
		ID:        "candidate-redaction",
		TenantID:  "writer",
		RuntimeID: "runtime-1",
		Finding: &ports.FindingRecord{
			ID:         "candidate-finding",
			Attributes: map[string]string{"api_key": "candidate-finding-secret", "environment": "prod"},
		},
		Evidence: []*cerebrov1.FindingEvidence{{
			Id:         "candidate-evidence",
			Attributes: map[string]string{"token": "candidate-evidence-secret", "resource_id": "asset-1"},
			GraphRows: []*cerebrov1.GraphEvidenceRow{{
				Attributes: map[string]string{"private_key": "candidate-row-secret", "asset_type": "service"},
				Paths: []*cerebrov1.GraphEvidencePath{{
					Attributes: map[string]string{"password": "candidate-path-secret", "relation": "owns"},
				}},
			}},
		}},
	}

	listResponse := listFindingCandidatesResponse(&findings.ListCandidatesResult{Candidates: []*ports.FindingCandidateRecord{candidate}})
	listCandidate := listResponse.GetCandidates()[0]
	if got := listCandidate.GetFinding().GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("list candidate finding api_key = %q, want [redacted]", got)
	}
	if got := listCandidate.GetEvidence()[0].GetAttributes()["token"]; got != "[redacted]" {
		t.Fatalf("list candidate evidence token = %q, want [redacted]", got)
	}
	if got := listCandidate.GetEvidence()[0].GetGraphRows()[0].GetAttributes()["private_key"]; got != "[redacted]" {
		t.Fatalf("list candidate graph row private_key = %q, want [redacted]", got)
	}

	promoteResponse := promoteFindingCandidateResponse(&findings.PromoteCandidateResult{
		Candidate:  candidate,
		Finding:    candidate.Finding,
		DecisionID: "decision-1",
	})
	if got := promoteResponse.GetFinding().GetAttributes()["api_key"]; got != "[redacted]" {
		t.Fatalf("promote finding api_key = %q, want [redacted]", got)
	}
	if got := promoteResponse.GetCandidate().GetEvidence()[0].GetGraphRows()[0].GetPaths()[0].GetAttributes()["password"]; got != "[redacted]" {
		t.Fatalf("promote candidate graph path password = %q, want [redacted]", got)
	}
	if got := candidate.Finding.Attributes["api_key"]; got != "candidate-finding-secret" {
		t.Fatalf("source candidate finding api_key = %q, want original value", got)
	}
	if got := candidate.Evidence[0].GetAttributes()["token"]; got != "candidate-evidence-secret" {
		t.Fatalf("source candidate evidence token = %q, want original value", got)
	}
}

type bootstrapTokenSource struct {
	id           string
	emittedKinds []string
	checkToken   string
	readToken    string
}

func (s *bootstrapTokenSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Bootstrap token source", EmittedKinds: append([]string{}, s.emittedKinds...)}
}

func (s *bootstrapTokenSource) Check(_ context.Context, config sourcecdk.Config) error {
	s.checkToken, _ = config.Lookup("token")
	return nil
}

func (s *bootstrapTokenSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *bootstrapTokenSource) Read(_ context.Context, config sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readToken, _ = config.Lookup("token")
	return sourcecdk.Pull{Events: []*primitives.Event{}}, nil
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := make([]string, len(finding.ResourceURNs))
	copy(resourceURNs, finding.ResourceURNs)
	eventIDs := make([]string, len(finding.EventIDs))
	copy(eventIDs, finding.EventIDs)
	observedPolicyIDs := make([]string, len(finding.ObservedPolicyIDs))
	copy(observedPolicyIDs, finding.ObservedPolicyIDs)
	controlRefs := make([]ports.FindingControlRef, len(finding.ControlRefs))
	copy(controlRefs, finding.ControlRefs)
	notes := make([]ports.FindingNote, len(finding.Notes))
	copy(notes, finding.Notes)
	tickets := make([]ports.FindingTicket, len(finding.Tickets))
	copy(tickets, finding.Tickets)
	externalRefs := make([]ports.FindingExternalRef, len(finding.ExternalRefs))
	copy(externalRefs, finding.ExternalRefs)
	riskReasons := append([]string(nil), finding.RiskReasons...)
	riskFactors := append([]ports.FindingRiskFactor(nil), finding.RiskFactors...)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantID:          finding.TenantID,
		RuntimeID:         finding.RuntimeID,
		RuleID:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            finding.Status,
		Summary:           finding.Summary,
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			ExternalRefs:    externalRefs,
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		FindingRisk: ports.FindingRisk{
			RiskScore:        finding.RiskScore,
			LikelihoodScore:  finding.LikelihoodScore,
			ImpactScore:      finding.ImpactScore,
			ConfidenceScore:  finding.ConfidenceScore,
			LikelihoodLevel:  finding.LikelihoodLevel,
			ImpactLevel:      finding.ImpactLevel,
			RiskReasons:      riskReasons,
			RiskFactors:      riskFactors,
			RiskModelVersion: finding.RiskModelVersion,
		},
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func preserveFindingWorkflow(existing *ports.FindingRecord, incoming *ports.FindingRecord) *ports.FindingRecord {
	if existing == nil || incoming == nil {
		return incoming
	}
	if strings.TrimSpace(existing.Assignee) != "" && strings.TrimSpace(incoming.Assignee) == "" {
		incoming.Assignee = strings.TrimSpace(existing.Assignee)
	}
	if !existing.DueAt.IsZero() && incoming.DueAt.IsZero() {
		incoming.DueAt = existing.DueAt
	}
	if len(existing.Notes) != 0 && len(incoming.Notes) == 0 {
		incoming.Notes = append([]ports.FindingNote(nil), existing.Notes...)
	}
	if len(existing.Tickets) != 0 && len(incoming.Tickets) == 0 {
		incoming.Tickets = append([]ports.FindingTicket(nil), existing.Tickets...)
	}
	if len(existing.ExternalRefs) != 0 && len(incoming.ExternalRefs) == 0 {
		incoming.ExternalRefs = append([]ports.FindingExternalRef(nil), existing.ExternalRefs...)
	}
	if strings.TrimSpace(incoming.Status) == "open" {
		switch strings.TrimSpace(existing.Status) {
		case "resolved", "suppressed":
			incoming.Status = strings.TrimSpace(existing.Status)
			incoming.StatusReason = strings.TrimSpace(existing.StatusReason)
			incoming.StatusUpdatedAt = existing.StatusUpdatedAt
		}
	}
	return incoming
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
		return false
	}
	runtimeIDs := normalizedTestStrings(append(request.RuntimeIDs, request.RuntimeID))
	if len(runtimeIDs) == 0 || !containsTrimmed(runtimeIDs, finding.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(finding.ID) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(finding.RuleID) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if len(request.ProfilePredicate.RuleIDs) != 0 || len(request.ProfilePredicate.ControlRefs) != 0 {
		profileMatch := containsTrimmed(request.ProfilePredicate.RuleIDs, finding.RuleID)
		for _, wanted := range request.ProfilePredicate.ControlRefs {
			for _, actual := range finding.ControlRefs {
				if strings.EqualFold(strings.TrimSpace(actual.FrameworkName), strings.TrimSpace(wanted.FrameworkName)) &&
					strings.EqualFold(strings.TrimSpace(actual.ControlID), strings.TrimSpace(wanted.ControlID)) {
					profileMatch = true
				}
			}
		}
		if !profileMatch {
			return false
		}
	}
	if request.Severity != "" && strings.TrimSpace(finding.Severity) != strings.TrimSpace(request.Severity) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(finding.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	resourceURNs := normalizedTestStrings(append(request.ResourceURNs, request.ResourceURN))
	if len(resourceURNs) != 0 {
		matched := false
		for _, resourceURN := range resourceURNs {
			if containsTrimmed(finding.ResourceURNs, resourceURN) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if request.EventID != "" && !containsTrimmed(finding.EventIDs, request.EventID) {
		return false
	}
	if request.PolicyID != "" && strings.TrimSpace(finding.PolicyID) != strings.TrimSpace(request.PolicyID) {
		return false
	}
	return true
}

func endpointVulnerabilityFindingMatches(request ports.EndpointVulnerabilityFindingQuery, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
		return false
	}
	if !request.IncludeStale && !strings.EqualFold(strings.TrimSpace(finding.Status), "open") {
		return false
	}
	attributes := finding.Attributes
	if strings.TrimSpace(request.DeviceID) != "" && containsTrimmed([]string{
		attributes["device_id"],
		attributes["endpoint_id"],
		attributes["asset_id"],
	}, request.DeviceID) {
		return true
	}
	if strings.TrimSpace(request.SerialNumber) != "" && strings.TrimSpace(attributes["serial_number"]) == strings.TrimSpace(request.SerialNumber) {
		return true
	}
	if strings.TrimSpace(request.AgentID) != "" && containsTrimmed([]string{
		attributes["agent_id"],
		attributes["agent_uuid"],
	}, request.AgentID) {
		return true
	}
	return false
}

func cloneClaim(claim *ports.ClaimRecord) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            claim.ID,
		RuntimeID:     claim.RuntimeID,
		TenantID:      claim.TenantID,
		SubjectURN:    claim.SubjectURN,
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectURN:     claim.ObjectURN,
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventID: claim.SourceEventID,
		ObservedAt:    claim.ObservedAt,
		ValidFrom:     claim.ValidFrom,
		ValidTo:       claim.ValidTo,
		UpdatedAt:     claim.UpdatedAt,
		Attributes:    attributes,
	}
}

func claimMatches(request ports.ListClaimsRequest, claim *ports.ClaimRecord) bool {
	if claim == nil {
		return false
	}
	if request.RuntimeID != "" && strings.TrimSpace(claim.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.TenantID != "" && strings.TrimSpace(claim.TenantID) != strings.TrimSpace(request.TenantID) {
		return false
	}
	if request.ClaimID != "" && strings.TrimSpace(claim.ID) != strings.TrimSpace(request.ClaimID) {
		return false
	}
	if request.SubjectURN != "" && strings.TrimSpace(claim.SubjectURN) != strings.TrimSpace(request.SubjectURN) {
		return false
	}
	if request.Predicate != "" && strings.TrimSpace(claim.Predicate) != strings.TrimSpace(request.Predicate) {
		return false
	}
	if request.ObjectURN != "" && strings.TrimSpace(claim.ObjectURN) != strings.TrimSpace(request.ObjectURN) {
		return false
	}
	if request.ObjectValue != "" && strings.TrimSpace(claim.ObjectValue) != strings.TrimSpace(request.ObjectValue) {
		return false
	}
	if request.ClaimType != "" && strings.TrimSpace(claim.ClaimType) != strings.TrimSpace(request.ClaimType) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(claim.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.SourceEventID != "" && strings.TrimSpace(claim.SourceEventID) != strings.TrimSpace(request.SourceEventID) {
		return false
	}
	if !request.AfterUpdatedAt.IsZero() && strings.TrimSpace(request.AfterID) != "" && !claimAfterCursor(claim, request) {
		return false
	}
	return true
}

func claimAfterCursor(claim *ports.ClaimRecord, request ports.ListClaimsRequest) bool {
	claimObserved := claim.ObservedAt
	cursorObserved := request.AfterObservedAt
	switch {
	case claimObserved.IsZero() != cursorObserved.IsZero():
		return claimObserved.IsZero()
	case !claimObserved.Equal(cursorObserved):
		return claimObserved.Before(cursorObserved)
	case !claim.UpdatedAt.Equal(request.AfterUpdatedAt):
		return claim.UpdatedAt.Before(request.AfterUpdatedAt)
	default:
		return strings.TrimSpace(claim.ID) > strings.TrimSpace(request.AfterID)
	}
}

func containsTrimmed(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}

func findingEvaluationRunMatches(request ports.ListFindingEvaluationRunsRequest, run *cerebrov1.FindingEvaluationRun) bool {
	if run == nil {
		return false
	}
	if strings.TrimSpace(run.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(run.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(run.GetStatus()) != strings.TrimSpace(request.Status) {
		return false
	}
	return true
}

func findingEvidenceMatches(request ports.ListFindingEvidenceRequest, evidence *cerebrov1.FindingEvidence) bool {
	if evidence == nil {
		return false
	}
	runtimeIDs := normalizedTestStrings(append(request.RuntimeIDs, request.RuntimeID))
	if len(runtimeIDs) == 0 || !containsTrimmed(runtimeIDs, evidence.GetRuntimeId()) {
		return false
	}
	findingIDs := normalizedTestStrings(append(request.FindingIDs, request.FindingID))
	if len(findingIDs) > 0 {
		if !containsTrimmed(findingIDs, evidence.GetFindingId()) {
			return false
		}
	} else if request.FindingIDs != nil {
		return false
	}
	if request.RunID != "" && strings.TrimSpace(evidence.GetRunId()) != strings.TrimSpace(request.RunID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(evidence.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.ClaimID != "" && !containsTrimmed(evidence.GetClaimIds(), request.ClaimID) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(evidence.GetEventIds(), request.EventID) {
		return false
	}
	if request.GraphRootURN != "" && !containsTrimmed(evidence.GetGraphRootUrns(), request.GraphRootURN) {
		return false
	}
	return true
}

func normalizedTestStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func cloneReportRun(run *cerebrov1.ReportRun) *cerebrov1.ReportRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.ReportRun)
}

func cloneFindingEvaluationRun(run *cerebrov1.FindingEvaluationRun) *cerebrov1.FindingEvaluationRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.FindingEvaluationRun)
}

func cloneFindingEvidence(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if evidence == nil {
		return nil
	}
	return proto.Clone(evidence).(*cerebrov1.FindingEvidence)
}

func cloneFindingCandidate(candidate *ports.FindingCandidateRecord) *ports.FindingCandidateRecord {
	if candidate == nil {
		return nil
	}
	cloned := *candidate
	cloned.Finding = cloneFinding(candidate.Finding)
	cloned.Evidence = make([]*cerebrov1.FindingEvidence, 0, len(candidate.Evidence))
	for _, evidence := range candidate.Evidence {
		cloned.Evidence = append(cloned.Evidence, cloneFindingEvidence(evidence))
	}
	return &cloned
}

func cloneNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return nil
	}
	cloned := &ports.EntityNeighborhood{
		Root:      cloneNeighborhoodNode(neighborhood.Root),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(neighborhood.Neighbors)),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		cloned.Neighbors = append(cloned.Neighbors, cloneNeighborhoodNode(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		cloned.Relations = append(cloned.Relations, cloneNeighborhoodRelation(relation))
	}
	return cloned
}

func cloneNeighborhoodNode(node *ports.NeighborhoodNode) *ports.NeighborhoodNode {
	if node == nil {
		return nil
	}
	return &ports.NeighborhoodNode{
		URN:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func cloneNeighborhoodRelation(relation *ports.NeighborhoodRelation) *ports.NeighborhoodRelation {
	if relation == nil {
		return nil
	}
	return &ports.NeighborhoodRelation{
		FromURN:    relation.FromURN,
		Relation:   relation.Relation,
		ToURN:      relation.ToURN,
		Attributes: cloneStringMap(relation.Attributes),
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func findingPolicyRuleTestEvent(id string, status string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.policy_rule",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/policy_rule/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"family":                            "policy_rule",
			"policy_id":                         "pol-1",
			"policy_rule_id":                    "rul-1",
			"policy_type":                       "OKTA_SIGN_ON",
			"name":                              "Require MFA",
			"priority":                          "1",
			"resource_id":                       "rul-1",
			"resource_type":                     "PolicyRule",
			"status":                            status,
			"policy_rule_status":                status,
			"system":                            "false",
			ports.EventAttributeSourceRuntimeID: "writer-okta-policy-rule",
		},
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}

func cloneEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return proto.Clone(ref).(*cerebrov1.EntityRef)
}

func captureBootstrapStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func decodeBootstrapTelemetryPayload(t *testing.T, stderr string, names ...string) map[string]any {
	t.Helper()
	wantName := ""
	if len(names) > 0 {
		wantName = names[0]
	}
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatal("telemetry stderr is empty")
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", line, err)
		}
		if payload["name"] == "http.server" {
			continue
		}
		if payload["kind"] == "span_start" {
			continue
		}
		if wantName != "" && payload["name"] != wantName {
			continue
		}
		return payload
	}
	if wantName != "" {
		t.Fatalf("telemetry payload %q not found in stderr: %s", wantName, stderr)
	}
	t.Fatalf("non-http telemetry payload not found in stderr: %s", stderr)
	return nil
}
