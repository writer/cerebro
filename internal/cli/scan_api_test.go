package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type scanCLIState struct {
	tables               []string
	limit                int
	dryRun               bool
	output               string
	full                 bool
	toxicCombos          bool
	useGraph             bool
	extractRelationships bool
	preflight            bool
	localFixture         string
	snapshotDir          string
}

func snapshotScanCLIState() scanCLIState {
	return scanCLIState{
		tables:               append([]string(nil), scanTables...),
		limit:                scanLimit,
		dryRun:               scanDryRun,
		output:               scanOutput,
		full:                 scanFull,
		toxicCombos:          scanToxicCombos,
		useGraph:             scanUseGraph,
		extractRelationships: scanExtractRelationships,
		preflight:            scanPreflight,
		localFixture:         scanLocalFixture,
		snapshotDir:          scanSnapshotDir,
	}
}

func restoreScanCLIState(state scanCLIState) {
	scanTables = append([]string(nil), state.tables...)
	scanLimit = state.limit
	scanDryRun = state.dryRun
	scanOutput = state.output
	scanFull = state.full
	scanToxicCombos = state.toxicCombos
	scanUseGraph = state.useGraph
	scanExtractRelationships = state.extractRelationships
	scanPreflight = state.preflight
	scanLocalFixture = state.localFixture
	scanSnapshotDir = state.snapshotDir
}

func TestRunScanViaAPI_AggregatesJSONOutput(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	expectedTables := []string{"aws_s3_buckets", "aws_iam_roles"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/findings/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		rawTables, ok := req["tables"].([]interface{})
		if !ok {
			t.Fatalf("expected tables array, got %#v", req["tables"])
		}
		if len(rawTables) != len(expectedTables) {
			t.Fatalf("expected %d tables, got %#v", len(expectedTables), rawTables)
		}
		for i, expected := range expectedTables {
			if rawTables[i] != expected {
				t.Fatalf("expected table %q at index %d, got %#v", expected, i, rawTables[i])
			}
		}
		if req["limit"] != float64(25) {
			t.Fatalf("expected limit=25, got %#v", req["limit"])
		}

		response := map[string]interface{}{
			"scanned":    3,
			"violations": 2,
			"duration":   "12ms",
			"findings": []map[string]interface{}{
				{"severity": "HIGH", "policy_id": "policy-1", "resource_id": expectedTables[0]},
				{"severity": "LOW", "policy_id": "policy-2", "resource_id": expectedTables[1]},
			},
			"tables": []map[string]interface{}{
				{"table": expectedTables[0], "scanned": 1, "violations": 1, "duration": "5ms"},
				{"table": expectedTables[1], "scanned": 2, "violations": 1, "duration": "7ms"},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	t.Setenv(envCLIAPIURL, server.URL)
	scanLimit = 25
	scanOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runScanViaAPI(context.Background(), expectedTables); err != nil {
			t.Fatalf("runScanViaAPI failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output json: %v (output=%s)", err, output)
	}
	if payload["mode"] != "api" {
		t.Fatalf("expected mode=api, got %#v", payload["mode"])
	}
	if payload["scanned"] != float64(3) {
		t.Fatalf("expected scanned=3, got %#v", payload["scanned"])
	}
	if payload["violations"] != float64(2) {
		t.Fatalf("expected violations=2, got %#v", payload["violations"])
	}
	findings, ok := payload["findings"].([]interface{})
	if !ok || len(findings) != 2 {
		t.Fatalf("expected two findings, got %#v", payload["findings"])
	}
	tables, ok := payload["tables"].([]interface{})
	if !ok || len(tables) != 2 {
		t.Fatalf("expected two table summaries, got %#v", payload["tables"])
	}
}

func TestRunScanViaAPI_ReturnsTransportError(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")
	scanOutput = FormatJSON

	err := runScanViaAPI(context.Background(), []string{"aws_s3_buckets"})
	if err == nil {
		t.Fatal("expected api transport error")
	}
}

func TestScanSupportsAPIMode(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	scanExtractRelationships = false
	scanFull = false
	scanToxicCombos = false
	scanUseGraph = false

	ok, reason := scanSupportsAPIMode(false)
	if !ok {
		t.Fatalf("expected api compatibility, got false: %s", reason)
	}

	scanDryRun = true
	ok, reason = scanSupportsAPIMode(false)
	if !ok {
		t.Fatalf("expected dry-run to remain api-compatible, got false: %s", reason)
	}
	scanDryRun = false

	scanToxicCombos = true
	ok, reason = scanSupportsAPIMode(false)
	if ok || !strings.Contains(reason, "--toxic-combos") {
		t.Fatalf("expected toxic-combo incompatibility, got ok=%v reason=%q", ok, reason)
	}

	scanToxicCombos = false
	scanUseGraph = true
	ok, reason = scanSupportsAPIMode(false)
	if ok || !strings.Contains(reason, "--graph") {
		t.Fatalf("expected graph incompatibility, got ok=%v reason=%q", ok, reason)
	}

	scanUseGraph = false
	ok, reason = scanSupportsAPIMode(true)
	if ok || !strings.Contains(reason, "local dataset mode") {
		t.Fatalf("expected local-mode incompatibility, got ok=%v reason=%q", ok, reason)
	}
}

func TestResolveAPIScanTables_UsesAPITablesWhenFlagsEmpty(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	requested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/tables" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tables": []string{"AWS_S3_BUCKETS", "cerebro_internal", "aws_iam_users"},
		})
	}))
	defer server.Close()

	t.Setenv(envCLIAPIURL, server.URL)
	scanTables = nil

	tables, err := resolveAPIScanTables(context.Background())
	if err != nil {
		t.Fatalf("resolveAPIScanTables failed: %v", err)
	}
	if !requested {
		t.Fatal("expected API /tables endpoint to be called")
	}

	expected := []string{"aws_iam_users", "aws_s3_buckets"}
	if !reflect.DeepEqual(tables, expected) {
		t.Fatalf("expected tables %v, got %v", expected, tables)
	}
}

func TestResolveAPIScanTables_UsesExplicitTablesWithoutAPI(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	scanTables = []string{"aws_s3_buckets", "aws_iam_users"}
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	tables, err := resolveAPIScanTables(context.Background())
	if err != nil {
		t.Fatalf("resolveAPIScanTables failed: %v", err)
	}

	if !reflect.DeepEqual(tables, scanTables) {
		t.Fatalf("expected explicit tables %v, got %v", scanTables, tables)
	}
}

func TestRunScanViaAPIFromFlags_EmptyTableSetJSONOutput(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tables" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tables": []string{}})
	}))
	defer server.Close()

	t.Setenv(envCLIAPIURL, server.URL)
	scanTables = nil
	scanOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runScanViaAPIFromFlags(context.Background()); err != nil {
			t.Fatalf("runScanViaAPIFromFlags failed: %v", err)
		}
	})

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output json: %v (output=%s)", err, output)
	}
	if payload["scanned"] != float64(0) {
		t.Fatalf("expected scanned=0, got %#v", payload["scanned"])
	}
	if payload["violations"] != float64(0) {
		t.Fatalf("expected violations=0, got %#v", payload["violations"])
	}
}

func TestRunScanViaAPIFromFlags_DryRunUsesAPIPolicyCount(t *testing.T) {
	state := snapshotScanCLIState()
	t.Cleanup(func() { restoreScanCLIState(state) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tables":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"tables": []string{"aws_s3_buckets"}})
		case "/api/v1/policies/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"policies": []map[string]interface{}{
					{"id": "policy-1", "name": "Policy 1", "severity": "high", "resource": "aws::s3::bucket"},
					{"id": "policy-2", "name": "Policy 2", "severity": "medium", "resource": "aws::s3::bucket"},
				},
			})
		case "/api/v1/findings/scan":
			t.Fatal("did not expect scan endpoint call in dry-run mode")
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(envCLIAPIURL, server.URL)
	scanTables = nil
	scanDryRun = true
	scanLimit = 123
	scanOutput = FormatTable

	output := captureStdout(t, func() {
		if err := runScanViaAPIFromFlags(context.Background()); err != nil {
			t.Fatalf("runScanViaAPIFromFlags failed: %v", err)
		}
	})

	if !strings.Contains(output, "Dry run - would scan") {
		t.Fatalf("expected dry-run banner in output, got %q", output)
	}
	if !strings.Contains(output, "aws_s3_buckets (up to 123 assets)") {
		t.Fatalf("expected table listing in output, got %q", output)
	}
	if !strings.Contains(output, "Using 2 policies") {
		t.Fatalf("expected policy count in output, got %q", output)
	}
}
