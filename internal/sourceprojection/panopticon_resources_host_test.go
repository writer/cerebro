package sourceprojection

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/wasmjson"
	"github.com/writer/cerebro/internal/wasmjson/wasmjsontest"
)

const panopticonResourcesFuzzMaxInput = 64 << 10

//go:embed testdata/panopticonresources/*.json
var panopticonResourcesCorpus embed.FS

func TestPanopticonResourceObjectsWasmCorpus(t *testing.T) {
	t.Parallel()
	inputs := wasmjsontest.LoadInputs[map[string]any](t, panopticonResourcesCorpus, "testdata/panopticonresources/*.json", panopticonResourcesFuzzMaxInput)
	wasmjsontest.RunCorpus(t, context.Background(), inputs, panopticonResourcesDifferential())
}

func FuzzPanopticonResourceObjectsWasmParity(f *testing.F) {
	inputs := wasmjsontest.LoadInputs[map[string]any](f, panopticonResourcesCorpus, "testdata/panopticonresources/*.json", panopticonResourcesFuzzMaxInput)
	wasmjsontest.AddSeeds(f, inputs)
	differential := panopticonResourcesDifferential()
	f.Fuzz(func(t *testing.T, raw []byte) {
		wasmjsontest.CheckFuzzInput(t, context.Background(), raw, differential)
	})
}

func TestPanopticonResourceObjectsWasmMatchesReferenceTraversal(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"assets": []any{
			map[string]any{"asset_id": "asset-1", "name": "host-1"},
			map[string]any{"asset_id": "asset-1", "name": "duplicate"},
		},
		"affected_resources": []any{"arn:aws:s3:::audit", "plain-resource"},
		"alerts": []any{map[string]any{
			"alert_id": "alert-1",
			"resource_results": []any{
				map[string]any{"resource_id": "nested-1", "resource_type": "AWS::EC2::Instance"},
			},
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	got, err := panopticonResourceObjectsWasm(context.Background(), raw)
	if err != nil {
		t.Fatalf("panopticonResourceObjectsWasm() error = %v", err)
	}
	want := referencePanopticonResourceObjects(payload)
	if gotJSON, wantJSON := mustJSONValue(t, got), mustJSONValue(t, want); gotJSON != wantJSON {
		t.Fatalf("resource objects mismatch\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}

func TestPanopticonResourceObjectsWasmHandlesAliasesAndMalformedPayload(t *testing.T) {
	t.Parallel()
	got, err := panopticonResourceObjectsWasm(context.Background(), []byte(`{"alerts":[{"resourceResults":[{"ResourceID":"resource-1"}]}],"affectedResources":["arn:aws:s3:::audit"]}`))
	if err != nil {
		t.Fatalf("panopticonResourceObjectsWasm() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(resources) = %d, want 2: %#v", len(got), got)
	}
	if got[0]["resource_id"] != "arn:aws:s3:::audit" || got[0]["resource_arn"] != "arn:aws:s3:::audit" {
		t.Fatalf("scalar ARN resource = %#v", got[0])
	}
	if got[1]["ResourceID"] != "resource-1" {
		t.Fatalf("nested alias resource = %#v", got[1])
	}

	got, err = panopticonResourceObjectsWasm(context.Background(), []byte(`not-json`))
	if err != nil {
		t.Fatalf("malformed payload error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("malformed payload resources = %#v, want none", got)
	}
}

func TestPanopticonResourceObjectsWasmMatchesGoNumericScalarFormatting(t *testing.T) {
	t.Parallel()
	cases := []string{"1.0", "9007199254740993", "1e-7", "1e20", "-0.0"}
	for _, rawNumber := range cases {
		t.Run(rawNumber, func(t *testing.T) {
			raw := []byte(`{"resources":[` + rawNumber + `]}`)
			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatalf("unmarshal reference payload: %v", err)
			}
			got, err := panopticonResourceObjectsWasm(context.Background(), raw)
			if err != nil {
				t.Fatalf("panopticonResourceObjectsWasm() error = %v", err)
			}
			want := referencePanopticonResourceObjects(payload)
			if gotJSON, wantJSON := mustJSONValue(t, got), mustJSONValue(t, want); gotJSON != wantJSON {
				t.Fatalf("numeric scalar mismatch for %s\ngot:  %s\nwant: %s", rawNumber, gotJSON, wantJSON)
			}
		})
	}
}

func TestPanopticonResourceObjectsWasmMatchesGoDerivedNameAliases(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"alerts":[{"assetName":"asset-only"},{"deviceName":"device-only"},{"computerName":"computer-only"},{"resourceName":"resource-only"}]}`)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal reference payload: %v", err)
	}
	got, err := panopticonResourceObjectsWasm(context.Background(), raw)
	if err != nil {
		t.Fatalf("panopticonResourceObjectsWasm() error = %v", err)
	}
	want := referencePanopticonResourceObjects(payload)
	if gotJSON, wantJSON := mustJSONValue(t, got), mustJSONValue(t, want); gotJSON != wantJSON {
		t.Fatalf("derived-name resource mismatch\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}

func TestPanopticonResourceObjectsWasmBoundsInputWithoutEchoingPayload(t *testing.T) {
	t.Parallel()
	marker := "payload-marker-that-must-not-be-logged"
	payload := []byte(`{"resources":["` + marker + strings.Repeat("x", panopticonResourcesMaxInputBytes) + `"]}`)
	_, err := panopticonResourceObjectsWasm(context.Background(), payload)
	if !errors.Is(err, errPanopticonResourceExtractorUnavailable) {
		t.Fatalf("oversized payload error = %v, want extractor unavailable", err)
	}
	if !errors.Is(err, wasmjson.ErrInputTooLarge) {
		t.Fatalf("oversized payload error = %v, want input too large", err)
	}
}

func TestPanopticonResourceObjectsWasmAcceptsEmptyPayloadWithLiveContext(t *testing.T) {
	resources, err := panopticonResourceObjectsWasm(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty payload error = %v", err)
	}
	if resources != nil {
		t.Fatalf("empty payload resources = %#v, want nil", resources)
	}
}

func TestPanopticonResourceObjectsWasmHonorsCanceledContextForEmptyPayload(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := panopticonResourceObjectsWasm(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled extraction error = %v, want %v", err, context.Canceled)
	}
}

func mustJSONValue(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON value: %v", err)
	}
	return string(raw)
}

var referencePanopticonAssetObjectKeys = []string{"assets", "affected_assets", "hosts", "endpoints"}
var referencePanopticonResourceObjectKeys = []string{
	"resources", "affected_resources", "affected_resource", "impacted_resources", "matched_resources",
	"failed_resources", "violating_resources", "policy_resources", "resource_results", "target_resources",
	"targets", "entities", "resource", "target", "entity",
}
var referencePanopticonResourceContextKeys = []string{
	"alert", "alerts", "linked_alerts", "source_alerts", "upstream_alerts", "related_alerts", "alert_context",
	"p_alert_context", "panther_alert_context", "event", "events", "finding", "findings", "log", "logs",
	"policy", "policy_scan", "detail", "details", "context", "metadata", "data", "result", "results",
}

func referencePanopticonResourceObjects(payload map[string]any) []map[string]any {
	seen := map[string]struct{}{}
	var objects []map[string]any
	referenceCollectPanopticonResourceObjects(&objects, seen, payload, 0)
	return objects
}

func referenceCollectPanopticonResourceObjects(objects *[]map[string]any, seen map[string]struct{}, payload map[string]any, depth int) {
	if len(payload) == 0 || depth > 4 || len(*objects) >= maxPanopticonResourceObjects {
		return
	}
	referenceAppendPanopticonObjectsForKeys(objects, seen, payload, false, referencePanopticonAssetObjectKeys...)
	referenceAppendPanopticonObjectsForKeys(objects, seen, payload, true, referencePanopticonResourceObjectKeys...)
	for _, context := range panopticonObjectsForKeys(payload, false, referencePanopticonResourceContextKeys...) {
		if referencePanopticonLooksLikeResourceObject(context) {
			referenceAppendPanopticonResourceObject(objects, seen, context)
		}
		referenceCollectPanopticonResourceObjects(objects, seen, context, depth+1)
		if len(*objects) >= maxPanopticonResourceObjects {
			return
		}
	}
}

func referenceAppendPanopticonObjectsForKeys(objects *[]map[string]any, seen map[string]struct{}, payload map[string]any, scalarAsResource bool, keys ...string) {
	for _, object := range panopticonObjectsForKeys(payload, scalarAsResource, keys...) {
		if !scalarAsResource || referencePanopticonLooksLikeResourceObject(object) {
			referenceAppendPanopticonResourceObject(objects, seen, object)
		}
		if len(*objects) >= maxPanopticonResourceObjects {
			return
		}
	}
}

func referenceAppendPanopticonResourceObject(objects *[]map[string]any, seen map[string]struct{}, object map[string]any) {
	if len(object) == 0 || len(*objects) >= maxPanopticonResourceObjects {
		return
	}
	attrs := panopticonAssetAttributesFromObject(object)
	signature := firstNonEmpty(attrs["resource_urn"], attrs["resource_arn"], attrs["resource_id"], attrs["asset_id"], attrs["id"], attrs["name"])
	if signature != "" {
		if _, ok := seen[signature]; ok {
			return
		}
		seen[signature] = struct{}{}
	}
	*objects = append(*objects, object)
}

func referencePanopticonLooksLikeResourceObject(object map[string]any) bool {
	if len(object) == 0 {
		return false
	}
	attrs := panopticonAssetAttributesFromObject(object)
	return firstNonEmpty(attrs["resource_urn"], attrs["resource_arn"], attrs["resource_id"], attrs["asset_id"], attrs["id"], attrs["hostname"], attrs["name"]) != ""
}

func panopticonResourcesDifferential() wasmjsontest.Differential[map[string]any, []map[string]any] {
	return wasmjsontest.Differential[map[string]any, []map[string]any]{
		MaxInputBytes: panopticonResourcesFuzzMaxInput,
		Oracle: func(payload map[string]any) []map[string]any {
			resources := referencePanopticonResourceObjects(payload)
			if resources == nil {
				return []map[string]any{}
			}
			return resources
		},
		Candidate: func(ctx context.Context, input wasmjsontest.Input[map[string]any]) ([]map[string]any, error) {
			return panopticonResourceObjectsWasm(ctx, input.Raw)
		},
	}
}
