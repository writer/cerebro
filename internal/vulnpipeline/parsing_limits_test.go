package vulnpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func repeatedJSON(element string, count int) string {
	return strings.TrimSuffix(strings.Repeat(element+",", count), ",")
}

func mustDecode(t *testing.T, payload string) any {
	t.Helper()
	document, err := decodeDocument([]byte(payload), "application/json")
	if err != nil {
		t.Fatalf("decodeDocument() error = %v", err)
	}
	return document
}

func TestBuiltinAdaptersRejectDeliveriesOverRecordCap(t *testing.T) {
	over := maxRecordsPerBatch + 1
	nestedTrivy := `{"SchemaVersion":2,"ArtifactName":"a","Results":[` +
		repeatedJSON(`{"Target":"t","Vulnerabilities":[`+repeatedJSON(`{"VulnerabilityID":"CVE-2024-0001"}`, 200)+`]}`, over/200+1) + `]}`
	cases := map[string]struct {
		format  string
		payload string
	}{
		"strix non-objects": {FormatStrix, `[{"scan_id":"s","display_number":1},` + repeatedJSON("1", over) + `]`},
		"native":            {FormatNative, `{"schema":"cerebro.vulnerability/v1","observations":[` + repeatedJSON("1", over) + `]}`},
		"sarif":             {FormatSARIF, `{"version":"2.1.0","runs":[{"results":[` + repeatedJSON("1", over) + `]}]}`},
		"cyclonedx":         {FormatCycloneDX, `{"bomFormat":"CycloneDX","vulnerabilities":[` + repeatedJSON("1", over) + `]}`},
		"cyclonedx affects": {FormatCycloneDX, `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2024-0001","affects":[` + repeatedJSON(`{"ref":"x"}`, over) + `]}]}`},
		"osv":               {FormatOSV, `{"results":[{"packages":[{"package":{"name":"p"},"vulnerabilities":[` + repeatedJSON(`{"id":"GO-1"}`, over) + `]}]}]}`},
		"trivy nested":      {FormatTrivy, nestedTrivy},
		"trivy misconfigs":  {FormatTrivy, `{"SchemaVersion":2,"Results":[{"Target":"t","Misconfigurations":[` + repeatedJSON(`{"ID":"AVD-1","Status":"FAIL"}`, over) + `]}]}`},
		"grype non-objects": {FormatGrype, `{"descriptor":{"name":"grype"},"matches":[` + repeatedJSON("1", over) + `]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			drafts, err := normalizeBuiltin(tc.format, mustDecode(t, tc.payload))
			if !errors.Is(err, errTooManyRecords) || drafts != nil {
				t.Fatalf("normalizeBuiltin() = %d drafts, %v; want errTooManyRecords", len(drafts), err)
			}
		})
	}
}

func TestBuiltinAdaptersAcceptDeliveriesAtRecordCap(t *testing.T) {
	payload := `[{"scan_id":"s","display_number":1},` + repeatedJSON("1", maxRecordsPerBatch-1) + `]`
	drafts, err := normalizeBuiltin(FormatStrix, mustDecode(t, payload))
	if err != nil || len(drafts) != maxRecordsPerBatch {
		t.Fatalf("normalizeBuiltin() = %d drafts, %v", len(drafts), err)
	}
}

func TestGenericMappingRejectsDeliveriesOverRecordCap(t *testing.T) {
	mapping := &Mapping{Fields: map[string]FieldRule{FieldTitle: {Paths: []string{"title"}}}}
	document := mustDecode(t, `[`+repeatedJSON("1", maxRecordsPerBatch+1)+`]`)
	if drafts, err := mapping.apply(document); !errors.Is(err, errTooManyRecords) {
		t.Fatalf("apply() = %d drafts, %v; want errTooManyRecords", len(drafts), err)
	}
	wildcard := &Mapping{RecordsPath: "findings[*]", Fields: mapping.Fields}
	document = mustDecode(t, `{"findings":[`+repeatedJSON("1", maxRecordsPerBatch+1)+`]}`)
	if drafts, err := wildcard.apply(document); !errors.Is(err, errTooManyRecords) {
		t.Fatalf("wildcard apply() = %d drafts, %v; want errTooManyRecords", len(drafts), err)
	}
}

func TestRecordsPathWildcardIsNotTruncatedToFieldValueLimit(t *testing.T) {
	records := make([]string, 0, 1000)
	for i := range 1000 {
		records = append(records, fmt.Sprintf(`{"id":"r-%d","title":"finding %d"}`, i, i))
	}
	document := mustDecode(t, `{"findings":[`+strings.Join(records, ",")+`]}`)
	mapping := &Mapping{RecordsPath: "findings[*]", Fields: map[string]FieldRule{FieldSourceRecordID: {Paths: []string{"id"}}, FieldTitle: {Paths: []string{"title"}}}}
	drafts, err := mapping.apply(document)
	if err != nil || len(drafts) != 1000 {
		t.Fatalf("apply() = %d drafts, %v; want 1000", len(drafts), err)
	}
	if got := len(resolveStrings(document, "findings[*].id")); got != maxResolvedValues {
		t.Fatalf("field value resolution = %d values, want the %d cap", got, maxResolvedValues)
	}
}

func TestIngestRejectsOversizedDeliveryWithoutResolvingSnapshot(t *testing.T) {
	service, store := newTestService(t)
	mustCreateProfile(t, service, ProfileInput{SourceID: "strix"})
	ctx := context.Background()
	if _, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(strixPage), FullSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	payload := `[{"scan_id":"s","display_number":1,"id":"v-1","title":"t"},` + repeatedJSON("1", maxRecordsPerBatch) + `]`
	result, err := service.Ingest(ctx, IngestRequest{TenantID: "tenant-a", ProfileID: "strix", Payload: []byte(payload), FullSnapshot: true})
	if !errors.Is(err, ErrInvalidPayload) || !errors.Is(err, errTooManyRecords) {
		t.Fatalf("Ingest() error = %v, want ErrInvalidPayload wrapping errTooManyRecords", err)
	}
	if result == nil || result.Status != BatchFailed || result.Resolved != 0 {
		t.Fatalf("result = %+v", result)
	}
	for _, observation := range store.ObservationsFor("strix") {
		if observation.SourceRecordID == "v-1" && observation.ResolvedAt != nil {
			t.Fatalf("rejected delivery resolved an observation: %+v", observation)
		}
	}
}

func TestPreviewRejectsDeliveriesOverRecordCap(t *testing.T) {
	service, _ := newTestService(t)
	payload := []byte(`[` + repeatedJSON(`{"x":1}`, maxRecordsPerBatch+1) + `]`)
	if _, err := service.Preview(PreviewRequest{Payload: payload}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Preview() error = %v, want ErrInvalidPayload", err)
	}
	mappingJSON := `{"fields":{"title":{"paths":["title"]}}}`
	if _, err := service.Preview(PreviewRequest{Payload: payload, MappingJSON: mappingJSON}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Preview(mapping) error = %v, want ErrInvalidPayload", err)
	}
}

func TestDecodeDocumentRejectsPathologicalValueCounts(t *testing.T) {
	payload := `[` + repeatedJSON("1", maxDocumentValues) + `]`
	if _, err := decodeDocument([]byte(payload), "application/json"); !errors.Is(err, errTooManyValues) {
		t.Fatalf("decodeDocument() error = %v, want value-count rejection", err)
	}
	if got := countJSONValues([]byte(`{"a":"x,y[{","b":[1,2],"c":"\"],"}`)); got != 6 {
		t.Fatalf("countJSONValues() = %d, want 6 (string contents ignored)", got)
	}
}

func TestScoresRejectNaNAndInf(t *testing.T) {
	for _, raw := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "Infinity", "11", "-1"} {
		if got := number(raw); got != nil {
			t.Errorf("number(%q) = %v, want nil", raw, *got)
		}
		if got := number(json.Number(raw)); got != nil {
			t.Errorf("number(json.Number(%q)) = %v, want nil", raw, *got)
		}
		if draft := draftFromValues(map[string][]string{FieldCVSSScore: {raw}}); draft.Observation.CVSSScore != nil {
			t.Errorf("draftFromValues(%q) score = %v, want nil", raw, *draft.Observation.CVSSScore)
		}
	}
	if got := number(math.NaN()); got != nil {
		t.Errorf("number(NaN float) = %v", *got)
	}
	osv := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"p","ecosystem":"Go"},"groups":[{"ids":["GO-1"],"max_severity":"NaN"}],"vulnerabilities":[{"id":"GO-1"}]}]}]}`
	drafts, err := normalizeBuiltin(FormatOSV, mustDecode(t, osv))
	if err != nil || len(drafts) != 1 || drafts[0].Observation.CVSSScore != nil {
		t.Fatalf("osv NaN severity drafts = %+v, %v", drafts, err)
	}

	nan := math.NaN()
	draft := Draft{}
	draft.Observation.Title = "t"
	draft.Observation.CVSSScore = &nan
	observation, problem := finalizeDraft(draft, finalizeContext{TenantID: "t", ProfileID: "p", IngestedAt: time.Now()})
	if problem != "" || observation.CVSSScore != nil {
		t.Fatalf("finalizeDraft() = %+v, %q; want NaN score dropped", observation, problem)
	}
	if _, err := json.Marshal(observation); err != nil {
		t.Fatalf("finalized observation must marshal: %v", err)
	}
}

func TestNormalizeVulnerabilityIDsCleansAndFilters(t *testing.T) {
	got := NormalizeVulnerabilityIDs([]string{"OSV-\u0000x", "ghsa-ABCD-efgh-2345", "cve-2024-1234", "bad\u0007", "<script>", "RHSA-2024:1234", strings.Repeat("A", 200)})
	want := []string{"CVE-2024-1234", "GHSA-abcd-efgh-2345", "OSV-x", "bad", "RHSA-2024:1234"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("NormalizeVulnerabilityIDs() = %v, want %v", got, want)
	}
	for _, id := range got {
		if strings.ContainsRune(id, 0) {
			t.Fatalf("id %q still contains NUL", id)
		}
	}
}

func TestFinalizeQuarantinesUnstorableText(t *testing.T) {
	draft := Draft{}
	draft.Observation.Title = "t\u0000itle"
	draft.Observation.VulnerabilityIDs = []string{"OSV-\u0000x"}
	draft.Observation.Attributes = map[string]string{"k\u0000": "v\u0000"}
	observation, problem := finalizeDraft(draft, finalizeContext{TenantID: "t", ProfileID: "p", IngestedAt: time.Now()})
	if problem != "" || !storableText(*observation) {
		t.Fatalf("finalizeDraft() = %+v, %q; want cleaned observation", observation, problem)
	}
	if storableText(ports.VulnerabilityObservation{SourceRecordID: "a\u0000b"}) {
		t.Fatal("storableText() accepted a NUL byte")
	}
	if storableText(ports.VulnerabilityObservation{Attributes: map[string]string{"k": "\xff"}}) {
		t.Fatal("storableText() accepted invalid UTF-8")
	}
}

func TestLearnedValueMapsAreBounded(t *testing.T) {
	records := []map[string][]string{}
	for i := range 100 {
		records = append(records, map[string][]string{"sev": {"weird-" + strconv.Itoa(i)}, "state": {"odd-" + strconv.Itoa(i)}})
	}
	records = append(records, map[string][]string{"sev": {strings.Repeat("x", 200)}, "state": {strings.Repeat("y", 200)}})
	_, severities, capped := learnSeverity(records, "sev")
	if !capped || len(severities) != maxLearnedValues {
		t.Fatalf("learnSeverity() = %d values, capped %v", len(severities), capped)
	}
	statuses, capped := learnStatus(records, "state")
	if !capped || len(statuses) != maxLearnedValues {
		t.Fatalf("learnStatus() = %d values, capped %v", len(statuses), capped)
	}
	for value := range severities {
		if len(value) > maxLearnedValueBytes {
			t.Fatalf("learned an oversized severity value %q", value)
		}
	}

	rows := []string{}
	for i := range maxInferenceSamples {
		severity, status := "high", "open"
		// A minority of unrecognized values keeps the fields recognizable by shape.
		if i%3 == 0 {
			severity, status = "weird-"+strconv.Itoa(i), "odd-"+strconv.Itoa(i)
		}
		rows = append(rows, fmt.Sprintf(`{"id":"r-%d","title":"Finding number %d","severity":%q,"status":%q}`, i, i, severity, status))
	}
	mapping, report := inferMapping(mustDecode(t, `[`+strings.Join(rows, ",")+`]`))
	if len(mapping.SeverityValues) > maxLearnedValues || len(mapping.StatusValues) > maxLearnedValues {
		t.Fatalf("inferred value maps not bounded: %d severity, %d status", len(mapping.SeverityValues), len(mapping.StatusValues))
	}
	if !strings.Contains(strings.Join(report.Warnings, "\n"), "severity_values") {
		t.Fatalf("report warnings = %v, want a capped severity warning", report.Warnings)
	}
	if err := mapping.Validate(); err != nil {
		t.Fatalf("learned mapping must validate: %v", err)
	}
}

func TestMappingValidateEnforcesSizeLimits(t *testing.T) {
	base := func() *Mapping {
		return &Mapping{Fields: map[string]FieldRule{FieldTitle: {Paths: []string{"title"}}}}
	}
	tooManySeverities := base()
	tooManySeverities.SeverityValues = map[string]string{}
	for i := range maxValueMapEntries + 1 {
		tooManySeverities.SeverityValues["v"+strconv.Itoa(i)] = SeverityLow
	}
	longStatusKey := base()
	longStatusKey.StatusValues = map[string]string{strings.Repeat("s", maxValueMapKeyBytes+1): StatusOpen}
	longDefault := base()
	longDefault.Defaults = map[string]string{FieldScanner: strings.Repeat("d", maxDefaultValueBytes+1)}
	oversized := base()
	paths := []string{}
	for range 8 {
		paths = append(paths, strings.Repeat("p", 9000))
	}
	oversized.Fields[FieldDescription] = FieldRule{Paths: paths}
	for name, mapping := range map[string]*Mapping{"severity entries": tooManySeverities, "status key": longStatusKey, "default value": longDefault, "json size": oversized} {
		if err := mapping.Validate(); !errors.Is(err, ErrInvalidMapping) {
			t.Errorf("%s: Validate() = %v, want ErrInvalidMapping", name, err)
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline Validate() = %v", err)
	}
}

func TestInferMappingWideRecordsIsFast(t *testing.T) {
	rows := make([]string, 0, 200)
	for record := range 200 {
		fields := make([]string, 0, 256)
		for key := range 256 {
			fields = append(fields, fmt.Sprintf(`"k_%d_%d":"value %d"`, record, key, key))
		}
		rows = append(rows, "{"+strings.Join(fields, ",")+"}")
	}
	document := mustDecode(t, `[`+strings.Join(rows, ",")+`]`)
	start := time.Now()
	_, report := inferMapping(document)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("inferMapping() took %v on 200x256 unique keys", elapsed)
	}
	if !strings.Contains(strings.Join(report.Warnings, "\n"), "distinct fields") {
		t.Fatalf("report warnings = %v, want a capped path warning", report.Warnings)
	}
}

func TestInferMappingIsDeterministic(t *testing.T) {
	document := mustDecode(t, `[{"id":"1","name":"Thing one","displayname":"x","category":"package","scanner":"s","status":"open","severity":"high"},
		{"id":"2","name":"Thing two","displayname":"y","category":"package","scanner":"s","status":"open","severity":"low"}]`)
	first, _ := inferMapping(document)
	for range 20 {
		again, _ := inferMapping(document)
		if again.JSON() != first.JSON() {
			t.Fatalf("inferMapping() is nondeterministic:\n%s\n%s", first.JSON(), again.JSON())
		}
	}
}

func TestSourceRecordIdentityDoesNotCollide(t *testing.T) {
	if recordKey("a", "", "x") == recordKey("", "a", "x") {
		t.Fatal("empty parts must keep their position")
	}
	if recordKey("a|b", "c") == recordKey("a", "b|c") {
		t.Fatal("separator inside a part must not collide")
	}
	if recordKey("a\\", "b") == recordKey("a", "\\b") {
		t.Fatal("escape character inside a part must not collide")
	}
	if recordKey("", "") != "" {
		t.Fatal("all-empty parts must yield an empty key so finalize derives one")
	}
	if key := recordKey(strings.Repeat("x", 600), "y"); len(key) > maxShortFieldBytes || !strings.HasPrefix(key, "key:") {
		t.Fatalf("long key = %q, want hashed", key)
	}

	grype := `{"descriptor":{"name":"grype"},"source":{"type":"image","target":{"userInput":"acme/api"}},"matches":[
		{"vulnerability":{"id":"CVE-2021-44228"},"artifact":{"name":"log4j","version":"2.14.1","purl":"pkg:maven/log4j@2.14.1","locations":[{"path":"/app/a.jar"}]}},
		{"vulnerability":{"id":"CVE-2021-44228"},"artifact":{"name":"log4j","version":"2.14.1","purl":"pkg:maven/log4j@2.14.1","locations":[{"path":"/app/b.jar"}]}}]}`
	trivy := `{"SchemaVersion":2,"ArtifactName":"repo","Results":[{"Target":"main.tf","Misconfigurations":[
		{"ID":"AVD-AWS-0086","Status":"FAIL","CauseMetadata":{"Resource":"aws_s3_bucket.a","StartLine":1}},
		{"ID":"AVD-AWS-0086","Status":"FAIL","CauseMetadata":{"Resource":"aws_s3_bucket.b","StartLine":9}}]}]}`
	for name, tc := range map[string]struct{ format, payload string }{"grype": {FormatGrype, grype}, "trivy misconfig": {FormatTrivy, trivy}} {
		drafts, err := normalizeBuiltin(tc.format, mustDecode(t, tc.payload))
		if err != nil || len(drafts) != 2 {
			t.Fatalf("%s: normalizeBuiltin() = %d drafts, %v", name, len(drafts), err)
		}
		if drafts[0].Observation.SourceRecordID == drafts[1].Observation.SourceRecordID {
			t.Fatalf("%s: distinct findings share source record id %q", name, drafts[0].Observation.SourceRecordID)
		}
	}
}
