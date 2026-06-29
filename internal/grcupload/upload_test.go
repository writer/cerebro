package grcupload

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestBuildEventsBuildsPolicyAndDocumentEvents(t *testing.T) {
	now := time.Date(2026, 6, 28, 10, 30, 0, 0, time.UTC)
	events, response, err := BuildEvents(UploadRequest{
		Target:      TargetPolicy,
		TenantID:    "tenant-1",
		SourceID:    "upload-source",
		RuntimeID:   "runtime-1",
		ActorUserID: "user-1",
		FileName:    "Access Policy.pdf",
		ContentType: "application/pdf",
		FileSize:    42,
		Fields: map[string]string{
			"policy_id":          "access-policy",
			"title":              "Access Policy",
			"owner_id":           "owner-1",
			"next_review_due_at": "2026-12-31",
			"ignored":            "drop-me",
		},
	}, ParsedDocument{
		ProviderFileID:    "file-1",
		ParseID:           "parse-1",
		Status:            "completed",
		TextPreview:       "  Access   policy body.  ",
		ChunkCount:        4,
		PageCount:         2,
		StructureStatus:   "structured",
		StructureSchema:   "grc_upload_v1",
		StructuredSummary: "Access policy summary",
		StructuredFields: []StructuredField{
			{Key: "summary", Label: "Summary", Value: "Access policy summary"},
			{Key: "owner", Value: "Owner 1"},
		},
	}, now)
	if err != nil {
		t.Fatalf("BuildEvents() error = %v", err)
	}
	if response.Target != string(TargetPolicy) || response.ReductoFileID != "file-1" || response.ReductoParseID != "parse-1" {
		t.Fatalf("response = %#v", response)
	}
	if response.TextPreview != "Access policy body." || response.ChunkCount != 4 || response.PageCount != 2 {
		t.Fatalf("parsed response fields = %#v", response)
	}
	if response.StructureStatus != "structured" || response.StructureSchema != "grc_upload_v1" || response.StructuredSummary != "Access policy summary" || len(response.StructuredFields) != 2 {
		t.Fatalf("structured response fields = %#v", response)
	}
	if len(events) != 2 || len(response.Events) != 2 {
		t.Fatalf("events length = %d, response refs = %d, want 2", len(events), len(response.Events))
	}

	policy := events[0]
	if policy.GetKind() != "grc.policy" || policy.GetSchemaRef() != SchemaRefPolicy || response.Events[0].RecordID != "access-policy" {
		t.Fatalf("policy event = %#v, ref = %#v", policy, response.Events[0])
	}
	if response.Events[0].RecordURN != "urn:cerebro:tenant-1:policy:cerebro_upload:access-policy" {
		t.Fatalf("policy record_urn = %q", response.Events[0].RecordURN)
	}
	if got := policy.GetAttributes()["record_urn"]; got != response.Events[0].RecordURN {
		t.Fatalf("policy record_urn attr = %q, want response value", got)
	}
	if got := policy.GetAttributes()["policy_id"]; got != "access-policy" {
		t.Fatalf("policy_id attr = %q, want access-policy", got)
	}
	if got := policy.GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "runtime-1" {
		t.Fatalf("runtime attr = %q, want runtime-1", got)
	}
	if got := policy.GetAttributes()["parsed_text_preview"]; got != "Access policy body." {
		t.Fatalf("parsed_text_preview = %q", got)
	}
	if got := policy.GetAttributes()["structured_summary"]; got != "Access policy summary" {
		t.Fatalf("structured_summary = %q", got)
	}
	if got := policy.GetAttributes()["structured_field_count"]; got != "2" {
		t.Fatalf("structured_field_count = %q", got)
	}
	if _, ok := policy.GetAttributes()["ignored"]; ok {
		t.Fatal("policy event included unapproved upload field")
	}

	document := events[1]
	if document.GetKind() != "grc.document" || document.GetSchemaRef() != SchemaRefDocument || response.Events[1].RecordID == "" {
		t.Fatalf("document event = %#v, ref = %#v", document, response.Events[1])
	}
	wantDocumentURN := "urn:cerebro:tenant-1:document:cerebro_upload:" + response.Events[1].RecordID
	if response.Events[1].RecordURN != wantDocumentURN {
		t.Fatalf("document record_urn = %q, want %q", response.Events[1].RecordURN, wantDocumentURN)
	}
	if got := document.GetAttributes()["policy_id"]; got != "access-policy" {
		t.Fatalf("document policy_id = %q, want access-policy", got)
	}
	if got := document.GetAttributes()["document_type"]; got != "policy" {
		t.Fatalf("document_type = %q, want policy", got)
	}
	if _, ok := document.GetAttributes()["legacy_record_urn"]; ok {
		t.Fatal("document included legacy_record_urn for unchanged encoding")
	}
	if got := document.GetAttributes()["owner_id"]; got != "owner-1" {
		t.Fatalf("owner_id = %q, want owner-1", got)
	}

	var payload map[string]any
	if err := json.Unmarshal(document.GetPayload(), &payload); err != nil {
		t.Fatalf("decode document payload: %v", err)
	}
	if payload["parsed"] != true || payload["file_name"] != "Access Policy.pdf" {
		t.Fatalf("document payload = %#v", payload)
	}
}

func TestBuildEventsBuildsVendorAndAssuranceDocumentEvents(t *testing.T) {
	now := time.Date(2026, 6, 28, 10, 30, 0, 0, time.UTC)
	events, response, err := BuildEvents(UploadRequest{
		Target:    TargetVendor,
		TenantID:  "tenant-1",
		SourceID:  "upload-source",
		RuntimeID: "runtime-1",
		FileName:  "Contoso SOC 2.pdf",
		Fields: map[string]string{
			"vendor_id":     "contoso",
			"vendor_name":   "Contoso",
			"document_type": "soc2",
			"website_url":   "https://contoso.example",
		},
	}, ParsedDocument{
		ProviderFileID: "file-2",
		ParseID:        "parse-2",
		Status:         "completed",
		TextPreview:    "SOC 2 report",
		ChunkCount:     3,
	}, now)
	if err != nil {
		t.Fatalf("BuildEvents() error = %v", err)
	}
	if response.Target != string(TargetVendor) || response.UploadID == "" {
		t.Fatalf("response = %#v", response)
	}
	if len(events) != 2 {
		t.Fatalf("events length = %d, want 2", len(events))
	}

	vendor := events[0]
	if vendor.GetKind() != "grc.vendor" || vendor.GetSchemaRef() != SchemaRefVendor || response.Events[0].RecordID != "contoso" {
		t.Fatalf("vendor event = %#v, ref = %#v", vendor, response.Events[0])
	}
	if response.Events[0].RecordURN != "urn:cerebro:tenant-1:vendor:cerebro_upload:contoso" {
		t.Fatalf("vendor record_urn = %q", response.Events[0].RecordURN)
	}
	if got := vendor.GetAttributes()["vendor_name"]; got != "Contoso" {
		t.Fatalf("vendor_name = %q, want Contoso", got)
	}
	if got := vendor.GetAttributes()["website_url"]; got != "https://contoso.example" {
		t.Fatalf("website_url = %q, want configured value", got)
	}

	document := events[1]
	if document.GetKind() != "grc.assurance_document" || document.GetSchemaRef() != SchemaRefAssuranceDocument {
		t.Fatalf("assurance document event = %#v", document)
	}
	if response.Events[1].RecordURN == "" {
		t.Fatal("assurance document record_urn is empty")
	}
	if got := document.GetAttributes()["vendor_id"]; got != "contoso" {
		t.Fatalf("document vendor_id = %q, want contoso", got)
	}
	if got := document.GetAttributes()["document_type"]; got != "soc2" {
		t.Fatalf("document_type = %q, want soc2", got)
	}
}

func TestBuildEventsReportsLegacyRecordURNWhenEncodingChanged(t *testing.T) {
	now := time.Date(2026, 6, 28, 10, 30, 0, 0, time.UTC)
	events, response, err := BuildEvents(UploadRequest{
		Target:   TargetPolicy,
		TenantID: "tenant-1",
		FileName: "Access Policy.pdf",
		Fields: map[string]string{
			"policy_id":   "Access Policy+Admin",
			"document_id": "Access Policy:v2",
		},
	}, ParsedDocument{}, now)
	if err != nil {
		t.Fatalf("BuildEvents() error = %v", err)
	}
	if got, want := response.Events[0].RecordURN, "urn:cerebro:tenant-1:policy:cerebro_upload:Access%20Policy+Admin"; got != want {
		t.Fatalf("policy record_urn = %q, want %q", got, want)
	}
	if got, want := response.Events[0].LegacyRecordURN, "urn:cerebro:tenant-1:policy:cerebro_upload:Access+Policy%2BAdmin"; got != want {
		t.Fatalf("policy legacy_record_urn = %q, want %q", got, want)
	}
	if got, want := events[0].GetAttributes()["legacy_record_urn"], response.Events[0].LegacyRecordURN; got != want {
		t.Fatalf("policy legacy_record_urn attr = %q, want %q", got, want)
	}
	if got, want := response.Events[1].RecordURN, "urn:cerebro:tenant-1:document:cerebro_upload:Access%20Policy%3Av2"; got != want {
		t.Fatalf("document record_urn = %q, want %q", got, want)
	}
	if got, want := response.Events[1].LegacyRecordURN, "urn:cerebro:tenant-1:document:cerebro_upload:Access+Policy%3Av2"; got != want {
		t.Fatalf("document legacy_record_urn = %q, want %q", got, want)
	}
	if got, want := events[1].GetAttributes()["legacy_record_urn"], response.Events[1].LegacyRecordURN; got != want {
		t.Fatalf("document legacy_record_urn attr = %q, want %q", got, want)
	}
}

func TestRecordURNEncodesRecordIDSegment(t *testing.T) {
	request := UploadRequest{TenantID: "tenant-1"}
	for _, tt := range []struct {
		name string
		kind string
		want string
	}{
		{
			name: "policy",
			kind: "grc.policy",
			want: "urn:cerebro:tenant-1:policy:cerebro_upload:ISO%3A27001%2F2022",
		},
		{
			name: "document",
			kind: "grc.document",
			want: "urn:cerebro:tenant-1:document:cerebro_upload:ISO%3A27001%2F2022",
		},
		{
			name: "vendor",
			kind: "grc.vendor",
			want: "urn:cerebro:tenant-1:vendor:cerebro_upload:ISO%3A27001%2F2022",
		},
		{
			name: "assurance document",
			kind: "grc.assurance_document",
			want: "urn:cerebro:tenant-1:assurance_document:cerebro_upload:ISO%3A27001%2F2022",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := recordURN(request, tt.kind, "ISO:27001/2022"); got != tt.want {
				t.Fatalf("recordURN() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStableUploadIDIgnoresParserIDsAndClock(t *testing.T) {
	request := normalizeRequest(UploadRequest{
		Target:      TargetPolicy,
		TenantID:    "tenant-1",
		SourceID:    "upload-source",
		RuntimeID:   "runtime-1",
		FileName:    "Access Policy.pdf",
		ContentType: "application/pdf",
		FileSize:    42,
		Fields: map[string]string{
			"policy_id": "access-policy",
			"upload_id": "caller-supplied-id",
		},
	})

	left := stableUploadID(request, ParsedDocument{ProviderFileID: "file-1"}, time.Date(2026, 6, 28, 10, 30, 0, 0, time.UTC))
	right := stableUploadID(request, ParsedDocument{ProviderFileID: "file-2"}, time.Date(2026, 6, 28, 10, 31, 0, 0, time.UTC))
	if left != right {
		t.Fatalf("stableUploadID() = %q then %q, want retry-stable ID", left, right)
	}
}

func TestBuildEventsRejectsMissingTenant(t *testing.T) {
	_, _, err := BuildEvents(UploadRequest{
		Target:   TargetPolicy,
		FileName: "policy.pdf",
	}, ParsedDocument{}, time.Now())
	if err == nil {
		t.Fatal("BuildEvents() error = nil, want error")
	}
}
