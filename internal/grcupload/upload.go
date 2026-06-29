package grcupload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	cerebrourn "github.com/writer/cerebro/internal/urn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultSourceID              = "grc"
	uploadProvider               = "cerebro_upload"
	maxStructuredFields          = 12
	maxStructuredFieldValueChars = 300
	maxStructuredSummaryChars    = 600

	SchemaRefPolicy            = "grc/policy/v1"
	SchemaRefDocument          = "grc/document/v1"
	SchemaRefVendor            = "grc/vendor/v1"
	SchemaRefAssuranceDocument = "grc/assurance_document/v1"
)

var (
	ErrInvalidRequest     = errors.New("invalid GRC upload request")
	ErrRuntimeUnavailable = errors.New("GRC upload runtime is unavailable")
	ErrRemote             = errors.New("GRC upload parser request failed")
)

type Target string

const (
	TargetPolicy Target = "policy"
	TargetVendor Target = "vendor"
)

type ParsedDocument struct {
	ProviderFileID    string
	ParseID           string
	Status            string
	TextPreview       string
	ChunkCount        int
	PageCount         int
	StructureStatus   string
	StructureSchema   string
	StructuredSummary string
	StructuredFields  []StructuredField
	Chunks            []ParsedChunk
}

type StructuredField struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
}

type ParsedChunk struct {
	Index       int    `json:"index"`
	Page        int    `json:"page,omitempty"`
	TextPreview string `json:"text_preview,omitempty"`
}

type UploadRequest struct {
	Target      Target
	TenantID    string
	SourceID    string
	RuntimeID   string
	ActorUserID string
	FileName    string
	ContentType string
	FileSize    int64
	FileSHA256  string
	Fields      map[string]string
}

type EventRef struct {
	EventID         string `json:"event_id"`
	EventKind       string `json:"event_kind"`
	SchemaRef       string `json:"schema_ref"`
	RecordID        string `json:"record_id,omitempty"`
	RecordURN       string `json:"record_urn,omitempty"`
	LegacyRecordURN string `json:"legacy_record_urn,omitempty"`
}

type UploadJobRef struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status,omitempty"`
}

type ParseArtifact struct {
	Provider       string        `json:"provider"`
	ProviderFileID string        `json:"provider_file_id,omitempty"`
	ParseID        string        `json:"parse_id,omitempty"`
	Status         string        `json:"status,omitempty"`
	TextPreview    string        `json:"text_preview,omitempty"`
	ChunkCount     int           `json:"chunk_count,omitempty"`
	PageCount      int           `json:"page_count,omitempty"`
	Chunks         []ParsedChunk `json:"chunks,omitempty"`
}

type ExtractedField struct {
	Name          string  `json:"name"`
	Value         string  `json:"value"`
	Source        string  `json:"source"`
	Confidence    float64 `json:"confidence,omitempty"`
	SourceSnippet string  `json:"source_snippet,omitempty"`
	ReviewState   string  `json:"review_state,omitempty"`
}

type ReviewItem struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	RecordKind    string `json:"record_kind,omitempty"`
	RecordID      string `json:"record_id,omitempty"`
	Field         string `json:"field,omitempty"`
	Value         string `json:"value,omitempty"`
	Reason        string `json:"reason"`
	Action        string `json:"action,omitempty"`
	SourceSnippet string `json:"source_snippet,omitempty"`
}

type QualityCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

type EntityMatchHint struct {
	RecordKind     string `json:"record_kind"`
	RecordID       string `json:"record_id"`
	MatchKey       string `json:"match_key"`
	Strategy       string `json:"strategy"`
	CandidateState string `json:"candidate_state"`
}

type ResponseIdentity struct {
	UploadID    string `json:"upload_id"`
	Status      string `json:"status,omitempty"`
	Target      string `json:"target"`
	FileName    string `json:"file_name"`
	ContentType string `json:"content_type,omitempty"`
	FileSHA256  string `json:"file_sha256,omitempty"`
}

type ResponseParse struct {
	ReductoFileID  string         `json:"reducto_file_id,omitempty"`
	ReductoParseID string         `json:"reducto_parse_id,omitempty"`
	ParseStatus    string         `json:"parse_status,omitempty"`
	TextPreview    string         `json:"text_preview,omitempty"`
	ChunkCount     int            `json:"chunk_count,omitempty"`
	PageCount      int            `json:"page_count,omitempty"`
	ParseArtifact  *ParseArtifact `json:"parse_artifact,omitempty"`
}

type ResponseStructure struct {
	StructureStatus   string            `json:"structure_status,omitempty"`
	StructureSchema   string            `json:"structure_schema,omitempty"`
	StructuredSummary string            `json:"structured_summary,omitempty"`
	StructuredFields  []StructuredField `json:"structured_fields,omitempty"`
	ExtractedFields   []ExtractedField  `json:"extracted_fields,omitempty"`
}

type ResponseProjection struct {
	ProjectionStatus   string `json:"projection_status,omitempty"`
	ProjectionFailures int    `json:"projection_failures,omitempty"`
}

type ResponseReview struct {
	ReviewState      string            `json:"review_state,omitempty"`
	QualityStatus    string            `json:"quality_status,omitempty"`
	Replayable       bool              `json:"replayable,omitempty"`
	Job              *UploadJobRef     `json:"job,omitempty"`
	ReviewItems      []ReviewItem      `json:"review_items,omitempty"`
	QualityChecks    []QualityCheck    `json:"quality_checks,omitempty"`
	EntityMatchHints []EntityMatchHint `json:"entity_match_hints,omitempty"`
}

type Response struct {
	ResponseIdentity
	ResponseParse
	ResponseStructure
	ResponseProjection
	ResponseReview
	Events      []EventRef `json:"events"`
	GeneratedAt time.Time  `json:"generated_at"`
}

func BuildEvents(request UploadRequest, parsed ParsedDocument, now time.Time) ([]*cerebrov1.EventEnvelope, Response, error) {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	request = normalizeRequest(request)
	if request.TenantID == "" {
		return nil, Response{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if request.FileName == "" {
		return nil, Response{}, fmt.Errorf("%w: file name is required", ErrInvalidRequest)
	}
	if request.SourceID == "" {
		request.SourceID = defaultSourceID
	}
	uploadID := NewUploadID(request)
	parsed.ProviderFileID = strings.TrimSpace(parsed.ProviderFileID)
	parsed.ParseID = strings.TrimSpace(parsed.ParseID)
	parsed.Status = strings.TrimSpace(parsed.Status)
	parsed.TextPreview = compactWhitespace(parsed.TextPreview)
	parsed.StructureStatus = strings.TrimSpace(parsed.StructureStatus)
	parsed.StructureSchema = strings.TrimSpace(parsed.StructureSchema)
	parsed.StructuredSummary = truncateRunes(compactWhitespace(parsed.StructuredSummary), maxStructuredSummaryChars)
	parsed.StructuredFields = sanitizeStructuredFields(parsed.StructuredFields)

	var specs []eventSpec
	switch request.Target {
	case TargetPolicy:
		specs = policyEventSpecs(request, parsed, uploadID, now)
	case TargetVendor:
		specs = vendorEventSpecs(request, parsed, uploadID, now)
	default:
		return nil, Response{}, fmt.Errorf("%w: target must be policy or vendor", ErrInvalidRequest)
	}
	if len(specs) == 0 {
		return nil, Response{}, fmt.Errorf("%w: no upload events were built", ErrInvalidRequest)
	}
	analysis := analyzeUpload(request, parsed, specs)
	analysisStatusAttrs := analysis.statusAttributes()
	for index := range specs {
		specs[index].Attrs = mergeAttrs(specs[index].Attrs, analysisStatusAttrs)
	}
	if len(specs) > 0 {
		index := artifactSpecIndex(specs)
		specs[index].Attrs = mergeAttrs(specs[index].Attrs, analysis.detailAttributes())
	}

	events := make([]*cerebrov1.EventEnvelope, 0, len(specs))
	refs := make([]EventRef, 0, len(specs))
	for index, spec := range specs {
		event, err := buildEvent(request, spec, uploadID, index, now)
		if err != nil {
			return nil, Response{}, err
		}
		events = append(events, event)
		refs = append(refs, EventRef{
			EventID:         event.GetId(),
			EventKind:       event.GetKind(),
			SchemaRef:       event.GetSchemaRef(),
			RecordID:        spec.RecordID,
			RecordURN:       spec.RecordURN,
			LegacyRecordURN: spec.LegacyRecordURN,
		})
	}
	return events, Response{
		ResponseIdentity: ResponseIdentity{
			UploadID:    uploadID,
			Status:      "events_built",
			Target:      string(request.Target),
			FileName:    request.FileName,
			ContentType: request.ContentType,
			FileSHA256:  request.FileSHA256,
		},
		ResponseParse: ResponseParse{
			ReductoFileID:  parsed.ProviderFileID,
			ReductoParseID: parsed.ParseID,
			ParseStatus:    parsed.Status,
			TextPreview:    parsed.TextPreview,
			ChunkCount:     parsed.ChunkCount,
			PageCount:      parsed.PageCount,
			ParseArtifact:  &analysis.artifact,
		},
		ResponseStructure: ResponseStructure{
			StructureStatus:   parsed.StructureStatus,
			StructureSchema:   parsed.StructureSchema,
			StructuredSummary: parsed.StructuredSummary,
			StructuredFields:  parsed.StructuredFields,
			ExtractedFields:   analysis.fields,
		},
		ResponseReview: ResponseReview{
			ReviewState:      analysis.reviewState,
			QualityStatus:    analysis.qualityStatus,
			Replayable:       true,
			ReviewItems:      analysis.reviewItems,
			QualityChecks:    analysis.qualityChecks,
			EntityMatchHints: analysis.matchHints,
		},
		Events:      refs,
		GeneratedAt: now,
	}, nil
}

type eventSpec struct {
	Kind            string
	SchemaRef       string
	RecordID        string
	RecordURN       string
	LegacyRecordURN string
	Attrs           map[string]string
}

func policyEventSpecs(request UploadRequest, parsed ParsedDocument, uploadID string, now time.Time) []eventSpec {
	title := firstNonEmpty(request.Fields["policy_name"], request.Fields["title"], titleFromFileName(request.FileName))
	policyID := firstNonEmpty(request.Fields["policy_id"], slug(title))
	documentTitle := firstNonEmpty(request.Fields["document_title"], title)
	documentID := firstNonEmpty(request.Fields["document_id"], uploadID)
	status := firstNonEmpty(request.Fields["status"], "uploaded")
	documentType := firstNonEmpty(request.Fields["document_type"], "policy")
	documentClass := firstNonEmpty(request.Fields["document_class"], "policy")

	common := commonAttrs(request, parsed, uploadID, now)
	policyAttrs := mergeAttrs(common, allowedAttrs(request.Fields), map[string]string{
		"policy_id":     policyID,
		"name":          title,
		"title":         title,
		"policy_name":   title,
		"status":        status,
		"policy_status": status,
	})
	documentAttrs := mergeAttrs(common, allowedAttrs(request.Fields), map[string]string{
		"document_id":          documentID,
		"title":                documentTitle,
		"document_title":       documentTitle,
		"document_type":        documentType,
		"document_class":       documentClass,
		"policy_document_type": documentType,
		"policy_id":            policyID,
		"policy_name":          title,
		"status":               status,
		"upload_status":        "parsed",
	})
	return []eventSpec{
		recordEventSpec(request, "grc.policy", SchemaRefPolicy, policyID, policyAttrs),
		recordEventSpec(request, "grc.document", SchemaRefDocument, documentID, documentAttrs),
	}
}

func vendorEventSpecs(request UploadRequest, parsed ParsedDocument, uploadID string, now time.Time) []eventSpec {
	name := firstNonEmpty(request.Fields["vendor_name"], request.Fields["name"], request.Fields["title"], titleFromFileName(request.FileName))
	vendorID := firstNonEmpty(request.Fields["vendor_id"], slug(name))
	documentTitle := firstNonEmpty(request.Fields["document_title"], request.Fields["title"], request.FileName)
	documentID := firstNonEmpty(request.Fields["assurance_document_id"], request.Fields["document_id"], uploadID)
	status := firstNonEmpty(request.Fields["status"], "active")
	documentType := firstNonEmpty(request.Fields["document_type"], "assurance_document")

	common := commonAttrs(request, parsed, uploadID, now)
	vendorAttrs := mergeAttrs(common, allowedAttrs(request.Fields), map[string]string{
		"vendor_id":     vendorID,
		"vendor_name":   name,
		"name":          name,
		"title":         name,
		"status":        status,
		"source_status": status,
	})
	documentAttrs := mergeAttrs(common, allowedAttrs(request.Fields), map[string]string{
		"assurance_document_id": documentID,
		"document_id":           documentID,
		"upload_id":             uploadID,
		"title":                 documentTitle,
		"name":                  documentTitle,
		"document_type":         documentType,
		"artifact_type":         documentType,
		"vendor_id":             vendorID,
		"vendor_name":           name,
		"status":                "uploaded",
		"upload_status":         "parsed",
	})
	return []eventSpec{
		recordEventSpec(request, "grc.vendor", SchemaRefVendor, vendorID, vendorAttrs),
		recordEventSpec(request, "grc.assurance_document", SchemaRefAssuranceDocument, documentID, documentAttrs),
	}
}

func recordEventSpec(request UploadRequest, kind string, schemaRef string, recordID string, attrs map[string]string) eventSpec {
	recordURN, legacyRecordURN := recordURNs(request, kind, recordID)
	return eventSpec{
		Kind:            kind,
		SchemaRef:       schemaRef,
		RecordID:        recordID,
		RecordURN:       recordURN,
		LegacyRecordURN: legacyRecordURN,
		Attrs:           attrs,
	}
}

func artifactSpecIndex(specs []eventSpec) int {
	for index, spec := range specs {
		switch spec.Kind {
		case "grc.document", "grc.assurance_document":
			return index
		}
	}
	return 0
}

func buildEvent(request UploadRequest, spec eventSpec, uploadID string, index int, now time.Time) (*cerebrov1.EventEnvelope, error) {
	attrs := map[string]string{}
	for key, value := range spec.Attrs {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			attrs[key] = value
		}
	}
	if request.RuntimeID != "" {
		attrs[ports.EventAttributeSourceRuntimeID] = request.RuntimeID
	}
	if spec.RecordURN != "" {
		attrs["record_urn"] = spec.RecordURN
	}
	if spec.LegacyRecordURN != "" {
		attrs["legacy_record_urn"] = spec.LegacyRecordURN
	}
	recordID := strings.TrimSpace(spec.RecordID)
	if recordID == "" {
		recordID = uploadID
	}
	attrs["source_event_id"] = firstNonEmpty(attrs["source_event_id"], eventID(request, spec.Kind, recordID, uploadID, index))
	payload := map[string]any{
		"upload_id":    uploadID,
		"record_id":    recordID,
		"record_kind":  spec.Kind,
		"file_name":    request.FileName,
		"content_type": request.ContentType,
		"parsed":       true,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode upload payload: %w", ErrInvalidRequest, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         attrs["source_event_id"],
		TenantId:   request.TenantID,
		SourceId:   request.SourceID,
		Kind:       spec.Kind,
		OccurredAt: timestamppb.New(now),
		SchemaRef:  spec.SchemaRef,
		Payload:    rawPayload,
		Attributes: attrs,
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return event, nil
}

func recordURN(request UploadRequest, kind string, recordID string) string {
	canonical, _ := recordURNs(request, kind, recordID)
	return canonical
}

func recordURNs(request UploadRequest, kind string, recordID string) (string, string) {
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		return "", ""
	}
	canonical := mintRecordURN(request, kind, cerebrourn.EncodeSegment(recordID))
	legacy := mintRecordURN(request, kind, url.QueryEscape(recordID))
	if legacy == canonical {
		legacy = ""
	}
	return canonical, legacy
}

func NewUploadID(request UploadRequest) string {
	request = normalizeRequest(request)
	if request.SourceID == "" {
		request.SourceID = defaultSourceID
	}
	return firstNonEmpty(request.Fields["upload_id"], stableUploadID(request))
}

func mintRecordURN(request UploadRequest, kind string, recordID string) string {
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		return ""
	}
	var urn string
	var err error
	switch kind {
	case "grc.policy":
		urn, err = cerebrourn.Mint(request.TenantID, "policy", uploadProvider, recordID)
	case "grc.document":
		urn, err = cerebrourn.Mint(request.TenantID, "document", uploadProvider, recordID)
	case "grc.vendor":
		urn, err = cerebrourn.Mint(request.TenantID, "vendor", uploadProvider, recordID)
	case "grc.assurance_document":
		urn, err = cerebrourn.Mint(request.TenantID, "assurance_document", uploadProvider, recordID)
	}
	if err != nil {
		return ""
	}
	return urn
}

func normalizeRequest(request UploadRequest) UploadRequest {
	request.Target = Target(strings.ToLower(strings.TrimSpace(string(request.Target))))
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	request.ActorUserID = strings.TrimSpace(request.ActorUserID)
	request.FileName = strings.TrimSpace(request.FileName)
	request.ContentType = strings.TrimSpace(request.ContentType)
	fields := map[string]string{}
	for key, value := range request.Fields {
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			fields[key] = value
		}
	}
	request.Fields = fields
	return request
}

func commonAttrs(request UploadRequest, parsed ParsedDocument, uploadID string, now time.Time) map[string]string {
	attrs := map[string]string{
		"provider":               uploadProvider,
		"source_system":          uploadProvider,
		"upload_id":              uploadID,
		"file_name":              request.FileName,
		"content_type":           request.ContentType,
		"uploaded_at":            now.Format(time.RFC3339),
		"parse_provider":         "reducto",
		"reducto_file_id":        parsed.ProviderFileID,
		"reducto_parse_id":       parsed.ParseID,
		"reducto_parse_status":   parsed.Status,
		"parsed_text_preview":    parsed.TextPreview,
		"parsed_chunk_count":     intString(parsed.ChunkCount),
		"parsed_page_count":      intString(parsed.PageCount),
		"structure_status":       parsed.StructureStatus,
		"structure_schema":       parsed.StructureSchema,
		"structured_summary":     parsed.StructuredSummary,
		"structured_field_count": intString(len(parsed.StructuredFields)),
		"uploaded_by_user_id":    request.ActorUserID,
		"created_by_user_id":     request.ActorUserID,
		"source_upload_surface":  "cerebro-web",
	}
	if request.FileSize > 0 {
		attrs["file_size_bytes"] = fmt.Sprintf("%d", request.FileSize)
	}
	if request.FileSHA256 != "" {
		attrs["file_sha256"] = request.FileSHA256
	}
	return attrs
}

type uploadAnalysis struct {
	artifact      ParseArtifact
	fields        []ExtractedField
	reviewItems   []ReviewItem
	qualityChecks []QualityCheck
	matchHints    []EntityMatchHint
	reviewState   string
	qualityStatus string
}

func analyzeUpload(request UploadRequest, parsed ParsedDocument, specs []eventSpec) uploadAnalysis {
	analysis := uploadAnalysis{
		artifact: parseArtifact(parsed),
	}
	snippet := truncateRunes(parsed.TextPreview, 240)
	for _, spec := range specs {
		switch spec.Kind {
		case "grc.policy":
			analysis.addField("policy_id", spec.RecordID, sourceFor(request.Fields, "policy_id", "derived"), 0.96, "")
			analysis.addField("policy_name", spec.Attrs["policy_name"], sourceForAny(request.Fields, []string{"policy_name", "title"}, "file_name"), 0.90, snippet)
			analysis.addField("owner_id", firstNonEmpty(spec.Attrs["owner_id"], spec.Attrs["policy_owner_user_id"]), sourceForAny(request.Fields, []string{"owner_id", "policy_owner_user_id"}, ""), 0.92, "")
			analysis.addField("next_review_due_at", firstNonEmpty(spec.Attrs["next_review_due_at"], spec.Attrs["review_due_at"]), sourceForAny(request.Fields, []string{"next_review_due_at", "review_due_at"}, ""), 0.88, "")
			analysis.addMatchHint(spec.Kind, spec.RecordID, normalizedMatchKey("policy", spec.Attrs["policy_name"], spec.RecordID), "policy_id_or_title")
			if firstNonEmpty(spec.Attrs["owner_id"], spec.Attrs["policy_owner_user_id"]) == "" {
				analysis.addReviewItem("policy_owner_missing", spec.Kind, spec.RecordID, "owner_id", "Policy owner is missing.", "Add an owner before relying on the policy for audit evidence.", snippet)
			}
			if firstNonEmpty(spec.Attrs["next_review_due_at"], spec.Attrs["review_due_at"]) == "" {
				analysis.addReviewItem("policy_review_due_missing", spec.Kind, spec.RecordID, "next_review_due_at", "Policy review date is missing.", "Add the next review date or review cadence.", snippet)
			}
		case "grc.document":
			analysis.addField("document_id", spec.RecordID, sourceFor(request.Fields, "document_id", "upload_id"), 0.94, "")
			analysis.addField("document_title", spec.Attrs["document_title"], sourceForAny(request.Fields, []string{"document_title", "title"}, "file_name"), 0.86, snippet)
			analysis.addField("document_type", spec.Attrs["document_type"], sourceFor(request.Fields, "document_type", "default"), 0.80, snippet)
			analysis.addMatchHint(spec.Kind, spec.RecordID, normalizedMatchKey("document", spec.Attrs["document_title"], spec.RecordID), "document_id_or_title")
		case "grc.vendor":
			analysis.addField("vendor_id", spec.RecordID, sourceFor(request.Fields, "vendor_id", "derived"), 0.96, "")
			analysis.addField("vendor_name", spec.Attrs["vendor_name"], sourceForAny(request.Fields, []string{"vendor_name", "name", "title"}, "file_name"), 0.90, snippet)
			analysis.addField("website_url", spec.Attrs["website_url"], sourceFor(request.Fields, "website_url", ""), 0.92, "")
			analysis.addField("risk_level", spec.Attrs["risk_level"], sourceFor(request.Fields, "risk_level", ""), 0.84, snippet)
			analysis.addMatchHint(spec.Kind, spec.RecordID, vendorMatchKey(spec.Attrs), "domain_or_vendor_name")
			if spec.Attrs["website_url"] == "" {
				analysis.addReviewItem("vendor_website_missing", spec.Kind, spec.RecordID, "website_url", "Vendor website is missing.", "Add the vendor domain so matching and ownership checks can use it.", snippet)
			}
			if spec.Attrs["risk_level"] == "" {
				analysis.addReviewItem("vendor_risk_level_missing", spec.Kind, spec.RecordID, "risk_level", "Vendor risk level is missing.", "Set the vendor risk level before using this record in review queues.", snippet)
			}
			if firstNonEmpty(spec.Attrs["security_owner_user_id"], spec.Attrs["business_owner_user_id"], spec.Attrs["owner_id"]) == "" {
				analysis.addReviewItem("vendor_owner_missing", spec.Kind, spec.RecordID, "owner_id", "Vendor owner is missing.", "Add a business or security owner.", snippet)
			}
		case "grc.assurance_document":
			analysis.addField("assurance_document_id", spec.RecordID, sourceForAny(request.Fields, []string{"assurance_document_id", "document_id"}, "upload_id"), 0.94, "")
			analysis.addField("document_type", spec.Attrs["document_type"], sourceFor(request.Fields, "document_type", "default"), 0.80, snippet)
			analysis.addMatchHint(spec.Kind, spec.RecordID, normalizedMatchKey("assurance_document", spec.Attrs["title"], spec.RecordID), "document_id_or_title")
		}
	}
	if parsed.TextPreview == "" {
		analysis.addReviewItem("parse_text_missing", "", "", "parsed_text_preview", "Parsed text preview is empty.", "Review the Reducto parse result before projecting extracted fields.", "")
		analysis.addQualityCheck("parse_text", "needs_review", "Parsed text preview is empty.", "Open the upload job and review the parser result.")
	} else {
		analysis.addQualityCheck("parse_text", "passed", "Parsed text preview is available.", "")
	}
	if parsed.ChunkCount == 0 {
		analysis.addQualityCheck("parse_chunks", "warning", "No parser chunks were reported.", "Check the parse artifact if field confidence is low.")
	} else {
		analysis.addQualityCheck("parse_chunks", "passed", "Parser chunks were reported.", "")
	}
	if len(specs) == 0 {
		analysis.addQualityCheck("events_built", "needs_review", "No upload events were built.", "Review the upload target and fields.")
	} else {
		analysis.addQualityCheck("events_built", "passed", "Upload events were built.", "")
	}
	analysis.reviewState = "ready_to_project"
	if len(analysis.reviewItems) > 0 {
		analysis.reviewState = "needs_review"
	}
	analysis.qualityStatus = "passed"
	for _, check := range analysis.qualityChecks {
		if check.Status == "needs_review" {
			analysis.qualityStatus = "needs_review"
			break
		}
		if check.Status == "warning" && analysis.qualityStatus == "passed" {
			analysis.qualityStatus = "warning"
		}
	}
	return analysis
}

func parseArtifact(parsed ParsedDocument) ParseArtifact {
	chunks := make([]ParsedChunk, 0, len(parsed.Chunks))
	for _, chunk := range parsed.Chunks {
		if len(chunks) >= 8 {
			break
		}
		chunk.TextPreview = truncateRunes(compactWhitespace(chunk.TextPreview), 240)
		if chunk.Index > 0 || chunk.Page > 0 || chunk.TextPreview != "" {
			chunks = append(chunks, chunk)
		}
	}
	return ParseArtifact{
		Provider:       "reducto",
		ProviderFileID: parsed.ProviderFileID,
		ParseID:        parsed.ParseID,
		Status:         parsed.Status,
		TextPreview:    parsed.TextPreview,
		ChunkCount:     parsed.ChunkCount,
		PageCount:      parsed.PageCount,
		Chunks:         chunks,
	}
}

func (a *uploadAnalysis) addField(name string, value string, source string, confidence float64, snippet string) {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return
	}
	reviewState := "ready_to_project"
	if source == "default" || source == "file_name" || source == "derived" || source == "upload_id" {
		reviewState = "needs_field_review"
	}
	a.fields = append(a.fields, ExtractedField{
		Name:          name,
		Value:         value,
		Source:        firstNonEmpty(source, "unknown"),
		Confidence:    confidence,
		SourceSnippet: strings.TrimSpace(snippet),
		ReviewState:   reviewState,
	})
}

func (a *uploadAnalysis) addReviewItem(id string, kind string, recordID string, field string, reason string, action string, snippet string) {
	a.reviewItems = append(a.reviewItems, ReviewItem{
		ID:            id,
		State:         "open",
		RecordKind:    kind,
		RecordID:      recordID,
		Field:         field,
		Reason:        reason,
		Action:        action,
		SourceSnippet: strings.TrimSpace(snippet),
	})
}

func (a *uploadAnalysis) addQualityCheck(id string, status string, message string, action string) {
	a.qualityChecks = append(a.qualityChecks, QualityCheck{
		ID:      id,
		Status:  status,
		Message: message,
		Action:  action,
	})
}

func (a *uploadAnalysis) addMatchHint(kind string, recordID string, matchKey string, strategy string) {
	matchKey = strings.TrimSpace(matchKey)
	if matchKey == "" {
		return
	}
	a.matchHints = append(a.matchHints, EntityMatchHint{
		RecordKind:     kind,
		RecordID:       recordID,
		MatchKey:       matchKey,
		Strategy:       strategy,
		CandidateState: "dedupe_candidate",
	})
}

func (a uploadAnalysis) statusAttributes() map[string]string {
	return map[string]string{
		"upload_review_state":   a.reviewState,
		"upload_quality_status": a.qualityStatus,
	}
}

func (a uploadAnalysis) detailAttributes() map[string]string {
	attrs := map[string]string{}
	if encoded := jsonAttribute(a.artifact); encoded != "" {
		attrs["parse_artifact_json"] = encoded
	}
	if len(a.fields) > 0 {
		if encoded := jsonAttribute(a.fields); encoded != "" {
			attrs["extracted_fields_json"] = encoded
		}
	}
	if len(a.reviewItems) > 0 {
		if encoded := jsonAttribute(a.reviewItems); encoded != "" {
			attrs["review_items_json"] = encoded
		}
	}
	if len(a.qualityChecks) > 0 {
		if encoded := jsonAttribute(a.qualityChecks); encoded != "" {
			attrs["quality_checks_json"] = encoded
		}
	}
	if len(a.matchHints) > 0 {
		if encoded := jsonAttribute(a.matchHints); encoded != "" {
			attrs["entity_match_hints_json"] = encoded
		}
	}
	keys := make([]string, 0, len(a.matchHints))
	for _, hint := range a.matchHints {
		if strings.TrimSpace(hint.MatchKey) != "" {
			keys = append(keys, hint.MatchKey)
		}
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		attrs["entity_match_keys"] = strings.Join(keys, ",")
	}
	return attrs
}

func allowedAttrs(fields map[string]string) map[string]string {
	allowed := map[string]struct{}{
		"approved_at": {}, "business_owner_user_id": {}, "category": {}, "control_id": {},
		"control_ids": {}, "data_sensitivity": {}, "document_url": {}, "domain": {},
		"due_at": {}, "effective_at": {}, "framework": {}, "frameworks": {},
		"lifecycle_reason": {}, "lifecycle_state": {}, "next_review_due_at": {},
		"owner_id": {}, "policy_owner_user_id": {}, "review_cadence": {},
		"review_due_at": {}, "reviewer": {}, "reviewer_user_id": {},
		"risk_level": {}, "security_owner_user_id": {}, "services_provided": {},
		"source_url": {}, "tags": {}, "url": {}, "version": {}, "version_number": {},
		"website": {}, "website_url": {},
	}
	attrs := map[string]string{}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := allowed[key]; !ok {
			continue
		}
		attrs[key] = fields[key]
	}
	return attrs
}

func mergeAttrs(groups ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, group := range groups {
		for key, value := range group {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				merged[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
	}
	return merged
}

func stableUploadID(request UploadRequest) string {
	parts := []string{
		string(request.Target),
		request.TenantID,
		request.SourceID,
		request.RuntimeID,
		request.FileName,
		request.ContentType,
		fmt.Sprintf("%d", request.FileSize),
	}
	keys := make([]string, 0, len(request.Fields))
	for key := range request.Fields {
		if key != "upload_id" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key, request.Fields[key])
	}
	seed := strings.Join(parts, "\x00")
	return "upload-" + shortHash(seed, 16)
}

func eventID(request UploadRequest, kind string, recordID string, uploadID string, index int) string {
	seed := strings.Join([]string{
		request.TenantID,
		request.SourceID,
		request.RuntimeID,
		kind,
		recordID,
		uploadID,
		fmt.Sprintf("%d", index),
	}, "\x00")
	return "grc-upload-" + shortHash(seed, 16)
}

func shortHash(value string, chars int) string {
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	if chars > len(encoded) {
		chars = len(encoded)
	}
	return encoded[:chars]
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, value)
	mapped = strings.Trim(mapped, "-")
	for strings.Contains(mapped, "--") {
		mapped = strings.ReplaceAll(mapped, "--", "-")
	}
	if mapped == "" {
		return "upload"
	}
	return mapped
}

func titleFromFileName(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return "Uploaded document"
	}
	if dot := strings.LastIndex(fileName, "."); dot > 0 {
		fileName = fileName[:dot]
	}
	fileName = strings.ReplaceAll(fileName, "_", " ")
	fileName = strings.ReplaceAll(fileName, "-", " ")
	return compactWhitespace(fileName)
}

func compactWhitespace(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func truncateRunes(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func intString(value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func sanitizeStructuredFields(fields []StructuredField) []StructuredField {
	if len(fields) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	sanitized := make([]StructuredField, 0, min(len(fields), maxStructuredFields))
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		value := truncateRunes(compactWhitespace(field.Value), maxStructuredFieldValueChars)
		if key == "" || value == "" {
			continue
		}
		normalizedKey := strings.ToLower(key)
		if _, ok := seen[normalizedKey]; ok {
			continue
		}
		seen[normalizedKey] = struct{}{}
		sanitized = append(sanitized, StructuredField{
			Key:   key,
			Label: compactWhitespace(field.Label),
			Value: value,
		})
		if len(sanitized) >= maxStructuredFields {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sourceFor(fields map[string]string, key string, fallback string) string {
	if strings.TrimSpace(fields[strings.TrimSpace(key)]) != "" {
		return "form"
	}
	return strings.TrimSpace(fallback)
}

func sourceForAny(fields map[string]string, keys []string, fallback string) string {
	for _, key := range keys {
		if strings.TrimSpace(fields[strings.TrimSpace(key)]) != "" {
			return "form"
		}
	}
	return strings.TrimSpace(fallback)
}

func normalizedMatchKey(prefix string, values ...string) string {
	for _, value := range values {
		normalized := slug(value)
		if normalized != "" && normalized != "upload" {
			return strings.TrimSpace(prefix) + ":" + normalized
		}
	}
	return ""
}

func vendorMatchKey(attrs map[string]string) string {
	if host := hostFromURL(attrs["website_url"]); host != "" {
		return "vendor_domain:" + strings.ToLower(host)
	}
	return normalizedMatchKey("vendor", attrs["vendor_name"], attrs["name"], attrs["vendor_id"])
}

func hostFromURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		parsed, err = url.Parse("//" + value)
	}
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

func jsonAttribute(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}
