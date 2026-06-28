package grcupload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultSourceID = "grc"
	uploadProvider  = "cerebro_upload"

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
	ProviderFileID string
	ParseID        string
	Status         string
	TextPreview    string
	ChunkCount     int
	PageCount      int
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
	Fields      map[string]string
}

type EventRef struct {
	EventID   string `json:"event_id"`
	EventKind string `json:"event_kind"`
	SchemaRef string `json:"schema_ref"`
	RecordID  string `json:"record_id,omitempty"`
	RecordURN string `json:"record_urn,omitempty"`
}

type Response struct {
	UploadID       string     `json:"upload_id"`
	Target         string     `json:"target"`
	FileName       string     `json:"file_name"`
	ContentType    string     `json:"content_type,omitempty"`
	ReductoFileID  string     `json:"reducto_file_id,omitempty"`
	ReductoParseID string     `json:"reducto_parse_id,omitempty"`
	ParseStatus    string     `json:"parse_status,omitempty"`
	TextPreview    string     `json:"text_preview,omitempty"`
	ChunkCount     int        `json:"chunk_count,omitempty"`
	PageCount      int        `json:"page_count,omitempty"`
	Events         []EventRef `json:"events"`
	GeneratedAt    time.Time  `json:"generated_at"`
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
	uploadID := firstNonEmpty(request.Fields["upload_id"], stableUploadID(request, parsed, now))
	parsed.ProviderFileID = strings.TrimSpace(parsed.ProviderFileID)
	parsed.ParseID = strings.TrimSpace(parsed.ParseID)
	parsed.Status = strings.TrimSpace(parsed.Status)
	parsed.TextPreview = compactWhitespace(parsed.TextPreview)

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

	events := make([]*cerebrov1.EventEnvelope, 0, len(specs))
	refs := make([]EventRef, 0, len(specs))
	for index, spec := range specs {
		event, err := buildEvent(request, spec, uploadID, index, now)
		if err != nil {
			return nil, Response{}, err
		}
		events = append(events, event)
		refs = append(refs, EventRef{
			EventID:   event.GetId(),
			EventKind: event.GetKind(),
			SchemaRef: event.GetSchemaRef(),
			RecordID:  spec.RecordID,
			RecordURN: spec.RecordURN,
		})
	}
	return events, Response{
		UploadID:       uploadID,
		Target:         string(request.Target),
		FileName:       request.FileName,
		ContentType:    request.ContentType,
		ReductoFileID:  parsed.ProviderFileID,
		ReductoParseID: parsed.ParseID,
		ParseStatus:    parsed.Status,
		TextPreview:    parsed.TextPreview,
		ChunkCount:     parsed.ChunkCount,
		PageCount:      parsed.PageCount,
		Events:         refs,
		GeneratedAt:    now,
	}, nil
}

type eventSpec struct {
	Kind      string
	SchemaRef string
	RecordID  string
	RecordURN string
	Attrs     map[string]string
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
		{Kind: "grc.policy", SchemaRef: SchemaRefPolicy, RecordID: policyID, Attrs: policyAttrs},
		{Kind: "grc.document", SchemaRef: SchemaRefDocument, RecordID: documentID, Attrs: documentAttrs},
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
		{Kind: "grc.vendor", SchemaRef: SchemaRefVendor, RecordID: vendorID, Attrs: vendorAttrs},
		{Kind: "grc.assurance_document", SchemaRef: SchemaRefAssuranceDocument, RecordID: documentID, Attrs: documentAttrs},
	}
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
		"provider":              uploadProvider,
		"source_system":         uploadProvider,
		"upload_id":             uploadID,
		"file_name":             request.FileName,
		"content_type":          request.ContentType,
		"uploaded_at":           now.Format(time.RFC3339),
		"parse_provider":        "reducto",
		"reducto_file_id":       parsed.ProviderFileID,
		"reducto_parse_id":      parsed.ParseID,
		"reducto_parse_status":  parsed.Status,
		"parsed_text_preview":   parsed.TextPreview,
		"parsed_chunk_count":    intString(parsed.ChunkCount),
		"parsed_page_count":     intString(parsed.PageCount),
		"uploaded_by_user_id":   request.ActorUserID,
		"created_by_user_id":    request.ActorUserID,
		"source_upload_surface": "cerebro-web",
	}
	if request.FileSize > 0 {
		attrs["file_size_bytes"] = fmt.Sprintf("%d", request.FileSize)
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

func stableUploadID(request UploadRequest, parsed ParsedDocument, now time.Time) string {
	seed := strings.Join([]string{
		string(request.Target),
		request.TenantID,
		request.SourceID,
		request.RuntimeID,
		request.FileName,
		parsed.ProviderFileID,
		now.Format(time.RFC3339Nano),
	}, "\x00")
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
