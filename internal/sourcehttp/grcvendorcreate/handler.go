package grcvendorcreate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	cerebrourn "github.com/writer/cerebro/internal/urn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxGRCVendorCreateBodyBytes       = 32 << 10
	maxGRCVendorCreateAttributes      = 32
	maxGRCVendorCreateAttributeKey    = 128
	maxGRCVendorCreateAttributeLength = 1024
	maxGRCVendorCreateFieldLength     = 1024
	grcVendorEventSourceID            = "grc"
	grcVendorEventKind                = "grc.vendor"
	grcVendorEventSchemaRef           = "grc/vendor/v1"
)

type grcVendorCreateRequest struct {
	TenantID            string            `json:"tenant_id,omitempty"`
	WorkspaceID         string            `json:"workspace_id,omitempty"`
	Name                string            `json:"name"`
	VendorID            string            `json:"vendor_id,omitempty"`
	SourceID            string            `json:"source_id,omitempty"`
	RuntimeID           string            `json:"runtime_id,omitempty"`
	Provider            string            `json:"provider,omitempty"`
	Status              string            `json:"status,omitempty"`
	Category            string            `json:"category,omitempty"`
	WebsiteURL          string            `json:"website_url,omitempty"`
	ServicesProvided    string            `json:"services_provided,omitempty"`
	Owner               string            `json:"owner,omitempty"`
	SecurityOwnerUserID string            `json:"security_owner_user_id,omitempty"`
	BusinessOwnerUserID string            `json:"business_owner_user_id,omitempty"`
	LifecycleState      string            `json:"lifecycle_state,omitempty"`
	ReviewState         string            `json:"review_state,omitempty"`
	RiskLevel           string            `json:"risk_level,omitempty"`
	DiscoveryURN        string            `json:"discovery_urn,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
}

type createResponse struct {
	Vendor      grcvendor.Vendor `json:"vendor"`
	GeneratedAt time.Time        `json:"generated_at"`
}

type Scope struct {
	TenantID               string
	ApplicationWorkspaceID string
	RuntimeID              string
	SourceID               string
}

type Options struct {
	AppendLog       ports.AppendLog
	Projector       ports.SourceProjector
	ResolveScope    func(*http.Request) (Scope, error)
	AuthorizeTenant func(context.Context, string) error
	BumpCache       func(context.Context, string)
	WriteError      func(http.ResponseWriter, error)
	Now             func() time.Time
}

type Handler struct {
	options Options
}

func NewHandler(options Options) Handler {
	return Handler{options: options}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request grcVendorCreateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCVendorCreateBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		h.writeError(w, fmt.Errorf("%w: decode vendor request: %w", grcvendor.ErrInvalidRequest, err))
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("request body must contain one JSON object")
		}
		h.writeError(w, fmt.Errorf("%w: decode vendor request: %w", grcvendor.ErrInvalidRequest, err))
		return
	}

	request.normalize()
	scopeRequest := r
	if request.TenantID != "" && strings.TrimSpace(r.URL.Query().Get("tenant_id")) == "" && strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant")) == "" {
		clone := new(http.Request)
		*clone = *r
		clonedURL := *r.URL
		query := clonedURL.Query()
		query.Set("tenant_id", request.TenantID)
		clonedURL.RawQuery = query.Encode()
		clone.URL = &clonedURL
		scopeRequest = clone
	}
	scope, err := h.scope(scopeRequest)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if request.TenantID != "" && scope.TenantID != "" && request.TenantID != scope.TenantID {
		h.writeError(w, fmt.Errorf("%w: tenant_id must match the resolved vendor scope", grcvendor.ErrInvalidRequest))
		return
	}
	if request.WorkspaceID != "" && request.WorkspaceID != scope.ApplicationWorkspaceID {
		h.writeError(w, fmt.Errorf("%w: workspace_id must match the resolved vendor scope", grcvendor.ErrInvalidRequest))
		return
	}
	if scope.TenantID == "" {
		h.writeError(w, fmt.Errorf("%w: tenant_id is required", grcvendor.ErrInvalidRequest))
		return
	}
	if h.options.AuthorizeTenant == nil {
		h.writeError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	if err := h.options.AuthorizeTenant(r.Context(), scope.TenantID); err != nil {
		h.writeError(w, err)
		return
	}

	event, vendor, err := buildGRCVendorCreateEvent(request, scope, h.now())
	if err != nil {
		h.writeError(w, err)
		return
	}
	if h.options.AppendLog == nil || h.options.Projector == nil {
		h.writeError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	if err := h.options.AppendLog.Append(r.Context(), event); err != nil {
		h.writeError(w, fmt.Errorf("%w: append vendor event: %w", grcvendor.ErrRuntimeUnavailable, err))
		return
	}
	if _, err := h.options.Projector.Project(r.Context(), event); err != nil {
		h.writeError(w, fmt.Errorf("%w: project vendor event: %w", grcvendor.ErrRuntimeUnavailable, err))
		return
	}
	if h.options.BumpCache != nil {
		h.options.BumpCache(r.Context(), scope.TenantID)
	}
	h.writeJSON(w, http.StatusCreated, createResponse{Vendor: vendor, GeneratedAt: event.GetOccurredAt().AsTime()})
}

func (h Handler) scope(r *http.Request) (Scope, error) {
	if h.options.ResolveScope == nil {
		return Scope{}, grcvendor.ErrRuntimeUnavailable
	}
	return h.options.ResolveScope(r)
}

func (h Handler) writeError(w http.ResponseWriter, err error) {
	if h.options.WriteError == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.options.WriteError(w, err)
}

func (h Handler) writeJSON(w http.ResponseWriter, statusCode int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func (h Handler) now() time.Time {
	if h.options.Now != nil {
		return h.options.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *grcVendorCreateRequest) normalize() {
	if r == nil {
		return
	}
	r.TenantID = strings.TrimSpace(r.TenantID)
	r.WorkspaceID = strings.TrimSpace(r.WorkspaceID)
	r.Name = strings.TrimSpace(r.Name)
	r.VendorID = strings.TrimSpace(r.VendorID)
	r.SourceID = strings.TrimSpace(r.SourceID)
	r.RuntimeID = strings.TrimSpace(r.RuntimeID)
	r.Provider = strings.TrimSpace(r.Provider)
	r.Status = strings.TrimSpace(r.Status)
	r.Category = strings.TrimSpace(r.Category)
	r.WebsiteURL = strings.TrimSpace(r.WebsiteURL)
	r.ServicesProvided = strings.TrimSpace(r.ServicesProvided)
	r.Owner = strings.TrimSpace(r.Owner)
	r.SecurityOwnerUserID = strings.TrimSpace(r.SecurityOwnerUserID)
	r.BusinessOwnerUserID = strings.TrimSpace(r.BusinessOwnerUserID)
	r.LifecycleState = strings.TrimSpace(r.LifecycleState)
	r.ReviewState = strings.TrimSpace(r.ReviewState)
	r.RiskLevel = strings.TrimSpace(r.RiskLevel)
	r.DiscoveryURN = strings.TrimSpace(r.DiscoveryURN)
}

func buildGRCVendorCreateEvent(request grcVendorCreateRequest, scope Scope, now time.Time) (*cerebrov1.EventEnvelope, grcvendor.Vendor, error) {
	request.normalize()
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if request.Name == "" {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: name is required", grcvendor.ErrInvalidRequest)
	}
	if err := validateGRCVendorCreateFields(request); err != nil {
		return nil, grcvendor.Vendor{}, err
	}
	tenantID := strings.TrimSpace(scope.TenantID)
	if tenantID == "" {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: tenant_id is required", grcvendor.ErrInvalidRequest)
	}
	vendorID := grcVendorCreateSlug(firstNonEmpty(request.VendorID, request.Name))
	if vendorID == "" {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: vendor_id is required", grcvendor.ErrInvalidRequest)
	}
	sourceID := firstNonEmpty(request.SourceID, scope.SourceID, grcVendorEventSourceID)
	runtimeID := firstNonEmpty(request.RuntimeID, scope.RuntimeID)
	provider := firstNonEmpty(request.Provider, sourceID)
	if request.Provider == "" && request.SourceID == "" && scope.SourceID == "" {
		provider = "manual"
	}
	provider = grcVendorCreateSlug(provider)
	if provider == "" {
		provider = "manual"
	}
	status := firstNonEmpty(request.Status, "active")
	category := firstNonEmpty(request.Category, "uncategorized")
	lifecycleState := firstNonEmpty(request.LifecycleState, grcvendor.LifecycleStateInReview)
	reviewState := firstNonEmpty(request.ReviewState, grcvendor.ReviewStateNotScheduled)
	riskLevel := firstNonEmpty(request.RiskLevel, grcvendor.FreshnessStateUnknown)
	ownerState := "missing"
	if firstNonEmpty(request.Owner, request.SecurityOwnerUserID, request.BusinessOwnerUserID) != "" {
		ownerState = grcvendor.OwnerStateAssigned
	}

	attrs, err := grcVendorCreateAttributes(request, scope, vendorID, sourceID, runtimeID, provider, status, category, lifecycleState, reviewState, riskLevel)
	if err != nil {
		return nil, grcvendor.Vendor{}, err
	}
	seed := strings.Join([]string{tenantID, vendorID, provider, now.Format(time.RFC3339Nano)}, "\x00")
	digest := sha256.Sum256([]byte(seed))
	eventID := "grc-vendor-create-" + hex.EncodeToString(digest[:8])
	recordURN, err := cerebrourn.Mint(tenantID, "vendor", provider, vendorID)
	if err != nil {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: vendor identity is invalid", grcvendor.ErrInvalidRequest)
	}
	attrs["record_urn"] = recordURN
	attrs["source_event_id"] = eventID
	payload, err := json.Marshal(map[string]string{"record_id": vendorID, "record_kind": grcVendorEventKind})
	if err != nil {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: encode vendor event: %w", grcvendor.ErrInvalidRequest, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   tenantID,
		SourceId:   grcVendorEventSourceID,
		Kind:       grcVendorEventKind,
		OccurredAt: timestamppb.New(now),
		SchemaRef:  grcVendorEventSchemaRef,
		Payload:    payload,
		Attributes: attrs,
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, grcvendor.Vendor{}, fmt.Errorf("%w: %w", grcvendor.ErrInvalidRequest, err)
	}
	vendor := grcvendor.Vendor{
		VendorIdentity: grcvendor.VendorIdentity{
			URN: recordURN, VendorID: vendorID, Name: request.Name, SourceID: sourceID,
			RuntimeID: runtimeID, Provider: provider, Status: status, Category: category,
			WebsiteURL: request.WebsiteURL, ServicesProvided: request.ServicesProvided,
		},
		VendorLifecycle: grcvendor.VendorLifecycle{
			SourceStatus: status, LifecycleState: lifecycleState,
			LifecycleReason: "Created from vendor review.",
		},
		VendorOwnership: grcvendor.VendorOwnership{
			SecurityOwnerUserID: request.SecurityOwnerUserID, BusinessOwnerUserID: request.BusinessOwnerUserID,
			Owner: request.Owner, OwnerState: ownerState,
		},
		VendorRiskPosture: grcvendor.VendorRiskPosture{
			InherentRiskLevel: riskLevel, ResidualRiskLevel: riskLevel, RiskLevel: riskLevel,
		},
		VendorReviewPosture: grcvendor.VendorReviewPosture{ReviewState: reviewState},
		Attributes:          cloneGRCVendorCreateAttrs(attrs),
	}
	vendor = grcvendor.RefreshVendorQueuePosture(vendor, now)
	return event, vendor, nil
}

func grcVendorCreateAttributes(request grcVendorCreateRequest, scope Scope, vendorID, sourceID, runtimeID, provider, status, category, lifecycleState, reviewState, riskLevel string) (map[string]string, error) {
	attrs := make(map[string]string, len(request.Attributes)+16)
	for key, value := range request.Attributes {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if len(attrs) >= maxGRCVendorCreateAttributes {
			return nil, fmt.Errorf("%w: attributes exceed %d entries", grcvendor.ErrInvalidRequest, maxGRCVendorCreateAttributes)
		}
		if len(key) > maxGRCVendorCreateAttributeKey {
			return nil, fmt.Errorf("%w: attribute key exceeds %d characters", grcvendor.ErrInvalidRequest, maxGRCVendorCreateAttributeKey)
		}
		if len(value) > maxGRCVendorCreateAttributeLength {
			return nil, fmt.Errorf("%w: attribute %q exceeds %d characters", grcvendor.ErrInvalidRequest, key, maxGRCVendorCreateAttributeLength)
		}
		if grcVendorCreateReservedAttribute(key) {
			continue
		}
		attrs[key] = value
	}
	attrs["vendor_id"] = vendorID
	attrs["vendor_name"] = request.Name
	attrs["name"] = request.Name
	attrs["title"] = request.Name
	attrs["provider"] = provider
	attrs["source_system"] = provider
	attrs["source_id"] = sourceID
	attrs["status"] = status
	attrs["source_status"] = status
	attrs["category"] = category
	attrs["lifecycle_state"] = lifecycleState
	attrs["review_state"] = reviewState
	attrs["risk_level"] = riskLevel
	if request.WebsiteURL != "" {
		attrs["website_url"] = request.WebsiteURL
	}
	if request.ServicesProvided != "" {
		attrs["services_provided"] = request.ServicesProvided
	}
	if request.Owner != "" {
		attrs["owner"] = request.Owner
	}
	if request.SecurityOwnerUserID != "" {
		attrs["security_owner_user_id"] = request.SecurityOwnerUserID
	}
	if request.BusinessOwnerUserID != "" {
		attrs["business_owner_user_id"] = request.BusinessOwnerUserID
	}
	if request.DiscoveryURN != "" {
		attrs["discovery_urn"] = request.DiscoveryURN
	}
	if runtimeID != "" {
		attrs[ports.EventAttributeSourceRuntimeID] = runtimeID
	}
	if scope.ApplicationWorkspaceID != "" {
		attrs[ports.EventAttributeApplicationWorkspaceID] = scope.ApplicationWorkspaceID
	}
	return attrs, nil
}

func validateGRCVendorCreateFields(request grcVendorCreateRequest) error {
	fields := map[string]string{
		"tenant_id": request.TenantID, "workspace_id": request.WorkspaceID, "name": request.Name,
		"vendor_id": request.VendorID, "source_id": request.SourceID, "runtime_id": request.RuntimeID,
		"provider": request.Provider, "status": request.Status, "category": request.Category,
		"website_url": request.WebsiteURL, "services_provided": request.ServicesProvided, "owner": request.Owner,
		"security_owner_user_id": request.SecurityOwnerUserID, "business_owner_user_id": request.BusinessOwnerUserID,
		"lifecycle_state": request.LifecycleState, "review_state": request.ReviewState,
		"risk_level": request.RiskLevel, "discovery_urn": request.DiscoveryURN,
	}
	for field, value := range fields {
		if len(value) > maxGRCVendorCreateFieldLength {
			return fmt.Errorf("%w: %s exceeds %d characters", grcvendor.ErrInvalidRequest, field, maxGRCVendorCreateFieldLength)
		}
	}
	return nil
}

func grcVendorCreateReservedAttribute(key string) bool {
	switch key {
	case "tenant_id", "workspace_id", ports.EventAttributeApplicationWorkspaceID, ports.EventAttributeSourceRuntimeID,
		"vendor_id", "vendor_name", "name", "title", "provider", "source_system", "source_id", "runtime_id",
		"status", "source_status", "category", "website_url", "services_provided", "owner",
		"security_owner_user_id", "business_owner_user_id", "lifecycle_state", "review_state", "risk_level",
		"discovery_urn", "record_urn", "source_event_id":
		return true
	default:
		return false
	}
}

func grcVendorCreateSlug(value string) string {
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
	return mapped
}

func cloneGRCVendorCreateAttrs(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
