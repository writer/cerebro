package graphactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const (
	ActionIdentityOktaSuspendUser   = "identity.okta.suspend_user"
	ActionIdentityOktaUnsuspendUser = "identity.okta.unsuspend_user"

	AccessApprovalsActionSuspend   = "suspend"
	AccessApprovalsActionUnsuspend = "unsuspend"

	ProviderAccessApprovals = "access-approvals"
	Source                  = "cerebro:graph_action"
	RefKind                 = "graph_action"

	maxTargetLen = 512
	maxReasonLen = 2048
	maxURLLen    = 2048
)

var (
	ErrNotConfigured  = errors.New("graph action executor is not configured")
	ErrInvalidRequest = errors.New("invalid graph action request")
	ErrRemote         = errors.New("graph action remote error")
)

type AccessApprovalsUserActionRequest struct {
	EmailOrUserID  string `json:"email_or_user_id"`
	Reason         string `json:"reason,omitempty"`
	Source         string `json:"source,omitempty"`
	TicketURL      string `json:"ticket_url,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	FindingID      string `json:"finding_id,omitempty"`
	FindingRuleID  string `json:"finding_rule_id,omitempty"`
	ResourceURN    string `json:"resource_urn,omitempty"`
	SubjectURN     string `json:"subject_urn,omitempty"`
}

type AccessApprovalsUserAction struct {
	ID              string `json:"id"`
	Action          string `json:"action"`
	Status          string `json:"status"`
	Target          string `json:"target"`
	OktaUserID      string `json:"okta_user_id,omitempty"`
	OktaUserStatus  string `json:"okta_user_status,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Source          string `json:"source,omitempty"`
	TicketURL       string `json:"ticket_url,omitempty"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	FindingID       string `json:"finding_id,omitempty"`
	FindingRuleID   string `json:"finding_rule_id,omitempty"`
	ResourceURN     string `json:"resource_urn,omitempty"`
	SubjectURN      string `json:"subject_urn,omitempty"`
	ActorType       string `json:"actor_type,omitempty"`
	ActorSubject    string `json:"actor_subject,omitempty"`
	CreatedAtUnix   int64  `json:"created_at_unix"`
	UpdatedAtUnix   int64  `json:"updated_at_unix"`
	CompletedAtUnix int64  `json:"completed_at_unix,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type GraphAction struct {
	ID                   string            `json:"id"`
	Action               string            `json:"action"`
	Provider             string            `json:"provider"`
	Status               string            `json:"status"`
	Target               string            `json:"target"`
	ExternalID           string            `json:"external_id,omitempty"`
	ExternalURL          string            `json:"external_url,omitempty"`
	ExternalStatus       string            `json:"external_status,omitempty"`
	ExternalStatusReason string            `json:"external_status_reason,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	Source               string            `json:"source,omitempty"`
	TicketURL            string            `json:"ticket_url,omitempty"`
	IdempotencyKey       string            `json:"idempotency_key,omitempty"`
	ActorType            string            `json:"actor_type,omitempty"`
	ActorSubject         string            `json:"actor_subject,omitempty"`
	CreatedAtUnix        int64             `json:"created_at_unix"`
	UpdatedAtUnix        int64             `json:"updated_at_unix"`
	CompletedAtUnix      int64             `json:"completed_at_unix,omitempty"`
	LastError            string            `json:"last_error,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

type AccessApprovalsClient interface {
	SuspendOktaUser(context.Context, AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error)
	UnsuspendOktaUser(context.Context, AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error)
	GetOktaUserAction(context.Context, string) (*AccessApprovalsUserAction, error)
	ActionURL(string) string
}

type FindingWorkflow interface {
	GetFinding(context.Context, string) (*ports.FindingRecord, error)
	LinkFindingExternalRef(context.Context, string, ports.FindingExternalRef) (*ports.FindingRecord, error)
}

type Service struct {
	Findings   FindingWorkflow
	Client     AccessApprovalsClient
	Registry   Registry
	BeforeLink func(context.Context, *ports.FindingRecord, *GraphAction, string) error
}

type Input struct {
	FindingID      string
	Action         string
	Target         string
	Reason         string
	TicketURL      string
	IdempotencyKey string
	Source         string
	Parameters     map[string]string
}

type ReconcileInput struct {
	FindingID  string
	ExternalID string
}

type Result struct {
	Finding     *ports.FindingRecord
	Action      *GraphAction
	Target      string
	ExternalRef ports.FindingExternalRef
}

func (s Service) Execute(ctx context.Context, input Input) (*Result, error) {
	if s.Client == nil {
		return nil, ErrNotConfigured
	}
	findingID := strings.TrimSpace(input.FindingID)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", ErrInvalidRequest)
	}
	var finding *ports.FindingRecord
	var err error
	if s.Findings == nil {
		return nil, ErrNotConfigured
	}
	finding, err = s.Findings.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	spec, err := s.actionSpec(input.Action)
	if err != nil {
		return nil, err
	}
	if err := validateParameters(input.Parameters); err != nil {
		return nil, err
	}
	if err := checkSpecEligibility(spec, finding); err != nil {
		return nil, err
	}
	target, err := resolveSpecTarget(spec, finding, input.Target)
	if err != nil {
		return nil, err
	}
	reason, err := Reason(finding, input.Reason)
	if err != nil {
		return nil, err
	}
	ticketURL, err := TicketURL(input.TicketURL)
	if err != nil {
		return nil, err
	}
	source := strings.TrimSpace(input.Source)
	if source == "" {
		source = Source
	}
	idempotencyKey := strings.TrimSpace(input.IdempotencyKey)
	if idempotencyKey == "" {
		idempotencyKey = IdempotencyKey(spec.ID, findingID, target)
	}
	actionRequest := AccessApprovalsUserActionRequest{
		EmailOrUserID:  target,
		Reason:         reason,
		Source:         source,
		TicketURL:      ticketURL,
		IdempotencyKey: idempotencyKey,
		TenantID:       strings.TrimSpace(finding.TenantID),
		FindingID:      strings.TrimSpace(finding.ID),
		FindingRuleID:  strings.TrimSpace(finding.RuleID),
		ResourceURN:    primaryResourceURN(finding),
		SubjectURN:     subjectURNForFinding(finding),
	}
	var externalAction *AccessApprovalsUserAction
	if spec.AccessApprovalsAction == AccessApprovalsActionSuspend {
		externalAction, err = s.Client.SuspendOktaUser(ctx, actionRequest)
	} else {
		externalAction, err = s.Client.UnsuspendOktaUser(ctx, actionRequest)
	}
	if err != nil {
		return nil, err
	}
	if externalAction == nil {
		return nil, fmt.Errorf("%w: response missing action", ErrRemote)
	}
	graphAction := GraphActionFromAccessApprovals(spec.ID, externalAction, s.Client.ActionURL(externalAction.ID), target)
	var ref ports.FindingExternalRef
	updated := finding
	if finding != nil {
		if s.BeforeLink != nil {
			if err := s.BeforeLink(ctx, finding, graphAction, target); err != nil {
				return nil, err
			}
		}
		ref = ExternalRef(graphAction)
		updated, err = s.Findings.LinkFindingExternalRef(ctx, finding.ID, ref)
		if err != nil {
			return nil, err
		}
	}
	return &Result{Finding: updated, Action: graphAction, Target: target, ExternalRef: ref}, nil
}

func (s Service) Reconcile(ctx context.Context, input ReconcileInput) (*Result, error) {
	if s.Client == nil || s.Findings == nil {
		return nil, ErrNotConfigured
	}
	findingID := strings.TrimSpace(input.FindingID)
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", ErrInvalidRequest)
	}
	externalID := strings.TrimSpace(input.ExternalID)
	if externalID == "" {
		return nil, fmt.Errorf("%w: external_id is required", ErrInvalidRequest)
	}
	finding, err := s.Findings.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if !findingHasGraphActionRef(finding, externalID) {
		return nil, fmt.Errorf("%w: external_id is not linked to finding", ErrInvalidRequest)
	}
	externalAction, err := s.Client.GetOktaUserAction(ctx, externalID)
	if err != nil {
		return nil, err
	}
	if externalAction == nil || strings.TrimSpace(externalAction.ID) == "" {
		return nil, fmt.Errorf("%w: response missing action", ErrRemote)
	}
	action, err := graphActionIDFromAccessApprovals(externalAction.Action)
	if err != nil {
		return nil, err
	}
	spec, err := s.actionSpec(action)
	if err != nil {
		return nil, err
	}
	if err := checkSpecEligibility(spec, finding); err != nil {
		return nil, err
	}
	target, err := resolveSpecTarget(spec, finding, externalAction.Target)
	if err != nil {
		return nil, err
	}
	graphAction := GraphActionFromAccessApprovals(action, externalAction, s.Client.ActionURL(externalAction.ID), target)
	if s.BeforeLink != nil {
		if err := s.BeforeLink(ctx, finding, graphAction, target); err != nil {
			return nil, err
		}
	}
	ref := ExternalRef(graphAction)
	updated, err := s.Findings.LinkFindingExternalRef(ctx, finding.ID, ref)
	if err != nil {
		return nil, err
	}
	return &Result{Finding: updated, Action: graphAction, Target: target, ExternalRef: ref}, nil
}

func (s Service) actionSpec(action string) (ActionSpec, error) {
	return s.Registry.Lookup(action)
}

func validateParameters(parameters map[string]string) error {
	for key, value := range parameters {
		if strings.TrimSpace(key) != "" || strings.TrimSpace(value) != "" {
			return fmt.Errorf("%w: parameters are reserved and not supported for this action", ErrInvalidRequest)
		}
	}
	return nil
}

func checkSpecEligibility(spec ActionSpec, finding *ports.FindingRecord) error {
	if spec.CheckEligibility == nil {
		return nil
	}
	return spec.CheckEligibility(spec.ID, finding)
}

func resolveSpecTarget(spec ActionSpec, finding *ports.FindingRecord, explicit string) (string, error) {
	if spec.ResolveTarget == nil {
		return "", fmt.Errorf("%w: action %q has no target resolver", ErrInvalidRequest, spec.ID)
	}
	return spec.ResolveTarget(finding, explicit)
}

func primaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if value := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); value != "" {
		return value
	}
	for _, urn := range finding.ResourceURNs {
		if value := strings.TrimSpace(urn); value != "" {
			return value
		}
	}
	return ""
}

func subjectURNForFinding(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	for _, key := range []string{"okta_user_urn", "subject_urn", "principal_urn", "primary_resource_urn"} {
		if value := strings.TrimSpace(finding.Attributes[key]); value != "" {
			return value
		}
	}
	for _, urn := range finding.ResourceURNs {
		if strings.Contains(urn, ":okta.user:") || strings.Contains(urn, ":okta_user:") || strings.Contains(urn, ":identity:email:") {
			return strings.TrimSpace(urn)
		}
	}
	return ""
}

func findingHasGraphActionRef(finding *ports.FindingRecord, externalID string) bool {
	externalID = strings.TrimSpace(externalID)
	if finding == nil || externalID == "" {
		return false
	}
	for _, ref := range finding.ExternalRefs {
		if strings.TrimSpace(ref.System) == ProviderAccessApprovals &&
			strings.TrimSpace(ref.Kind) == RefKind &&
			strings.TrimSpace(ref.ExternalID) == externalID {
			return true
		}
	}
	return false
}

func graphActionIDFromAccessApprovals(action string) (string, error) {
	switch strings.TrimSpace(action) {
	case AccessApprovalsActionSuspend:
		return ActionIdentityOktaSuspendUser, nil
	case AccessApprovalsActionUnsuspend:
		return ActionIdentityOktaUnsuspendUser, nil
	default:
		return "", fmt.Errorf("%w: unsupported access-approvals action %q", ErrRemote, action)
	}
}

func OktaUserTargetForFinding(finding *ports.FindingRecord, explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		normalized, err := NormalizeTarget(explicit)
		if err != nil {
			return "", err
		}
		if !targetMatchesFinding(finding, normalized) {
			return "", fmt.Errorf("%w: target does not match authorized finding identity", ErrInvalidRequest)
		}
		return normalized, nil
	}
	for _, candidate := range targetCandidates(finding) {
		normalized, err := NormalizeTarget(candidate)
		if err == nil {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("%w: email_or_user_id is required or no Okta user target could be derived from finding", ErrInvalidRequest)
}

func targetMatchesFinding(finding *ports.FindingRecord, target string) bool {
	target = strings.TrimSpace(target)
	if finding == nil || target == "" {
		return false
	}
	for _, candidate := range targetCandidates(finding) {
		normalized, err := NormalizeTarget(candidate)
		if err == nil && strings.EqualFold(normalized, target) {
			return true
		}
	}
	return false
}

func targetCandidates(finding *ports.FindingRecord) []string {
	candidates := []string{}
	if finding == nil {
		return candidates
	}
	attrs := finding.Attributes
	for _, key := range []string{"okta_user_id", "okta_user_email", "okta_user_login", "okta_email", "okta_login", "principal_email", "user_email", "email", "identity_email"} {
		candidates = append(candidates, attrs[key])
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	for _, key := range []string{"okta_user_urn", "primary_resource_urn", "principal_urn", "identity_urns"} {
		candidates = append(candidates, candidatesFromDelimited(tenantID, attrs[key])...)
	}
	for _, key := range []string{"okta_identity_attributes_json", "okta_attributes_json", "principal_attributes_json"} {
		candidates = append(candidates, candidatesFromJSON(attrs[key])...)
	}
	for _, urn := range finding.ResourceURNs {
		if candidate := candidateFromURN(tenantID, urn); candidate != "" {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func candidatesFromJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	return []string{
		stringFromMap(payload, "id"),
		stringFromMap(payload, "user_id"),
		stringFromMap(payload, "okta_user_id"),
		stringFromMap(payload, "email"),
		stringFromMap(payload, "login"),
		stringFromMap(payload, "identifier_value"),
		stringFromNestedMap(payload, "profile", "email"),
		stringFromNestedMap(payload, "profile", "login"),
	}
}

func candidatesFromDelimited(tenantID string, raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\t' })
	candidates := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "urn:cerebro:") {
			if candidate := candidateFromURN(tenantID, part); candidate != "" {
				candidates = append(candidates, candidate)
			}
			continue
		}
		candidates = append(candidates, part)
	}
	return candidates
}

func candidateFromURN(tenantID string, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || (!strings.Contains(raw, ":okta.user:") && !strings.Contains(raw, ":okta_user:") && !strings.Contains(raw, ":identity:email:")) {
		return ""
	}
	if urnTenantID(raw) != strings.TrimSpace(tenantID) {
		return ""
	}
	index := strings.LastIndex(raw, ":")
	if index < 0 || index == len(raw)-1 {
		return ""
	}
	return raw[index+1:]
}

func urnTenantID(raw string) string {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func stringFromMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	if typed, ok := value.(string); ok {
		return typed
	}
	return fmt.Sprint(value)
}

func stringFromNestedMap(values map[string]any, parent string, key string) string {
	value, ok := values[parent].(map[string]any)
	if !ok {
		return ""
	}
	return stringFromMap(value, key)
}

func NormalizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("%w: target is required", ErrInvalidRequest)
	}
	if len(target) > maxTargetLen || !utf8.ValidString(target) || strings.ContainsAny(target, "\x00\r\n") {
		return "", fmt.Errorf("%w: target is invalid", ErrInvalidRequest)
	}
	if strings.Contains(target, "@") {
		address, err := mail.ParseAddress(target)
		if err != nil {
			return "", fmt.Errorf("%w: target email is invalid", ErrInvalidRequest)
		}
		target = address.Address
	} else if strings.IndexFunc(target, unicode.IsSpace) >= 0 || strings.ContainsAny(target, "<>") {
		return "", fmt.Errorf("%w: target user id is invalid", ErrInvalidRequest)
	}
	return target, nil
}

func Reason(finding *ports.FindingRecord, explicit string) (string, error) {
	reason := strings.TrimSpace(explicit)
	if reason == "" && finding != nil {
		reason = "Cerebro finding " + strings.TrimSpace(finding.ID)
		if title := strings.TrimSpace(finding.Title); title != "" {
			reason += ": " + title
		}
	}
	if len(reason) > maxReasonLen || !utf8.ValidString(reason) || strings.ContainsRune(reason, '\x00') {
		return "", fmt.Errorf("%w: reason is invalid", ErrInvalidRequest)
	}
	return reason, nil
}

func TicketURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxURLLen || !utf8.ValidString(raw) {
		return "", fmt.Errorf("%w: ticket_url is invalid", ErrInvalidRequest)
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("%w: ticket_url is invalid", ErrInvalidRequest)
	}
	return raw, nil
}

func IdempotencyKey(action string, findingID string, target string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(action) + "\x00" + strings.TrimSpace(findingID) + "\x00" + strings.ToLower(strings.TrimSpace(target))))
	return "cerebro:graph-action:" + strings.TrimSpace(action) + ":" + hex.EncodeToString(sum[:])
}

func GraphActionFromAccessApprovals(action string, external *AccessApprovalsUserAction, actionURL string, fallbackTarget string) *GraphAction {
	if external == nil {
		return nil
	}
	metadata := map[string]string{}
	if value := strings.TrimSpace(external.Action); value != "" {
		metadata["access_approvals_action"] = value
	}
	if value := strings.TrimSpace(external.OktaUserID); value != "" {
		metadata["okta_user_id"] = value
	}
	if value := strings.TrimSpace(external.OktaUserStatus); value != "" {
		metadata["okta_user_status"] = value
	}
	for key, value := range map[string]string{
		"tenant_id":       external.TenantID,
		"finding_id":      external.FindingID,
		"finding_rule_id": external.FindingRuleID,
		"resource_urn":    external.ResourceURN,
		"subject_urn":     external.SubjectURN,
	} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			metadata[key] = trimmed
		}
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	target := strings.TrimSpace(external.Target)
	if target == "" {
		target = strings.TrimSpace(fallbackTarget)
	}
	return &GraphAction{
		ID:                   external.ID,
		Action:               strings.TrimSpace(action),
		Provider:             ProviderAccessApprovals,
		Status:               external.Status,
		Target:               target,
		ExternalID:           external.ID,
		ExternalURL:          strings.TrimSpace(actionURL),
		ExternalStatus:       external.Status,
		ExternalStatusReason: external.LastError,
		Reason:               external.Reason,
		Source:               external.Source,
		TicketURL:            external.TicketURL,
		IdempotencyKey:       external.IdempotencyKey,
		ActorType:            external.ActorType,
		ActorSubject:         external.ActorSubject,
		CreatedAtUnix:        external.CreatedAtUnix,
		UpdatedAtUnix:        external.UpdatedAtUnix,
		CompletedAtUnix:      external.CompletedAtUnix,
		LastError:            external.LastError,
		Metadata:             metadata,
	}
}

func ExternalRef(action *GraphAction) ports.FindingExternalRef {
	if action == nil {
		return ports.FindingExternalRef{}
	}
	observedAt := time.Now().UTC()
	if action.UpdatedAtUnix > 0 {
		observedAt = time.Unix(action.UpdatedAtUnix, 0).UTC()
	}
	return ports.FindingExternalRef{
		System:               ProviderAccessApprovals,
		Kind:                 RefKind,
		ExternalID:           strings.TrimSpace(action.ExternalID),
		URL:                  strings.TrimSpace(action.ExternalURL),
		ExternalStatus:       action.ExternalStatus,
		ExternalStatusReason: action.ExternalStatusReason,
		LifecycleOwner:       "external_owned",
		ObservedAt:           observedAt,
	}
}
