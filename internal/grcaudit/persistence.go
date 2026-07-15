package grcaudit

import (
	"context"
	"errors"
	"time"
)

var (
	ErrProjectionConflict = errors.New("audit projection event conflict")
	ErrProjectionGap      = errors.New("audit projection aggregate version gap")
)

const (
	AuditAggregateEngagement    = "audit_engagement"
	AuditAggregateRequest       = "audit_evidence_request"
	AuditAggregateSubmission    = "audit_evidence_submission"
	AuditAggregateSample        = "audit_sample"
	AuditAggregatePackage       = "audit_package"
	AuditAggregatePacketReceipt = "audit_packet_receipt"
	AuditAggregateCapability    = "audit_capability"
	AuditAggregateGrant         = "audit_access_grant"
)

type EngagementRecordedPayload struct {
	Engagement Engagement         `json:"engagement"`
	Revision   EngagementRevision `json:"revision"`
}

type EvidenceRequestRecordedPayload struct {
	Request  EvidenceRequest         `json:"request"`
	Revision EvidenceRequestRevision `json:"revision"`
}

type EvidenceSubmissionRecordedPayload struct {
	Request    EvidenceRequest    `json:"request"`
	Submission EvidenceSubmission `json:"submission"`
}

type CapabilityState struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Kind      string    `json:"kind"`
	Enabled   bool      `json:"enabled"`
	Version   uint64    `json:"version"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AccessGrant struct {
	ID             string               `json:"id"`
	TenantID       string               `json:"tenant_id"`
	EngagementID   string               `json:"engagement_id"`
	PrincipalID    string               `json:"principal_id"`
	Permission     EngagementPermission `json:"permission"`
	Status         ParticipantStatus    `json:"status"`
	Version        uint64               `json:"version"`
	GrantedBy      string               `json:"granted_by"`
	EffectiveFrom  time.Time            `json:"effective_from"`
	EffectiveUntil time.Time            `json:"effective_until,omitempty"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

type StateStore interface {
	GetAuditEngagement(context.Context, Principal, string, EngagementPermission) (*Engagement, error)
	GetAuditEvidenceRequest(context.Context, Principal, string, string, EngagementPermission) (*EvidenceRequest, error)
	GetAuditPackageManifest(context.Context, Principal, string, string, uint64, EngagementPermission) (*PackageManifest, error)
}
