// Package grcauditverify verifies audit submissions from immutable manifests.
// Verification is deliberately provider-free: callers supply every packet,
// citation, population, key, and superseded manifest needed for a decision.
package grcauditverify

import (
	"encoding/json"
	"time"
)

const (
	RequestSchemaVersion    = "grc.audit-request.v1"
	DisclosureSchemaVersion = "grc.selective-disclosure.v1"
	PopulationSchemaVersion = "grc.population-manifest.v1"
	SampleSchemaVersion     = "grc.sample-manifest.v1"

	SampleAlgorithmDeterministicSHA256V1 = "deterministic-sha256-v1"
	SignatureAlgorithmEd25519            = "ed25519"
)

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ManifestSignature struct {
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	SignatureBase64 string `json:"signature_base64"`
	SignedDigest    string `json:"signed_digest"`
}

type ManifestReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type RequestManifest struct {
	SchemaVersion       string              `json:"schema_version"`
	ID                  string              `json:"id"`
	Digest              string              `json:"digest"`
	TenantID            string              `json:"tenant_id"`
	Period              Window              `json:"period"`
	ScopeReferences     []string            `json:"scope_references"`
	RequiredCitationIDs []string            `json:"required_citation_ids"`
	ExternalFields      []string            `json:"external_fields"`
	Recipient           RecipientGrant      `json:"recipient"`
	Supersedes          []ManifestReference `json:"supersedes,omitempty"`
	SupersededBy        *ManifestReference  `json:"superseded_by,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	Signature           *ManifestSignature  `json:"signature,omitempty"`
}

type RecipientGrant struct {
	RecipientID   string    `json:"recipient_id"`
	AllowedFields []string  `json:"allowed_fields"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Citation struct {
	ID              string   `json:"id"`
	Digest          string   `json:"digest"`
	Period          Window   `json:"period"`
	ScopeReferences []string `json:"scope_references"`
	SampleID        string   `json:"sample_id,omitempty"`
	Payload         []byte   `json:"payload"`
}

type DisclosureManifest struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Digest        string             `json:"digest"`
	RequestID     string             `json:"request_id"`
	RecipientID   string             `json:"recipient_id"`
	Fields        []DisclosureField  `json:"fields"`
	CreatedAt     time.Time          `json:"created_at"`
	Signature     *ManifestSignature `json:"signature,omitempty"`
}

type DisclosureField struct {
	Path       string `json:"path"`
	State      string `json:"state"` // included or redacted
	Digest     string `json:"digest,omitempty"`
	CitationID string `json:"citation_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type PopulationManifest struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Digest        string             `json:"digest"`
	Complete      bool               `json:"complete"`
	Window        Window             `json:"window"`
	Members       []PopulationMember `json:"members"`
	CreatedAt     time.Time          `json:"created_at"`
	Signature     *ManifestSignature `json:"signature,omitempty"`
}

type PopulationMember struct {
	ID         string    `json:"id"`
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
	ArrivedAt  time.Time `json:"arrived_at"`
}

type SampleManifest struct {
	SchemaVersion    string              `json:"schema_version"`
	ID               string              `json:"id"`
	Digest           string              `json:"digest"`
	PopulationID     string              `json:"population_id"`
	PopulationDigest string              `json:"population_digest"`
	Window           Window              `json:"window"`
	Algorithm        string              `json:"algorithm"`
	AlgorithmVersion string              `json:"algorithm_version"`
	Seed             string              `json:"seed"`
	Rationale        string              `json:"rationale"`
	SampleSize       int                 `json:"sample_size"`
	Exclusions       []SampleExclusion   `json:"exclusions,omitempty"`
	SelectedIDs      []string            `json:"selected_ids"`
	Replacements     []SampleReplacement `json:"replacements,omitempty"`
	LateArrivals     []LateArrival       `json:"late_arrivals,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	Signature        *ManifestSignature  `json:"signature,omitempty"`
}

type SampleExclusion struct {
	MemberID string `json:"member_id"`
	Reason   string `json:"reason"`
}

type SampleReplacement struct {
	RemovedID string `json:"removed_id"`
	AddedID   string `json:"added_id"`
	Reason    string `json:"reason"`
}

type LateArrival struct {
	MemberID    string `json:"member_id"`
	Disposition string `json:"disposition"` // included, excluded, or after_window
	Reason      string `json:"reason"`
}

type Submission struct {
	Request           RequestManifest            `json:"request"`
	PacketJSON        []byte                     `json:"packet_json"`
	Disclosure        DisclosureManifest         `json:"disclosure"`
	ExternalFields    map[string]json.RawMessage `json:"external_fields"`
	Citations         []Citation                 `json:"citations"`
	Population        *PopulationManifest        `json:"population,omitempty"`
	Sample            *SampleManifest            `json:"sample,omitempty"`
	PriorRequests     []RequestManifest          `json:"prior_requests,omitempty"`
	SupersededPackets [][]byte                   `json:"superseded_packets,omitempty"`
	VerifiedAt        time.Time                  `json:"verified_at"`
}

// TrustBundle is caller-controlled verifier configuration, not submission
// content. A submitter cannot establish trust by including a new key.
type TrustBundle struct {
	SigningKeys map[string]string
}

type Result struct {
	Ready   bool                `json:"ready"`
	Code    ResultCode          `json:"result_code"`
	Defects []Defect            `json:"defects"`
	Metrics VerificationMetrics `json:"metrics"`
}

type ResultCode string

const (
	ResultFirstPassReady     ResultCode = "first_pass_ready"
	ResultResubmissionNeeded ResultCode = "resubmission_required"
)

type Defect struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type VerificationMetrics struct {
	FirstPassReady      bool          `json:"first_pass_ready"`
	ResubmissionDefects int           `json:"resubmission_defects"`
	VerifyDuration      time.Duration `json:"verify_duration"`
}
