package complianceexchange

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func NewStagingService(store StagingStore, appendLog ports.AppendLog) (*StagingService, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: staging store is required", ErrStagingInvalid)
	}
	return &StagingService{store: store, appendLog: appendLog, now: time.Now}, nil
}

func (s *StagingService) Stage(ctx context.Context, request StagePackageRequest) (StagedPackage, bool, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	key := strings.TrimSpace(request.IdempotencyKey)
	if tenantID == "" || key == "" {
		return StagedPackage{}, false, fmt.Errorf("%w: tenant_id and idempotency_key are required", ErrStagingInvalid)
	}
	now := s.now().UTC()
	limits, err := normalizeStagingLimits(request.Limits)
	if err != nil {
		return StagedPackage{}, false, err
	}
	expiresAt := request.ExpiresAt.UTC()
	if request.ExpiresAt.IsZero() || !expiresAt.After(now) || expiresAt.After(now.Add(limits.MaxTTL)) {
		return StagedPackage{}, false, fmt.Errorf("%w: expires_at must be in the future and within the staging TTL", ErrStagingInvalid)
	}
	manifestDigest := sha256Hex(request.Package.ManifestBytes)
	if supplied := strings.TrimSpace(request.Package.ManifestDigest); supplied != "" && supplied != manifestDigest {
		return StagedPackage{}, false, fmt.Errorf("%w: supplied manifest digest does not match bytes", ErrStagingDigest)
	}
	stagedBytes, err := stagedPackageBytes(request.Package)
	if err != nil || stagedBytes > limits.MaxStagedBytes {
		return StagedPackage{}, false, fmt.Errorf("%w: staged package exceeds byte limit", ErrStagingInvalid)
	}
	packageDigest := digestPackage(request.Package)
	stage := StagedPackage{
		ID:             deterministicID("exchange-stage", tenantID, key),
		TenantID:       tenantID,
		PackageID:      strings.TrimSpace(request.Package.Manifest.PackageID),
		ManifestDigest: manifestDigest,
		PackageDigest:  packageDigest,
		IdempotencyKey: key,
		ManifestBytes:  bytes.Clone(request.Package.ManifestBytes),
		Signature:      request.Package.Signature,
		Files:          cloneStagedFiles(request.Package.Files),
		FileCount:      len(request.Package.Files),
		TotalBytes:     payloadBytes(request.Package.Files),
		StagedBytes:    stagedBytes,
		Status:         StagingStatusStaged,
		Version:        1,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return s.store.PutStagedPackage(ctx, stage)
}

func (s *StagingService) ValidateStaged(ctx context.Context, request ValidateStagedRequest) (StagedValidation, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	stagingID := strings.TrimSpace(request.StagingID)
	policyVersion := strings.TrimSpace(request.PolicyVersion)
	if tenantID == "" || stagingID == "" || request.ExpectedStagingVersion == 0 || policyVersion == "" {
		return StagedValidation{}, fmt.Errorf("%w: tenant_id, staging_id, expected version, and policy_version are required", ErrStagingInvalid)
	}
	stage, err := s.store.GetStagedPackage(ctx, tenantID, stagingID)
	if err != nil {
		return StagedValidation{}, err
	}
	if !stage.ExpiresAt.After(s.now().UTC()) {
		return StagedValidation{}, ErrStagingExpired
	}
	limits, err := normalizeLimits(request.Limits)
	if err != nil {
		return StagedValidation{}, err
	}
	requestDigest := validationRequestDigest(stage.PackageDigest, policyVersion, limits)
	prior, err := s.store.GetStagedValidation(ctx, tenantID, stagingID, requestDigest)
	if err == nil {
		if request.ExpectedStagingVersion != prior.StagingVersion &&
			(prior.StagingVersion == 0 || request.ExpectedStagingVersion != prior.StagingVersion-1) {
			return StagedValidation{}, ErrStagingVersion
		}
		prior.Replayed = true
		return prior, nil
	}
	if !errors.Is(err, ErrValidationNotFound) {
		return StagedValidation{}, err
	}
	if stage.Version != request.ExpectedStagingVersion {
		return StagedValidation{}, ErrStagingVersion
	}
	validatedAt := s.now().UTC()
	result := Validate(ctx, ValidationRequest{
		ExpectedTenantID: tenantID,
		ManifestBytes:    stage.ManifestBytes,
		Signature:        stage.Signature,
		Files:            stage.Files,
		Limits:           limits,
		Trust:            request.Trust,
	})
	record := StagedValidation{
		TenantID:       tenantID,
		StagingID:      stagingID,
		RequestDigest:  requestDigest,
		StagingVersion: stage.Version + 1,
		Status:         result.Status,
		Result:         result,
		ValidatedAt:    validatedAt,
	}
	if result.ChangePlan != nil {
		record.ChangePlanDigest = digestJSON(result.ChangePlan)
	}
	if result.Status == ValidationValid {
		record.Signature = &SignatureReceipt{
			ManifestDigest:  result.ManifestDigest,
			SignatureDigest: sha256Hex([]byte(stage.Signature)),
			SignerKeyID:     result.SignerKeyID,
			Algorithm:       result.Algorithm,
			VerifiedAt:      validatedAt,
		}
	}
	stored, replayed, err := s.store.PutStagedValidation(ctx, record, request.ExpectedStagingVersion)
	if err != nil {
		return StagedValidation{}, err
	}
	stored.Replayed = replayed
	return stored, nil
}

func (s *StagingService) CreateCommitIntent(ctx context.Context, request CreateCommitIntentRequest) (CommitIntent, bool, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	stagingID := strings.TrimSpace(request.StagingID)
	key := strings.TrimSpace(request.IdempotencyKey)
	requestedBy := strings.TrimSpace(request.RequestedBy)
	if tenantID == "" || stagingID == "" || key == "" || requestedBy == "" || request.ExpectedStagingVersion == 0 {
		return CommitIntent{}, false, fmt.Errorf("%w: commit intent identity, actor, key, and expected staging version are required", ErrStagingInvalid)
	}
	stage, err := s.store.GetStagedPackage(ctx, tenantID, stagingID)
	if err != nil {
		return CommitIntent{}, false, err
	}
	if !stage.ExpiresAt.After(s.now().UTC()) {
		return CommitIntent{}, false, ErrStagingExpired
	}
	if stage.Version != request.ExpectedStagingVersion {
		return CommitIntent{}, false, ErrStagingVersion
	}
	if stage.Status != StagingStatusValid || stage.ChangePlanDigest == "" {
		return CommitIntent{}, false, fmt.Errorf("%w: only a valid staged package can create a commit intent", ErrStagingInvalid)
	}
	now := s.now().UTC()
	intent := CommitIntent{
		ID:                     deterministicID("exchange-intent", tenantID, key),
		TenantID:               tenantID,
		StagingID:              stagingID,
		ExpectedStagingVersion: request.ExpectedStagingVersion,
		ChangePlanDigest:       stage.ChangePlanDigest,
		IdempotencyKey:         key,
		RequiredScope:          ComplianceExchangeCommitScope,
		Status:                 CommitIntentAwaitingAuthorization,
		Version:                1,
		RequestedBy:            requestedBy,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	intent.IntentDigest = digestFields(intent.TenantID, intent.StagingID, fmt.Sprint(intent.ExpectedStagingVersion), intent.ChangePlanDigest, intent.RequestedBy)
	return s.store.PutCommitIntent(ctx, intent)
}

// AppendCommitIntent publishes the authorization receipt and exact staging
// version before any canonical projector can act. This service never writes
// canonical state itself.
func (s *StagingService) AppendCommitIntent(ctx context.Context, request AppendCommitIntentRequest) (CommitIntent, error) {
	if s.appendLog == nil {
		return CommitIntent{}, ErrAppendBoundary
	}
	tenantID := strings.TrimSpace(request.TenantID)
	intentID := strings.TrimSpace(request.IntentID)
	if tenantID == "" || intentID == "" || request.ExpectedIntentVersion == 0 || request.ExpectedStagingVersion == 0 {
		return CommitIntent{}, fmt.Errorf("%w: tenant, intent, and expected versions are required", ErrStagingInvalid)
	}
	auth := request.Authorization
	if strings.TrimSpace(auth.ActorID) == "" || strings.TrimSpace(auth.DecisionID) == "" || strings.TrimSpace(auth.Scope) != ComplianceExchangeCommitScope || auth.GrantedAt.IsZero() {
		return CommitIntent{}, ErrCommitAuthorization
	}
	intent, err := s.store.GetCommitIntent(ctx, tenantID, intentID)
	if err != nil {
		return CommitIntent{}, err
	}
	if intent.Status == CommitIntentEventAppended {
		if intent.ExpectedStagingVersion != request.ExpectedStagingVersion ||
			intent.Version != request.ExpectedIntentVersion+1 ||
			intent.AuthorizedBy != strings.TrimSpace(auth.ActorID) ||
			intent.AuthorizationDecisionID != strings.TrimSpace(auth.DecisionID) ||
			!intent.AuthorizedAt.Equal(auth.GrantedAt.UTC()) {
			return CommitIntent{}, ErrStagingDigest
		}
		return intent, nil
	}
	if intent.Version != request.ExpectedIntentVersion || intent.ExpectedStagingVersion != request.ExpectedStagingVersion {
		return CommitIntent{}, ErrStagingVersion
	}
	payload, err := json.Marshal(struct {
		IntentID                string `json:"intent_id"`
		StagingID               string `json:"staging_id"`
		ExpectedStagingVersion  uint64 `json:"expected_staging_version"`
		ChangePlanDigest        string `json:"change_plan_digest"`
		AuthorizedBy            string `json:"authorized_by"`
		AuthorizationDecisionID string `json:"authorization_decision_id"`
		AuthorizationScope      string `json:"authorization_scope"`
		AuthorizedAt            string `json:"authorized_at"`
	}{
		IntentID:                intent.ID,
		StagingID:               intent.StagingID,
		ExpectedStagingVersion:  intent.ExpectedStagingVersion,
		ChangePlanDigest:        intent.ChangePlanDigest,
		AuthorizedBy:            strings.TrimSpace(auth.ActorID),
		AuthorizationDecisionID: strings.TrimSpace(auth.DecisionID),
		AuthorizationScope:      ComplianceExchangeCommitScope,
		AuthorizedAt:            auth.GrantedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return CommitIntent{}, err
	}
	aggregateVersion, err := complianceAggregateVersion(intent.ExpectedStagingVersion)
	if err != nil {
		return CommitIntent{}, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind:             workflowevents.EventKindComplianceExchangeCommitRequested,
		TenantID:         tenantID,
		AggregateType:    "compliance_exchange_stage",
		AggregateID:      intent.StagingID,
		RevisionID:       intent.ID,
		AggregateVersion: aggregateVersion,
		Operation:        "commit_requested",
		ContentDigest:    intent.ChangePlanDigest,
		PayloadJSON:      string(payload),
		ActorID:          strings.TrimSpace(auth.ActorID),
		RecordedAt:       auth.GrantedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return CommitIntent{}, fmt.Errorf("build compliance exchange commit request event: %w", err)
	}
	event.Attributes["intent_id"] = intent.ID
	event.Attributes["staging_version"] = fmt.Sprint(intent.ExpectedStagingVersion)
	event.Attributes["authorization_decision_id"] = strings.TrimSpace(auth.DecisionID)
	if err := s.appendLog.Append(ctx, event); err != nil {
		return CommitIntent{}, err
	}
	return s.store.MarkCommitIntentEventAppended(ctx, intent, auth, event.Id)
}

func complianceAggregateVersion(version uint64) (int64, error) {
	if version > math.MaxInt64 {
		return 0, fmt.Errorf("%w: staging version exceeds the event contract", ErrStagingVersion)
	}
	return int64(version), nil // #nosec G115 -- version is bounded by MaxInt64 above.
}

func normalizeStagingLimits(limits StagingLimits) (StagingLimits, error) {
	defaults := DefaultStagingLimits()
	if limits.MaxStagedBytes < 0 || limits.MaxTTL < 0 {
		return StagingLimits{}, fmt.Errorf("%w: staging limits cannot be negative", ErrStagingInvalid)
	}
	if limits.MaxStagedBytes == 0 {
		limits.MaxStagedBytes = defaults.MaxStagedBytes
	}
	if limits.MaxTTL == 0 {
		limits.MaxTTL = defaults.MaxTTL
	}
	return limits, nil
}

func stagedPackageBytes(pkg Package) (int64, error) {
	total := int64(len(pkg.ManifestBytes)) + int64(len(pkg.Signature))
	for _, file := range pkg.Files {
		size := int64(len(file.Data))
		if size > int64(^uint64(0)>>1)-total {
			return 0, ErrStagingInvalid
		}
		total += size
	}
	return total, nil
}

func payloadBytes(files []File) int64 {
	var total int64
	for _, file := range files {
		total += int64(len(file.Data))
	}
	return total
}

func digestPackage(pkg Package) string {
	hash := sha256.New()
	digestWrite(hash, pkg.ManifestBytes)
	digestWrite(hash, []byte(pkg.Signature))
	files := cloneStagedFiles(pkg.Files)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, file := range files {
		digestWrite(hash, []byte(file.Path))
		digestWrite(hash, []byte(file.MediaType))
		digestWrite(hash, []byte(file.LogicalType))
		digestWrite(hash, file.Data)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validationRequestDigest(packageDigest string, policyVersion string, limits Limits) string {
	return digestFields(packageDigest, policyVersion, fmt.Sprintf("%d/%d/%d/%d/%d/%d", limits.MaxFiles, limits.MaxFileBytes, limits.MaxTotalBytes, limits.MaxPathBytes, limits.MaxManifestBytes, limits.MaxSignatureBytes))
}

func digestJSON(value any) string {
	content, _ := json.Marshal(value)
	return sha256Hex(content)
}

func digestFields(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		digestWrite(hash, []byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestWrite(hash interface{ Write([]byte) (int, error) }, content []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(content)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(content)
}

func deterministicID(prefix string, values ...string) string {
	digest := digestFields(values...)
	return prefix + "-" + digest[:24]
}

func cloneStagedFiles(files []File) []File {
	result := make([]File, len(files))
	for index, file := range files {
		result[index] = File{Path: file.Path, MediaType: file.MediaType, LogicalType: file.LogicalType, Data: bytes.Clone(file.Data)}
	}
	return result
}
