package sourceworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const exactGoAuthorizationPolicyResponse = `{
  "id":"authorizationPolicy",
  "allowEmailVerifiedUsersToJoinOrganization":false,
  "allowInvitesFrom":"adminsAndGuestInviters",
  "allowedToSignUpEmailBasedSubscriptions":false,
  "allowedToUseSSPR":true,
  "blockMsolPowerShell":true,
  "defaultUserRolePermissions":{
    "allowedToCreateApps":false,
    "allowedToCreateSecurityGroups":false,
    "allowedToReadBitlockerKeysForOwnedDevice":true,
    "permissionGrantPoliciesAssigned":["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
  }
}`

func exactScope(plan *cerebrov1.SourceExecutionPlanV1, now time.Time) CredentialScope {
	return CredentialScope{
		TenantID: "tenant-1", RuntimeID: "runtime-1", SourceID: "azure", FamilyID: "authorization_policy",
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: "logical-page-1",
		LeaseOwner: "owner-1", RuntimeGeneration: 7, LeaseGeneration: 11, LeaseExpiresAt: now.Add(time.Minute),
		ObservedAtUnixMillis: now.UTC().UnixMilli(),
	}
}

func exactReceipt(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, body []byte) SafeReceipt {
	return SafeReceipt{
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: scope.LogicalPageID,
		RequestIntentDigest: scope.RequestIntentDigest, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, CredentialOperation: "lease-operation-1",
		StatusCode: http.StatusOK, ResponseBytes: len(body), ResponseSHA256: responseSHA256(body),
		TenantID: scope.TenantID, RuntimeID: scope.RuntimeID, ObservedAtUnixMillis: scope.ObservedAtUnixMillis,
	}
}

type fakeWorker struct {
	responseBody    []byte
	escapedURL      string
	tamperedDigest  bool
	planSawSecret   bool
	decodeSawSecret bool
}

func (w *fakeWorker) Compile(_ context.Context, _ SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	return AzureAuthorizationPolicyPlan(), nil
}

func (w *fakeWorker) Context(_ context.Context, request ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	return &cerebrov1.SourceWorkerExecutionContextV1{
		TenantId: request.TenantID, RuntimeId: request.RuntimeID, LogicalPageId: "logical-page-1",
		PriorCursor: request.PriorCursor, RuntimeGeneration: request.RuntimeGeneration,
		LeaseGeneration: request.LeaseGeneration, ObservedAtUnixMillis: request.ObservedAtUnixMillis,
	}, nil
}

func (w *fakeWorker) Plan(_ context.Context, request *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	payload, _ := proto.Marshal(request)
	w.planSawSecret = bytes.Contains(payload, []byte("not-in-worker-or-receipt"))
	plan := request.GetPlan()
	endpoint := "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
	if w.escapedURL != "" {
		endpoint = w.escapedURL
	}
	result := &cerebrov1.SourceWorkerHTTPRequestV1{PlanId: plan.GetPlanId(), Method: "GET", Url: endpoint, Accept: "application/json", MaxResponseBytes: plan.GetMaxResponseBytes(), PlanDigestSha256: plan.GetPlanDigestSha256()}
	result.RequestIntentDigest, _ = canonicalRequestIntentDigestForContext(plan, request.GetContext(), result)
	return result, nil
}

func (w *fakeWorker) Decode(_ context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	payload, _ := proto.Marshal(request)
	w.decodeSawSecret = bytes.Contains(payload, []byte("not-in-worker-or-receipt"))
	payloadJSON, err := goTypedAuthorizationPolicyPayload(w.responseBody)
	if err != nil {
		return nil, err
	}
	result := &cerebrov1.SourceWorkerDecodeResultV1{
		PlanId: request.GetPlan().GetPlanId(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), LogicalPageId: request.GetLogicalPageId(), RequestIntentDigest: request.GetRequestIntentDigest(),
		TenantId: request.GetContext().GetTenantId(), RuntimeId: request.GetContext().GetRuntimeId(),
		RuntimeGeneration: request.GetContext().GetRuntimeGeneration(), LeaseGeneration: request.GetContext().GetLeaseGeneration(),
		ObservedAtUnixMillis: request.GetContext().GetObservedAtUnixMillis(),
		Records: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", Attributes: map[string]string{
			"allow_email_verified_users_to_join": "false", "allow_invites_from": "adminsAndGuestInviters", "allowed_to_sign_up_email": "false", "allowed_to_use_sspr": "true", "block_msol_powershell": "true", "default_user_can_create_apps": "false", "default_user_can_create_groups": "false", "default_user_can_read_bitlocker": "true", "family": "authorization_policy", "resource_id": "authorizationPolicy", "resource_name": "authorizationPolicy", "resource_provider": "azure", "resource_type": "authorization_policy",
		}, PayloadJson: payloadJSON, EventId: "azure-authorization-policy-authorizationPolicy", OccurredAtUnixMillis: request.GetContext().GetObservedAtUnixMillis()}},
	}
	receipt, err := safeReceiptFromProto(request.GetReceipt())
	if err != nil {
		return nil, err
	}
	result.ResultDigestSha256, err = CanonicalResultDigest(result, receipt)
	if err != nil {
		return nil, err
	}
	if w.tamperedDigest {
		result.ResultDigestSha256 = strings.Repeat("a", 64)
	}
	return result, nil
}

func (w *fakeWorker) Transition(_ context.Context, request LifecycleRequest) (*LifecycleDecision, error) {
	if w.tamperedDigest {
		return nil, ErrWorkerContract
	}
	required := PhaseAppended
	if request.CompletedPhase == PhaseAppended {
		required = PhaseProjected
	} else if request.CompletedPhase == PhaseProjected {
		required = PhaseCheckpointed
	} else if request.CompletedPhase == PhaseCheckpointed {
		required = PhaseComplete
	}
	decision := &LifecycleDecision{RequiredPhase: required, TransitionDigest: strings.Repeat("d", 64)}
	if required == PhaseAppended {
		record := proto.Clone(request.Result.GetRecords()[0]).(*cerebrov1.SourceWorkerRecordV1)
		record.Attributes["domain"] = request.Context.GetTenantId()
		var raw map[string]any
		_ = json.Unmarshal(record.GetPayloadJson(), &raw)
		record.PayloadJson, _ = json.Marshal(map[string]any{"id": record.GetProviderId(), "tenant_id": request.Context.GetTenantId(), "raw": raw})
		decision.AdmittedRecords = []*cerebrov1.SourceWorkerRecordV1{record}
	}
	return decision, nil
}

func goTypedAuthorizationPolicyPayload(body []byte) ([]byte, error) {
	var input map[string]any
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, err
	}
	valueOrNull := func(key string) any {
		if value, ok := input[key]; ok {
			return value
		}
		return nil
	}
	payload := map[string]any{
		"id": "authorizationPolicy", "allowInvitesFrom": "", "guestUserRoleId": "",
		"allowedToSignUpEmailBasedSubscriptions":    valueOrNull("allowedToSignUpEmailBasedSubscriptions"),
		"allowedToUseSSPR":                          valueOrNull("allowedToUseSSPR"),
		"allowEmailVerifiedUsersToJoinOrganization": valueOrNull("allowEmailVerifiedUsersToJoinOrganization"),
		"blockMsolPowerShell":                       valueOrNull("blockMsolPowerShell"),
		"defaultUserRolePermissions":                valueOrNull("defaultUserRolePermissions"),
	}
	if value, ok := input["id"].(string); ok && strings.TrimSpace(value) != "" {
		payload["id"] = strings.TrimSpace(value)
	}
	if value, ok := input["allowInvitesFrom"].(string); ok {
		payload["allowInvitesFrom"] = value
	}
	if value, ok := input["guestUserRoleId"].(string); ok {
		payload["guestUserRoleId"] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

type fakeCredentialLease struct {
	token       []byte
	operationID string
	expiresAt   time.Time
	closeCalls  int
}

func (l *fakeCredentialLease) BearerToken() []byte  { return append([]byte(nil), l.token...) }
func (l *fakeCredentialLease) OperationID() string  { return l.operationID }
func (l *fakeCredentialLease) ExpiresAt() time.Time { return l.expiresAt }
func (l *fakeCredentialLease) Close() error         { l.closeCalls++; return nil }

type fakeCredentialRedeemer struct {
	lease CredentialLease
	calls int
}

func (r *fakeCredentialRedeemer) Redeem(_ context.Context, _ string, _ CredentialScope) (CredentialLease, error) {
	r.calls++
	return r.lease, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }
func errorsIsInvalid(err error) bool {
	return errors.Is(err, ErrInvalidExecution)
}
func errorsNewRedirect() error { return fmt.Errorf("%w: redirect", ErrInvalidExecution) }
