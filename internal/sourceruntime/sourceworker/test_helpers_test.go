package sourceworker

import (
	"bytes"
	"context"
	"encoding/json"
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
	scope := CredentialScope{
		TenantID: "tenant-1", RuntimeID: "runtime-1", SourceID: "azure", FamilyID: "authorization_policy",
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: "logical-page-1",
		LeaseOwner: "owner-1", RuntimeGeneration: 7, LeaseGeneration: 11, LeaseExpiresAt: now.Add(time.Minute),
	}
	digest, err := CanonicalRequestIntentDigest(plan, scope, canonicalRequestForPlan(plan))
	if err != nil {
		panic(err)
	}
	scope.RequestIntentDigest = digest
	return scope
}

func exactReceipt(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, body []byte) SafeReceipt {
	return SafeReceipt{
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: scope.LogicalPageID,
		RequestIntentDigest: scope.RequestIntentDigest, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, CredentialOperation: "lease-operation-1",
		StatusCode: http.StatusOK, ResponseBytes: len(body), ResponseSHA256: responseSHA256(body),
	}
}

type fakeWorker struct {
	responseBody    []byte
	escapedURL      string
	tamperedDigest  bool
	planSawSecret   bool
	decodeSawSecret bool
}

func (w *fakeWorker) Plan(_ context.Context, plan *cerebrov1.SourceExecutionPlanV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	payload, _ := proto.Marshal(plan)
	w.planSawSecret = bytes.Contains(payload, []byte("not-in-worker-or-receipt"))
	endpoint := "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
	if w.escapedURL != "" {
		endpoint = w.escapedURL
	}
	return &cerebrov1.SourceWorkerHTTPRequestV1{PlanId: plan.GetPlanId(), Method: "GET", Url: endpoint, Accept: "application/json", MaxResponseBytes: plan.GetMaxResponseBytes(), PlanDigestSha256: plan.GetPlanDigestSha256()}, nil
}

func (w *fakeWorker) Decode(_ context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	payload, _ := proto.Marshal(request)
	w.decodeSawSecret = bytes.Contains(payload, []byte("not-in-worker-or-receipt"))
	result := &cerebrov1.SourceWorkerDecodeResultV1{
		PlanId: request.GetPlan().GetPlanId(), PlanDigestSha256: request.GetPlan().GetPlanDigestSha256(), LogicalPageId: request.GetLogicalPageId(), RequestIntentDigest: request.GetRequestIntentDigest(),
		Records: []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", Attributes: map[string]string{
			"allow_email_verified_users_to_join": "false", "allow_invites_from": "adminsAndGuestInviters", "allowed_to_sign_up_email": "false", "allowed_to_use_sspr": "true", "block_msol_powershell": "true", "default_user_can_create_apps": "false", "default_user_can_create_groups": "false", "default_user_can_read_bitlocker": "true", "family": "authorization_policy", "resource_id": "authorizationPolicy", "resource_name": "authorizationPolicy", "resource_provider": "azure", "resource_type": "authorization_policy",
		}, PayloadJson: goTypedAuthorizationPolicyPayload(w.responseBody)}},
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

func goTypedAuthorizationPolicyPayload(body []byte) []byte {
	var input map[string]any
	if err := json.Unmarshal(body, &input); err != nil {
		panic(err)
	}
	valueOrNull := func(key string) any {
		if value, ok := input[key]; ok {
			return value
		}
		return nil
	}
	payload := map[string]any{
		"id": "authorizationPolicy", "allowInvitesFrom": "", "guestUserRoleId": "",
		"allowedToSignUpEmailBasedSubscriptions": valueOrNull("allowedToSignUpEmailBasedSubscriptions"),
		"allowedToUseSSPR": valueOrNull("allowedToUseSSPR"),
		"allowEmailVerifiedUsersToJoinOrganization": valueOrNull("allowEmailVerifiedUsersToJoinOrganization"),
		"blockMsolPowerShell": valueOrNull("blockMsolPowerShell"),
		"defaultUserRolePermissions": valueOrNull("defaultUserRolePermissions"),
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
		panic(err)
	}
	return encoded
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
	return err != nil && strings.Contains(err.Error(), ErrInvalidExecution.Error())
}
func errorsNewRedirect() error { return fmt.Errorf("%w: redirect", ErrInvalidExecution) }
