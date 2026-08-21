package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func TestAuthorizationPolicyWorkerEventMatchesGoOracleSemantics(t *testing.T) {
	providerBody := []byte(`{
		"id":"authorizationPolicy",
		"allowInvitesFrom":"adminsAndGuestInviters",
		"allowedToSignUpEmailBasedSubscriptions":false,
		"allowedToUseSSPR":true,
		"blockMsolPowerShell":true,
		"defaultUserRolePermissions":{"allowedToCreateApps":false},
		"guestUserRoleId":null,
		"unknownProviderField":"discarded-by-typed-go-remarshal"
	}`)
	var record authorizationPolicyRecord
	if err := json.Unmarshal(providerBody, &record); err != nil {
		t.Fatal(err)
	}
	typedRaw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	record.raw = typedRaw
	goEvent, err := authorizationPolicyEvent(settings{tenantID: "tenant-1"}, record)
	if err != nil {
		t.Fatal(err)
	}

	plan := sourceworker.AzureAuthorizationPolicyPlan()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := sourceworker.CredentialScope{
		TenantID: "tenant-1", RuntimeID: "runtime-1", SourceID: "azure", FamilyID: "authorization_policy",
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: "logical-page-1", LeaseOwner: "owner-1",
		RuntimeGeneration: 7, LeaseGeneration: 11, LeaseExpiresAt: now.Add(time.Minute),
	}
	request := &cerebrov1.SourceWorkerHTTPRequestV1{
		PlanId: plan.GetPlanId(), Method: "GET", Url: "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
		Accept: "application/json", MaxResponseBytes: plan.GetMaxResponseBytes(), PlanDigestSha256: plan.GetPlanDigestSha256(),
	}
	scope.RequestIntentDigest, err = sourceworker.CanonicalRequestIntentDigest(plan, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	responseSum := sha256.Sum256(providerBody)
	receipt := sourceworker.SafeReceipt{
		PlanDigestSHA256: plan.GetPlanDigestSha256(), LogicalPageID: scope.LogicalPageID,
		RequestIntentDigest: scope.RequestIntentDigest, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, CredentialOperation: "lease-operation-1",
		StatusCode: 200, ResponseBytes: len(providerBody), ResponseSHA256: hex.EncodeToString(responseSum[:]),
	}
	attributes := make(map[string]string, len(goEvent.Attributes)-1)
	for key, value := range goEvent.Attributes {
		if key != "domain" {
			attributes[key] = value
		}
	}
	result := &cerebrov1.SourceWorkerDecodeResultV1{
		PlanId: plan.GetPlanId(), PlanDigestSha256: plan.GetPlanDigestSha256(), LogicalPageId: scope.LogicalPageID,
		RequestIntentDigest: scope.RequestIntentDigest,
		Records:             []*cerebrov1.SourceWorkerRecordV1{{ProviderId: "authorizationPolicy", Attributes: attributes, PayloadJson: typedRaw}},
	}
	result.ResultDigestSha256, err = sourceworker.CanonicalResultDigest(result, receipt)
	if err != nil {
		t.Fatal(err)
	}
	workerEvent, err := sourceworker.AuthorizationPolicyEvent(plan, scope, receipt, result, goEvent.OccurredAt.AsTime())
	if err != nil {
		t.Fatal(err)
	}
	if workerEvent.Id != goEvent.Id || workerEvent.TenantId != goEvent.TenantId || workerEvent.SourceId != goEvent.SourceId || workerEvent.Kind != goEvent.Kind || workerEvent.SchemaRef != goEvent.SchemaRef || !reflect.DeepEqual(workerEvent.Attributes, goEvent.Attributes) {
		t.Fatalf("worker event identity or attributes differ: worker=%#v go=%#v", workerEvent, goEvent)
	}
	var workerPayload, goPayload any
	if err := json.Unmarshal(workerEvent.Payload, &workerPayload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(goEvent.Payload, &goPayload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(workerPayload, goPayload) {
		t.Fatalf("worker payload = %#v, go payload = %#v", workerPayload, goPayload)
	}
}
