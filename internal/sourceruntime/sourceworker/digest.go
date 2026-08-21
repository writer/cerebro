package sourceworker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// CanonicalRequestIntentDigest binds the exact compiled plan, fenced scope,
// and credential-free HTTP request before credential redemption.
func CanonicalRequestIntentDigest(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, request *cerebrov1.SourceWorkerHTTPRequestV1) (string, error) {
	if plan == nil || request == nil {
		return "", fmt.Errorf("%w: request intent inputs are incomplete", ErrInvalidExecution)
	}
	planWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("%w: compiled plan cannot be encoded", ErrInvalidExecution)
	}
	requestWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("%w: worker request cannot be encoded", ErrInvalidExecution)
	}
	hasher := sha256.New()
	for _, value := range [][]byte{
		planWire,
		[]byte(scope.TenantID),
		[]byte(scope.RuntimeID),
		[]byte(scope.SourceID),
		[]byte(scope.FamilyID),
		[]byte(scope.PlanDigestSHA256),
		[]byte(scope.LogicalPageID),
		[]byte(scope.LeaseOwner),
		u64Bytes(scope.RuntimeGeneration),
		u64Bytes(scope.LeaseGeneration),
		i64Bytes(scope.LeaseExpiresAt.UTC().UnixNano()),
		requestWire,
	} {
		writeDigestField(hasher, value)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CanonicalResultDigest binds normalized records and continuation to the safe
// receipt produced by the trusted host. Attribute keys are sorted explicitly.
func CanonicalResultDigest(result *cerebrov1.SourceWorkerDecodeResultV1, receipt SafeReceipt) (string, error) {
	if result == nil {
		return "", fmt.Errorf("%w: worker result is missing", ErrInvalidExecution)
	}
	hasher := sha256.New()
	for _, value := range [][]byte{
		[]byte(receipt.PlanDigestSHA256),
		[]byte(receipt.LogicalPageID),
		[]byte(receipt.RequestIntentDigest),
		u64Bytes(receipt.RuntimeGeneration),
		u64Bytes(receipt.LeaseGeneration),
		[]byte(receipt.CredentialOperation),
		u64Bytes(uint64(receipt.StatusCode)),
		u64Bytes(uint64(receipt.ResponseBytes)),
		[]byte(receipt.ResponseSHA256),
		[]byte(result.GetNextCursor()),
		u64Bytes(uint64(len(result.GetRecords()))),
	} {
		writeDigestField(hasher, value)
	}
	for _, record := range result.GetRecords() {
		if record == nil {
			return "", fmt.Errorf("%w: worker result contains a nil record", ErrInvalidExecution)
		}
		writeDigestField(hasher, []byte(record.GetProviderId()))
		keys := make([]string, 0, len(record.GetAttributes()))
		for key := range record.GetAttributes() {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		writeDigestField(hasher, u64Bytes(uint64(len(keys))))
		for _, key := range keys {
			writeDigestField(hasher, []byte(key))
			writeDigestField(hasher, []byte(record.GetAttributes()[key]))
		}
		writeDigestField(hasher, record.GetPayloadJson())
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeDigestField(hasher hash.Hash, value []byte) {
	_, _ = hasher.Write(u64Bytes(uint64(len(value))))
	_, _ = hasher.Write(value)
}

func u64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func i64Bytes(value int64) []byte { return u64Bytes(uint64(value)) }

func canonicalRequestForPlan(plan *cerebrov1.SourceExecutionPlanV1) *cerebrov1.SourceWorkerHTTPRequestV1 {
	return &cerebrov1.SourceWorkerHTTPRequestV1{
		PlanId: plan.GetPlanId(), Method: "GET", Url: "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
		Accept: "application/json", MaxResponseBytes: plan.GetMaxResponseBytes(), PlanDigestSha256: plan.GetPlanDigestSha256(),
	}
}

func executionPlanDigest(plan *cerebrov1.SourceExecutionPlanV1) string {
	clone := proto.Clone(plan).(*cerebrov1.SourceExecutionPlanV1)
	clone.PlanDigestSha256 = ""
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		panic("compiled source execution plan cannot be encoded: " + err.Error())
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
