package sourceworker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const maxSafeIdentifierBytes = 128

func (receipt SafeReceipt) protobuf() *cerebrov1.SourceWorkerSafeReceiptV1 {
	return &cerebrov1.SourceWorkerSafeReceiptV1{
		PlanDigestSha256: receipt.PlanDigestSHA256, LogicalPageId: receipt.LogicalPageID,
		RequestIntentDigest: receipt.RequestIntentDigest, RuntimeGeneration: receipt.RuntimeGeneration,
		LeaseGeneration: receipt.LeaseGeneration, CredentialOperation: receipt.CredentialOperation,
		StatusCode: uint32(receipt.StatusCode), ResponseBytes: uint64(receipt.ResponseBytes), ResponseSha256: receipt.ResponseSHA256,
	}
}

func safeReceiptFromProto(receipt *cerebrov1.SourceWorkerSafeReceiptV1) (SafeReceipt, error) {
	if receipt == nil || receipt.GetResponseBytes() > uint64(^uint(0)>>1) {
		return SafeReceipt{}, fmt.Errorf("%w: worker receipt is invalid", ErrWorkerContract)
	}
	return SafeReceipt{
		PlanDigestSHA256: receipt.GetPlanDigestSha256(), LogicalPageID: receipt.GetLogicalPageId(),
		RequestIntentDigest: receipt.GetRequestIntentDigest(), RuntimeGeneration: receipt.GetRuntimeGeneration(),
		LeaseGeneration: receipt.GetLeaseGeneration(), CredentialOperation: receipt.GetCredentialOperation(),
		StatusCode: int(receipt.GetStatusCode()), ResponseBytes: int(receipt.GetResponseBytes()), ResponseSHA256: receipt.GetResponseSha256(),
	}, nil
}

func validateSafeReceipt(receipt SafeReceipt, plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, response []byte, statusCode int) error {
	sum := sha256.Sum256(response)
	if receipt.PlanDigestSHA256 != plan.GetPlanDigestSha256() || receipt.LogicalPageID != scope.LogicalPageID || receipt.RequestIntentDigest != scope.RequestIntentDigest || receipt.RuntimeGeneration != scope.RuntimeGeneration || receipt.LeaseGeneration != scope.LeaseGeneration || receipt.StatusCode != statusCode || receipt.ResponseBytes != len(response) || receipt.ResponseSHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("%w: safe receipt does not match the execution", ErrInvalidExecution)
	}
	if !safeIdentifier(receipt.CredentialOperation) || !lowerSHA256(receipt.PlanDigestSHA256) || !lowerSHA256(receipt.RequestIntentDigest) || !lowerSHA256(receipt.ResponseSHA256) {
		return fmt.Errorf("%w: safe receipt metadata is invalid", ErrInvalidExecution)
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maxSafeIdentifierBytes {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || char == ':' {
			continue
		}
		return false
	}
	return true
}

func lowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func responseSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
