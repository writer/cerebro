package sourceworker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const maxSafeIdentifierBytes = 128

func (receipt SafeReceipt) protobuf() (*cerebrov1.SourceWorkerSafeReceiptV1, error) {
	statusCode, err := safeUint32(receipt.StatusCode)
	if err != nil {
		return nil, err
	}
	responseBytes, err := safeUint64(receipt.ResponseBytes)
	if err != nil {
		return nil, err
	}
	return &cerebrov1.SourceWorkerSafeReceiptV1{
		PlanDigestSha256: receipt.PlanDigestSHA256, LogicalPageId: receipt.LogicalPageID,
		RequestIntentDigest: receipt.RequestIntentDigest, RuntimeGeneration: receipt.RuntimeGeneration,
		LeaseGeneration: receipt.LeaseGeneration, CredentialOperation: receipt.CredentialOperation,
		StatusCode: statusCode, ResponseBytes: responseBytes, ResponseSha256: receipt.ResponseSHA256,
	}, nil
}

func safeUint32(value int) (uint32, error) {
	var converted uint32
	if _, err := fmt.Sscan(strconv.Itoa(value), &converted); err != nil {
		return 0, fmt.Errorf("%w: status code is outside the worker protocol", ErrInvalidExecution)
	}
	return converted, nil
}

func safeUint64(value int) (uint64, error) {
	converted, err := strconv.ParseUint(strconv.Itoa(value), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: byte count is outside the worker protocol", ErrInvalidExecution)
	}
	return converted, nil
}

func safeReceiptFromProto(receipt *cerebrov1.SourceWorkerSafeReceiptV1) (SafeReceipt, error) {
	if receipt == nil {
		return SafeReceipt{}, fmt.Errorf("%w: worker receipt is invalid", ErrWorkerContract)
	}
	statusCode, err := safeProtocolInt(strconv.FormatUint(uint64(receipt.GetStatusCode()), 10), "status code")
	if err != nil {
		return SafeReceipt{}, err
	}
	responseBytes, err := safeProtocolInt(strconv.FormatUint(receipt.GetResponseBytes(), 10), "byte count")
	if err != nil {
		return SafeReceipt{}, err
	}
	return SafeReceipt{
		PlanDigestSHA256: receipt.GetPlanDigestSha256(), LogicalPageID: receipt.GetLogicalPageId(),
		RequestIntentDigest: receipt.GetRequestIntentDigest(), RuntimeGeneration: receipt.GetRuntimeGeneration(),
		LeaseGeneration: receipt.GetLeaseGeneration(), CredentialOperation: receipt.GetCredentialOperation(),
		StatusCode: statusCode, ResponseBytes: responseBytes, ResponseSHA256: receipt.GetResponseSha256(),
	}, nil
}

func safeProtocolInt(value, field string) (int, error) {
	converted, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is outside the worker protocol", ErrWorkerContract, field)
	}
	return converted, nil
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
