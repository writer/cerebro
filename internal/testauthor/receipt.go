package testauthor

import (
	"fmt"
	"strings"
)

type ReceiptStatus string

const (
	ReceiptPassed ReceiptStatus = "passed"
	ReceiptFailed ReceiptStatus = "failed"
)

type ValidationReceipt struct {
	SpecID           string        `json:"spec_id"`
	SpecDigest       string        `json:"spec_digest"`
	Gate             string        `json:"gate"`
	Status           ReceiptStatus `json:"status"`
	Detail           string        `json:"detail,omitempty"`
	Generator        string        `json:"generator"`
	GeneratorVersion string        `json:"generator_version"`
}

func NewValidationReceipt(spec TestSpec, gate string, status ReceiptStatus, detail string) (ValidationReceipt, error) {
	spec = spec.Normalize()
	digest, err := spec.Digest()
	if err != nil {
		return ValidationReceipt{}, err
	}
	gate = strings.TrimSpace(gate)
	if gate == "" {
		return ValidationReceipt{}, fmt.Errorf("validation receipt gate is required")
	}
	if status != ReceiptPassed && status != ReceiptFailed {
		return ValidationReceipt{}, fmt.Errorf("unsupported validation receipt status %q", status)
	}
	return ValidationReceipt{
		SpecID:           spec.ID,
		SpecDigest:       digest,
		Gate:             gate,
		Status:           status,
		Detail:           strings.TrimSpace(detail),
		Generator:        spec.Generator.Name,
		GeneratorVersion: spec.Generator.Version,
	}, nil
}
