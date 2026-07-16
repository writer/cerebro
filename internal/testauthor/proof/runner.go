package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/testauthor"
)

var (
	ErrNonReproducible   = errors.New("generated test artifact is not reproducible")
	ErrUnexpectedOutcome = errors.New("generated test produced an unexpected proof outcome")
)

type Mode string

const (
	ModeRevision Mode = "revision"
	ModeMutation Mode = "mutation"
)

type GenerateFunc func(context.Context, testauthor.TestSpec) ([]byte, error)

type ProbeFunc func(context.Context, string, []byte) (ProbeResult, error)

type ProbeResult struct {
	Passed bool
	Detail string
}

type Request struct {
	Spec           testauthor.TestSpec
	Mode           Mode
	UnprotectedRef string
	ProtectedRef   string
}

type Result struct {
	SpecID         string                         `json:"spec_id"`
	ArtifactDigest string                         `json:"artifact_digest,omitempty"`
	Receipts       []testauthor.ValidationReceipt `json:"receipts"`
}

type Runner struct {
	generate GenerateFunc
	probe    ProbeFunc
}

func NewRunner(generate GenerateFunc, probe ProbeFunc) (*Runner, error) {
	if generate == nil {
		return nil, errors.New("test proof generator is required")
	}
	if probe == nil {
		return nil, errors.New("test proof probe is required")
	}
	return &Runner{generate: generate, probe: probe}, nil
}

func (runner *Runner) Run(ctx context.Context, request Request) (Result, error) {
	if runner == nil || runner.generate == nil || runner.probe == nil {
		return Result{}, errors.New("test proof runner is not configured")
	}
	request.Spec = request.Spec.Normalize()
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	result := Result{SpecID: request.Spec.ID, Receipts: []testauthor.ValidationReceipt{}}

	first, err := runner.generate(ctx, request.Spec)
	if err != nil {
		return result, fmt.Errorf("generate test artifact: %w", err)
	}
	second, err := runner.generate(ctx, request.Spec)
	if err != nil {
		return result, fmt.Errorf("regenerate test artifact: %w", err)
	}
	if len(first) == 0 || !bytes.Equal(first, second) {
		receipt, receiptErr := testauthor.NewValidationReceipt(request.Spec, "reproducibility", testauthor.ReceiptFailed, "generation did not produce identical non-empty output")
		if receiptErr != nil {
			return result, errors.Join(ErrNonReproducible, receiptErr)
		}
		result.Receipts = append(result.Receipts, receipt)
		return result, ErrNonReproducible
	}
	sum := sha256.Sum256(first)
	result.ArtifactDigest = hex.EncodeToString(sum[:])
	receipt, err := testauthor.NewValidationReceipt(request.Spec, "reproducibility", testauthor.ReceiptPassed, "generated output is byte-identical")
	if err != nil {
		return result, err
	}
	result.Receipts = append(result.Receipts, receipt)

	proofErrs := make([]error, 0, 2)
	result, err = runner.probeTarget(ctx, result, request.Spec, "unprotected_target", request.UnprotectedRef, false, first)
	if err != nil {
		proofErrs = append(proofErrs, err)
	}
	result, err = runner.probeTarget(ctx, result, request.Spec, "protected_target", request.ProtectedRef, true, first)
	if err != nil {
		proofErrs = append(proofErrs, err)
	}
	return result, errors.Join(proofErrs...)
}

func (runner *Runner) probeTarget(ctx context.Context, result Result, spec testauthor.TestSpec, gate string, reference string, expectedPass bool, artifact []byte) (Result, error) {
	probe, err := runner.probe(ctx, reference, artifact)
	if err != nil {
		return result, fmt.Errorf("probe %s %q: %w", gate, reference, err)
	}
	status := testauthor.ReceiptPassed
	var outcomeErr error
	if probe.Passed != expectedPass {
		status = testauthor.ReceiptFailed
		outcomeErr = fmt.Errorf("%w: %s %q passed=%t, want %t", ErrUnexpectedOutcome, gate, reference, probe.Passed, expectedPass)
	}
	receipt, err := testauthor.NewValidationReceipt(spec, gate, status, probe.Detail)
	if err != nil {
		return result, errors.Join(outcomeErr, err)
	}
	result.Receipts = append(result.Receipts, receipt)
	return result, outcomeErr
}

func validateRequest(request Request) error {
	if err := request.Spec.Validate(); err != nil {
		return err
	}
	if request.Mode != ModeRevision && request.Mode != ModeMutation {
		return fmt.Errorf("unsupported test proof mode %q", request.Mode)
	}
	unprotected := strings.TrimSpace(request.UnprotectedRef)
	protected := strings.TrimSpace(request.ProtectedRef)
	if unprotected == "" {
		return errors.New("unprotected test proof reference is required")
	}
	if protected == "" {
		return errors.New("protected test proof reference is required")
	}
	if unprotected == protected {
		return errors.New("unprotected and protected test proof references must differ")
	}
	return nil
}
