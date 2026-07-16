package proof

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/testauthor"
)

func TestRunnerProvesReproducibleFailThenPass(t *testing.T) {
	generated := 0
	var probed []string
	runner, err := NewRunner(
		func(context.Context, testauthor.TestSpec) ([]byte, error) {
			generated++
			return []byte("generated-test"), nil
		},
		func(_ context.Context, reference string, artifact []byte) (ProbeResult, error) {
			if string(artifact) != "generated-test" {
				t.Fatalf("probe artifact = %q, want generated test", artifact)
			}
			probed = append(probed, reference)
			return ProbeResult{Passed: reference == "protected", Detail: reference + " result"}, nil
		},
	)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	result, err := runner.Run(context.Background(), Request{
		Spec:           proofSpec(),
		Mode:           ModeRevision,
		UnprotectedRef: "unprotected",
		ProtectedRef:   "protected",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if generated != 2 {
		t.Fatalf("generate calls = %d, want 2", generated)
	}
	if !reflect.DeepEqual(probed, []string{"unprotected", "protected"}) {
		t.Fatalf("probe refs = %v, want unprotected then protected", probed)
	}
	if len(result.ArtifactDigest) != 64 {
		t.Fatalf("artifact digest length = %d, want 64", len(result.ArtifactDigest))
	}
	if len(result.Receipts) != 3 {
		t.Fatalf("receipt count = %d, want 3", len(result.Receipts))
	}
	for _, receipt := range result.Receipts {
		if receipt.Status != testauthor.ReceiptPassed {
			t.Fatalf("receipt = %#v, want passed", receipt)
		}
	}
}

func TestRunnerRejectsNonReproducibleArtifactBeforeProbe(t *testing.T) {
	generated := 0
	probed := false
	runner, err := NewRunner(
		func(context.Context, testauthor.TestSpec) ([]byte, error) {
			generated++
			if generated == 1 {
				return []byte("first"), nil
			}
			return []byte("second"), nil
		},
		func(context.Context, string, []byte) (ProbeResult, error) {
			probed = true
			return ProbeResult{}, nil
		},
	)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	result, err := runner.Run(context.Background(), proofRequest())
	if !errors.Is(err, ErrNonReproducible) {
		t.Fatalf("Run() error = %v, want ErrNonReproducible", err)
	}
	if probed {
		t.Fatal("probe called for non-reproducible artifact")
	}
	if len(result.Receipts) != 1 || result.Receipts[0].Status != testauthor.ReceiptFailed {
		t.Fatalf("receipts = %#v, want failed reproducibility receipt", result.Receipts)
	}
}

func TestRunnerRecordsBothUnexpectedProofOutcomes(t *testing.T) {
	runner, err := NewRunner(
		func(context.Context, testauthor.TestSpec) ([]byte, error) { return []byte("test"), nil },
		func(_ context.Context, reference string, _ []byte) (ProbeResult, error) {
			return ProbeResult{Passed: reference == "unprotected"}, nil
		},
	)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	result, err := runner.Run(context.Background(), proofRequest())
	if !errors.Is(err, ErrUnexpectedOutcome) {
		t.Fatalf("Run() error = %v, want ErrUnexpectedOutcome", err)
	}
	if len(result.Receipts) != 3 {
		t.Fatalf("receipt count = %d, want 3", len(result.Receipts))
	}
	if result.Receipts[1].Status != testauthor.ReceiptFailed || result.Receipts[2].Status != testauthor.ReceiptFailed {
		t.Fatalf("proof receipts = %#v, want both failed", result.Receipts[1:])
	}
}

func TestRunnerRejectsInvalidRequestBeforeGeneration(t *testing.T) {
	generated := false
	runner, err := NewRunner(
		func(context.Context, testauthor.TestSpec) ([]byte, error) {
			generated = true
			return []byte("test"), nil
		},
		func(context.Context, string, []byte) (ProbeResult, error) { return ProbeResult{}, nil },
	)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	request := proofRequest()
	request.ProtectedRef = request.UnprotectedRef
	if _, err := runner.Run(context.Background(), request); err == nil {
		t.Fatal("Run() error = nil, want invalid references")
	}
	if generated {
		t.Fatal("generator called for invalid request")
	}
}

func proofRequest() Request {
	return Request{
		Spec:           proofSpec(),
		Mode:           ModeMutation,
		UnprotectedRef: "unprotected",
		ProtectedRef:   "protected",
	}
}

func proofSpec() testauthor.TestSpec {
	return testauthor.TestSpec{
		APIVersion: testauthor.APIVersion,
		ID:         "finding-rule-unrelated-close",
		Family:     testauthor.FamilyFindingRule,
		Subject:    "example-risk",
		Behavior:   "unrelated evidence does not close the finding",
		Signal: testauthor.Signal{
			Kind:      testauthor.SignalMutationSurvivor,
			Reference: "mutation/unrelated-close",
		},
		Oracle: testauthor.Oracle{
			Kind:      testauthor.OracleLifecycleContract,
			Assertion: "finding_status == open",
		},
		Fixture: testauthor.Fixture{
			Kind:      testauthor.FixtureSyntheticEventSequence,
			SchemaRef: "example/synthetic/v1",
		},
		Generator: testauthor.Generator{Name: "finding_rule_fixture", Version: "v1"},
	}
}
