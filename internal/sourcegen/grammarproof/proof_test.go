package grammarproof

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestDefaultGrammarIsExecutable(t *testing.T) {
	grammar := connectordefinitions.DefaultGrammar()
	report, err := Prove(t.TempDir(), grammar)
	if err != nil {
		t.Fatalf("Prove() error = %v", err)
	}
	wantDeclared := len(grammar.Runtimes) + len(grammar.AuthModels) + len(grammar.Methods) + len(grammar.PaginationTypes) + len(grammar.IncrementalStates) + len(grammar.ProjectionTemplates)
	if report.DeclaredFeatures != wantDeclared {
		t.Fatalf("declared features = %d, want %d", report.DeclaredFeatures, wantDeclared)
	}
	if report.FailedFeatures != 0 || report.ProvenFeatures != report.DeclaredFeatures {
		for _, proof := range report.Proofs {
			if proof.Status == ProofStatusFailed {
				t.Logf("%s: %s", proof.FeatureID, proof.Error)
			}
		}
		t.Fatalf("grammar proof = %d proven, %d failed", report.ProvenFeatures, report.FailedFeatures)
	}
	if report.PairwiseWitnesses == 0 || report.FailedInteractions != 0 || report.ProvenInteractions != report.PairwiseWitnesses {
		for _, proof := range report.InteractionProofs {
			if proof.Status == ProofStatusFailed {
				t.Logf("%s: %v: %s", proof.WitnessSourceID, proof.Features, proof.Error)
			}
		}
		t.Fatalf("interaction proof = %d witnesses, %d proven, %d failed", report.PairwiseWitnesses, report.ProvenInteractions, report.FailedInteractions)
	}
}

func TestProveReportsUnsupportedDeclaredFeature(t *testing.T) {
	grammar := connectordefinitions.DefaultGrammar()
	grammar.AuthModels = append(grammar.AuthModels, "unsupported_auth")
	unsupported := proveWitness(t.TempDir(), grammar, witness{category: "auth", value: "unsupported_auth"})
	if unsupported.Status != ProofStatusFailed || unsupported.Error == "" {
		t.Fatalf("proof = %#v", unsupported)
	}
}
