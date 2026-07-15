package sourcegen

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestBuildProofBundleBindsReviewedProviderContract(t *testing.T) {
	request := normalizedRequest{
		Request: Request{SourceID: "example", SourceType: SourceTypeJSONAPI, AuthModel: AuthModelBearerToken},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status: "verified",
		},
		ProviderContract: &ProviderContractEvidence{
			LockDigest:  "contract-digest",
			DriftStatus: "unchanged",
			Reviewed:    true,
		},
	}
	bundle := buildProofBundle(request, generationManifest{
		GeneratorVersion: generatorVersion,
		SourceID:         "example",
		InputDigest:      "input-digest",
		Outputs:          map[string]string{"sources/example/source.go": "output-digest"},
	})
	if bundle.ProviderContract == nil || bundle.ProviderContract.LockDigest != "contract-digest" {
		t.Fatalf("provider contract evidence = %#v", bundle.ProviderContract)
	}
	for _, obligation := range bundle.Obligations {
		if obligation.ID == "provider.contract_lock" {
			if obligation.Status != ProofStatusPassed || obligation.Action != "" {
				t.Fatalf("provider contract obligation = %#v", obligation)
			}
			return
		}
	}
	t.Fatal("provider contract obligation not found")
}

func TestBuildProofBundleKeepsNewProviderContractPending(t *testing.T) {
	request := normalizedRequest{
		Request: Request{SourceID: "example", SourceType: SourceTypeJSONAPI, AuthModel: AuthModelBearerToken},
		ProviderContract: &ProviderContractEvidence{
			LockDigest:  "contract-digest",
			DriftStatus: "new",
		},
	}
	bundle := buildProofBundle(request, generationManifest{
		GeneratorVersion: generatorVersion,
		SourceID:         "example",
		InputDigest:      "input-digest",
		Outputs:          map[string]string{},
	})
	for _, obligation := range bundle.Obligations {
		if obligation.ID == "provider.contract_lock" {
			if obligation.Status != ProofStatusPending || obligation.Action == "" {
				t.Fatalf("provider contract obligation = %#v", obligation)
			}
			return
		}
	}
	t.Fatal("provider contract obligation not found")
}
