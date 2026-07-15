// Package reproproof runs deterministic and mutation-based proofs against
// sourcegen using minimal connector definitions.
package reproproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

const (
	ProofStatusPassed = "passed"
	ProofStatusFailed = "failed"
)

// Report records sourcegen invariance and mutation-gate results.
type Report struct {
	Cases  []CaseProof `json:"cases"`
	Passed int         `json:"passed"`
	Failed int         `json:"failed"`
}

// CaseProof is one named input transformation or rejected mutation.
type CaseProof struct {
	ID             string `json:"id"`
	Transformation string `json:"transformation"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

// Prove runs the sourcegen reproducibility and mutation suite under outputRoot.
func Prove(outputRoot string) (Report, error) {
	if strings.TrimSpace(outputRoot) == "" {
		return Report{}, fmt.Errorf("sourcegen reproducibility output root is required")
	}
	if err := os.MkdirAll(outputRoot, 0o750); err != nil {
		return Report{}, err
	}
	report := Report{}
	run := func(id string, transformation string, prove func() error) {
		result := CaseProof{ID: id, Transformation: transformation, Status: ProofStatusPassed}
		if err := prove(); err != nil {
			result.Status = ProofStatusFailed
			result.Error = err.Error()
			report.Failed++
		} else {
			report.Passed++
		}
		report.Cases = append(report.Cases, result)
	}

	run("output_root_invariance", "render the same normalized definition under two output roots", func() error {
		first, err := generateProof(filepath.Join(outputRoot, "root-a"), fixtureDefinition(), fixtureContractEvidence())
		if err != nil {
			return err
		}
		second, err := generateProof(filepath.Join(outputRoot, "root-b"), fixtureDefinition(), fixtureContractEvidence())
		if err != nil {
			return err
		}
		return equalProof(first, second)
	})

	run("normalized_input_invariance", "add equivalent whitespace and casing to normalized connector fields", func() error {
		first, err := generateProof(filepath.Join(outputRoot, "normalized-a"), fixtureDefinition(), fixtureContractEvidence())
		if err != nil {
			return err
		}
		variant := fixtureDefinition()
		variant.SourceID = " repro_source "
		variant.DisplayName = " Repro source "
		variant.Auth.Model = " bearer_token "
		variant.ResourceFamilies[0].Method = " get "
		variant.ResourceFamilies[0].Path = " /v1/resources "
		evidence := fixtureContractEvidence()
		evidence.LockDigest = " contract-digest "
		evidence.DriftStatus = " unchanged "
		second, err := generateProof(filepath.Join(outputRoot, "normalized-b"), variant, evidence)
		if err != nil {
			return err
		}
		return equalProof(first, second)
	})

	run("map_order_invariance", "rebuild equivalent transport and projection maps in reverse insertion order", func() error {
		first, err := generateProof(filepath.Join(outputRoot, "maps-a"), fixtureDefinition(), fixtureContractEvidence())
		if err != nil {
			return err
		}
		variant := fixtureDefinition()
		variant.Transport.Headers = map[string]string{}
		variant.Transport.Headers["X-Zone"] = "${config.zone}"
		variant.Transport.Headers["Accept"] = "application/json"
		variant.ResourceFamilies[0].Projection.Fields = map[string]string{}
		variant.ResourceFamilies[0].Projection.Fields["name"] = "name"
		variant.ResourceFamilies[0].Projection.Fields["id"] = "id"
		second, err := generateProof(filepath.Join(outputRoot, "maps-b"), variant, fixtureContractEvidence())
		if err != nil {
			return err
		}
		return equalProof(first, second)
	})

	run("regeneration_idempotence", "regenerate unchanged inputs in the same output root", func() error {
		root := filepath.Join(outputRoot, "repeat")
		first, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
			Definition:       fixtureDefinition(),
			ProviderContract: fixtureContractEvidence(),
			OutputDir:        root,
		})
		if err != nil {
			return err
		}
		firstProof, err := os.ReadFile(first.ProofBundle) // #nosec G304 -- proof path is generated beneath outputRoot.
		if err != nil {
			return err
		}
		second, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
			Definition:       fixtureDefinition(),
			ProviderContract: fixtureContractEvidence(),
			OutputDir:        root,
		})
		if err != nil {
			return err
		}
		for _, change := range second.ChangePlan.Changes {
			if change.Action != sourcegen.ChangeActionUnchanged {
				return fmt.Errorf("%s action is %s", change.Path, change.Action)
			}
		}
		secondProof, err := os.ReadFile(second.ProofBundle) // #nosec G304 -- proof path is generated beneath outputRoot.
		if err != nil {
			return err
		}
		return equalProof(firstProof, secondProof)
	})

	run("auth_credential_mutation", "remove the required bearer credential field", func() error {
		mutation := fixtureDefinition()
		mutation.Auth.CredentialFields = nil
		_, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{Definition: mutation, OutputDir: filepath.Join(outputRoot, "mutation-auth"), DryRun: true})
		if err == nil {
			return fmt.Errorf("sourcegen accepted a bearer auth definition without a credential field")
		}
		return nil
	})

	run("unstable_identity_mutation", "replace a stable projection identity with a timestamp", func() error {
		mutation := fixtureDefinition()
		mutation.ResourceFamilies[0].Projection.Entity = &connectordefinitions.ProjectionEntitySpec{
			EntityType:   "runtime.resource",
			URNKind:      "resource",
			IDAttributes: []string{"timestamp"},
		}
		_, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{Definition: mutation, OutputDir: filepath.Join(outputRoot, "mutation-identity"), DryRun: true})
		if err == nil {
			return fmt.Errorf("sourcegen accepted an ephemeral projection identity")
		}
		return nil
	})

	run("generated_output_mutation", "modify one sourcegen-owned output before regeneration", func() error {
		root := filepath.Join(outputRoot, "mutation-output")
		_, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{Definition: fixtureDefinition(), OutputDir: root})
		if err != nil {
			return err
		}
		path := filepath.Join(root, "sources", "repro_source", "source.go")
		if err := os.WriteFile(path, []byte("package reprosource\n\n// operator mutation\n"), 0o600); err != nil {
			return err
		}
		_, err = sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{Definition: fixtureDefinition(), OutputDir: root})
		if err == nil {
			return fmt.Errorf("regeneration succeeded, want generated-output ownership rejection")
		}
		if !errors.Is(err, sourcegen.ErrGeneratedOutputModified) {
			return fmt.Errorf("regeneration returned the wrong error: %w", err)
		}
		return nil
	})

	return report, nil
}

func generateProof(root string, definition connectordefinitions.Definition, evidence *sourcegen.ProviderContractEvidence) ([]byte, error) {
	result, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition:       definition,
		ProviderContract: evidence,
		OutputDir:        root,
	})
	if err != nil {
		return nil, err
	}
	return os.ReadFile(result.ProofBundle) // #nosec G304 -- proof path is generated beneath the caller-owned root.
}

func equalProof(first []byte, second []byte) error {
	if string(first) != string(second) {
		return fmt.Errorf("proof bundles differ")
	}
	return nil
}

func fixtureContractEvidence() *sourcegen.ProviderContractEvidence {
	return &sourcegen.ProviderContractEvidence{LockDigest: "contract-digest", DriftStatus: "unchanged", Reviewed: true}
}

func fixtureDefinition() connectordefinitions.Definition {
	definition := connectordefinitions.Definition{
		SchemaVersion:  connectordefinitions.SchemaVersionIntegrationV1,
		ID:             "builtin-repro_source",
		TenantID:       "builtin",
		SourceID:       "repro_source",
		DisplayName:    "Repro source",
		Runtime:        connectordefinitions.RuntimeJSONAPI,
		Stage:          connectordefinitions.StageDraft,
		CurrentVersion: 1,
		ConfigFields: []connectordefinitions.Field{
			{Key: "account", Required: true},
			{Key: "zone"},
		},
		Auth: connectordefinitions.AuthSpec{
			Model: "bearer_token",
			CredentialFields: []connectordefinitions.Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: "https://api.example.test",
			Headers: map[string]string{"Accept": "application/json", "X-Zone": "${config.zone}"},
			Verification: &connectordefinitions.VerificationSpec{
				Path: "/v1/resources",
			},
		},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:     "verified",
			Basis:      "detected",
			Transport:  "rest",
			Auth:       "bearer_token",
			BaseURL:    "https://api.example.test",
			SpecURL:    "https://api.example.test/openapi.json",
			SpecKind:   "openapi",
			References: []string{"https://api.example.test/openapi.json"},
			Families: []connectordefinitions.ProviderAPIFamilySpec{{
				ID:     "resources",
				Method: "GET",
				Path:   "/v1/resources",
			}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "resources",
			Path:           "/v1/resources",
			Method:         "GET",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "name",
			StaticQuery:    map[string]string{"active": "true", "type": "resource"},
			Pagination: &connectordefinitions.PaginationSpec{
				Type:           "cursor",
				CursorParam:    "cursor",
				CursorJSONPath: "$.next_cursor",
			},
			Incremental: &connectordefinitions.IncrementalSpec{
				State:       "high_watermark",
				CursorField: "updated_at",
				RequestKey:  "updated_after",
				RequestIn:   "query",
			},
			Event: connectordefinitions.EventMappingSpec{
				Kind:                  "repro_source.resources",
				SchemaRef:             "repro_source/resources/v1",
				RequiredAttributes:    []string{"resource_id", "resource_name"},
				RequiredPayloadFields: []string{"id"},
			},
			Projection: &connectordefinitions.ProjectionSpec{
				Template: "asset",
				Fields:   map[string]string{"id": "id", "name": "name"},
			},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				ID:             "resources",
				Type:           "entity_family",
				Title:          "Resources",
				Families:       []string{"resources"},
				Support:        "supported",
				HighValue:      true,
				EvidenceTypes:  []string{"asset_inventory"},
				ControlDomains: []string{"asset_inventory"},
			}},
		}},
	}
	return cloneDefinition(definition)
}

func cloneDefinition(definition connectordefinitions.Definition) connectordefinitions.Definition {
	payload, _ := json.Marshal(definition)
	var cloned connectordefinitions.Definition
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}
