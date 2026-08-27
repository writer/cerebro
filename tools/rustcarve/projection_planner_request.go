package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	projectionMigrationKind   = "projection"
	projectionCandidateStatus = "candidate"
	projectionBlockedStatus   = "blocked"
)

var projectionAuthorityGates = []string{
	"append_projection_checkpoint_order",
	"go_projection_registry_retired",
	"rust_projection_single_writer",
	"stale_lease_cannot_commit",
	"tenant_scoped_stable_identity",
}

var projectionRequiredReceipts = []string{
	"append_projection_checkpoint",
	"authenticated_product_read",
	"authority_promotion",
	"fixture_parity",
	"lease_restart",
	"projection_parity",
}

// projectionPlanRequest mirrors cerebro_migrator::PlanRequest v1. Keep this
// transport type closed and covered by the cross-contract schema test.
type projectionPlanRequest struct {
	Objective projectionPlanObjective `json:"objective"`
	Units     []projectionUnitSpec    `json:"units"`
}

type projectionPlanObjective struct {
	ProductionLineWeight    uint64 `json:"production_line_weight"`
	TestLineWeight          uint64 `json:"test_line_weight"`
	PackageWeight           uint64 `json:"package_weight"`
	RuntimeEntrypointWeight uint64 `json:"runtime_entrypoint_weight"`
	EffortWeight            uint64 `json:"effort_weight"`
}

type projectionUnitSpec struct {
	ID                    string                     `json:"id"`
	Kind                  string                     `json:"kind"`
	BaseSHA               string                     `json:"base_sha"`
	GoOwners              []string                   `json:"go_owners"`
	ProductionEntrypoints []string                   `json:"production_entrypoints"`
	RustOperation         string                     `json:"rust_operation"`
	ContractDigest        string                     `json:"contract_digest"`
	Prerequisites         []string                   `json:"prerequisites"`
	AuthorityGates        []string                   `json:"authority_gates"`
	RequiredReceipts      []string                   `json:"required_receipts"`
	DeletionTargets       []projectionDeletionTarget `json:"deletion_targets"`
	Benefit               projectionDeletionBenefit  `json:"benefit"`
	Effort                uint64                     `json:"effort"`
	Status                string                     `json:"status"`
	Blockers              []string                   `json:"blockers"`
}

type projectionDeletionTarget struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type projectionDeletionBenefit struct {
	ProductionLines    int `json:"production_lines"`
	TestLines          int `json:"test_lines"`
	Packages           int `json:"packages"`
	RuntimeEntrypoints int `json:"runtime_entrypoints"`
}

type projectionContract struct {
	SchemaVersion string   `json:"schema_version"`
	SourceID      string   `json:"source_id"`
	FamilyIDs     []string `json:"family_ids"`
	EventKinds    []string `json:"event_kinds"`
}

func buildProjectionPlanRequest(plan projectionBatchPlan) (projectionPlanRequest, error) {
	if !isFullLowerGitSHA(plan.RepositoryRevision) {
		return projectionPlanRequest{}, fmt.Errorf("projection planner request requires an exact repository base SHA")
	}
	request := projectionPlanRequest{
		Objective: projectionPlanObjective{ProductionLineWeight: 1, TestLineWeight: 1},
		Units:     make([]projectionUnitSpec, 0, len(plan.Batches)),
	}
	for _, batch := range plan.Batches {
		unit, err := buildProjectionUnit(plan.RepositoryRevision, batch)
		if err != nil {
			return projectionPlanRequest{}, err
		}
		request.Units = append(request.Units, unit)
	}
	return request, nil
}

func buildProjectionUnit(baseSHA string, batch projectionBatch) (projectionUnitSpec, error) {
	contract := projectionContract{
		SchemaVersion: "cerebro.rustcarve.projection-contract/v1",
		SourceID:      batch.SourceID,
		FamilyIDs:     append([]string(nil), batch.FamilyIDs...),
		EventKinds:    append([]string(nil), batch.EventKinds...),
	}
	contractPayload, err := json.Marshal(contract)
	if err != nil {
		return projectionUnitSpec{}, fmt.Errorf("marshal projection contract for %s: %w", batch.SourceID, err)
	}

	owners := append([]string(nil), batch.ImplementationFiles...)
	owners = append(owners, batch.TestFiles...)
	owners = append(owners, batch.ExcludedPaths...)
	sort.Strings(owners)
	owners = deduplicateSortedStrings(owners)

	paths := append([]string(nil), batch.ImplementationFiles...)
	paths = append(paths, batch.TestFiles...)
	sort.Strings(paths)
	targets := make([]projectionDeletionTarget, 0, len(paths))
	for _, path := range deduplicateSortedStrings(paths) {
		targets = append(targets, projectionDeletionTarget{Kind: "path", Path: path})
	}

	blockers := append([]string(nil), batch.Blockers...)
	for _, path := range batch.ExcludedPaths {
		blockers = append(blockers, "ownership_exclusion:"+path)
	}
	if len(targets) == 0 {
		blockers = append(blockers, "no_exact_deletion_targets")
	}
	sort.Strings(blockers)
	blockers = deduplicateSortedStrings(blockers)
	status := projectionCandidateStatus
	if len(blockers) != 0 {
		status = projectionBlockedStatus
	}

	return projectionUnitSpec{
		ID:                    "projection/" + batch.SourceID,
		Kind:                  projectionMigrationKind,
		BaseSHA:               baseSHA,
		GoOwners:              owners,
		ProductionEntrypoints: []string{"internal/sourceprojection/registry.go:RegisterConnectorDefinitions"},
		RustOperation:         "source_projection/" + batch.SourceID,
		ContractDigest:        "sha256:" + sha256Hex(contractPayload),
		Prerequisites:         []string{},
		AuthorityGates:        append([]string(nil), projectionAuthorityGates...),
		RequiredReceipts:      append([]string(nil), projectionRequiredReceipts...),
		DeletionTargets:       targets,
		Benefit: projectionDeletionBenefit{
			ProductionLines: batch.ProductionLines,
			TestLines:       batch.TestLines,
		},
		Effort:   uint64(len(batch.FamilyIDs)),
		Status:   status,
		Blockers: blockers,
	}, nil
}

func isFullLowerGitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func deduplicateSortedStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
