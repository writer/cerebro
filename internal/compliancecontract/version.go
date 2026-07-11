// Package compliancecontract publishes static discovery metadata for generated
// compliance contracts that are not yet backed by registered handlers.
package compliancecontract

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/authz"
	"github.com/writer/cerebro/internal/buildinfo"
)

// VersionResponse returns bootstrap build metadata plus the contract-only
// compliance read service declaration.
func VersionResponse() *cerebrov1.GetVersionResponse {
	return &cerebrov1.GetVersionResponse{
		ServiceName: buildinfo.ServiceName,
		Version:     buildinfo.Version,
		Commit:      buildinfo.Commit,
		BuildDate:   buildinfo.BuildDate,
		ApiVersion:  buildinfo.APIVersion,
		ComplianceReads: &cerebrov1.ComplianceReadContract{
			ServiceName: "cerebro.v1.ComplianceReadService",
			RouteState:  cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_CONTRACT_ONLY,
			RequiredScopes: []string{
				authz.ScopeComplianceProgramsRead,
				authz.ScopeComplianceEvidenceRead,
				authz.ScopeComplianceAssessmentsRead,
				authz.ScopeComplianceWorkRead,
			},
		},
	}
}
