// Package compliancecontract publishes discovery metadata for generated
// compliance contracts and their runtime registration state.
package compliancecontract

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/authz"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/complianceread"
)

// VersionResponse returns bootstrap build metadata and whether the compliance
// read repository capability registered its generated handler.
func VersionResponse(registered bool) *cerebrov1.GetVersionResponse {
	routeState := cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_CONTRACT_ONLY
	if registered {
		routeState = cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_REGISTERED
	}
	return &cerebrov1.GetVersionResponse{
		ServiceName: buildinfo.ServiceName,
		Version:     buildinfo.Version,
		Commit:      buildinfo.Commit,
		BuildDate:   buildinfo.BuildDate,
		ApiVersion:  buildinfo.APIVersion,
		ComplianceReads: &cerebrov1.ComplianceReadContract{
			ServiceName: "cerebro.v1.ComplianceReadService",
			RouteState:  routeState,
			RequiredScopes: []string{
				authz.ScopeComplianceProgramsRead,
				authz.ScopeComplianceEvidenceRead,
				authz.ScopeComplianceAssessmentsRead,
				authz.ScopeComplianceWorkRead,
			},
		},
	}
}

// VersionResponseFor reports registration from the composed store capability.
func VersionResponseFor(value complianceread.StateStore) *cerebrov1.GetVersionResponse {
	return VersionResponse(complianceread.RepositoryFrom(value) != nil)
}
