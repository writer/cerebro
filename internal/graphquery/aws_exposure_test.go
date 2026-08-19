package graphquery

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type awsExposureStubStore struct {
	requests         []ports.CypherQueryRequest
	responses        [][]ports.CypherRow
	exposureRequests []ports.ExposureCoverageRequest
	result           *ports.ExposureCoverageResult
	err              error
	rawReads         int
}

func (s *awsExposureStubStore) Ping(context.Context) error { return s.err }

func (s *awsExposureStubStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}

func (s *awsExposureStubStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.rawReads++
	s.requests = append(s.requests, request)
	if s.err != nil {
		return nil, s.err
	}
	if len(s.responses) == 0 {
		return nil, nil
	}
	rows := s.responses[0]
	s.responses = s.responses[1:]
	return rows, nil
}

func (s *awsExposureStubStore) CompareExposureCoverage(_ context.Context, request ports.ExposureCoverageRequest) (*ports.ExposureCoverageResult, error) {
	s.exposureRequests = append(s.exposureRequests, request)
	return s.result, s.err
}

func (s *awsExposureStubStore) ListEntities(context.Context, ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	return nil, nil
}

func (s *awsExposureStubStore) CountEntityKinds(context.Context, ports.EntityKindCountRequest) (*ports.EntityKindCountPage, error) {
	return nil, nil
}

func (s *awsExposureStubStore) ListEntityRelations(context.Context, ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	return nil, nil
}

func TestGetAWSPublicEndpointInsightsRequiresTenant(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetAWSPublicEndpointInsightsUsesOneTypedBoundedRead(t *testing.T) {
	entity := func(kind, id string) ports.ExposureCoverageEntity {
		return ports.ExposureCoverageEntity{URN: "urn:cerebro:writer:" + kind + ":" + id, EntityType: kind, Label: id}
	}
	store := &awsExposureStubStore{result: &ports.ExposureCoverageResult{
		TenantID:      "writer",
		GraphRevision: 42,
		Counts: ports.ExposureCoverageCounts{
			PrimaryEntities: 7, Indicators: 8, HostIndicators: 6, IPIndicators: 2,
			OverlappingPrimaryEntities: 3, OverlappingIndicators: 4, OverlappingCorroboratingEntities: 5,
		},
		TypeCounts: []ports.ExposureCoverageKindCount{{EntityKind: "aws.application.load.balancer", Count: 4}},
		Overlaps: []ports.ExposureCoverageOverlap{{
			Primary: entity("aws.application.load.balancer", "alb"), Indicator: entity("internet.host", "app.example.com"), Corroborating: entity("external.asset", "app.example.com"),
		}},
		PrimaryOnly:       []ports.ExposureCoveragePair{{Primary: entity("aws.elastic.ip", "eipalloc-1"), Indicator: entity("internet.ip", "192.0.2.10")}},
		CorroboratingOnly: []ports.ExposureCoverageCorroboratingOnly{{Corroborating: entity("external.asset", "missing.example.com"), Indicator: entity("internet.host", "missing.example.com")}},
		Accounts:          []ports.ExposureCoverageAccount{{Account: entity("cloud.account", "account-a"), PrimaryEntities: 9, CorroboratingObservations: 2}},
		Completeness:      ports.ExposureCoverageCompleteness{PrimaryOnlyTruncated: true},
	}}

	result, err := New(store).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{
		TenantID: "writer", AccountID: " account-a ", Region: " us-east-1 ", Search: " App ", Limit: 250,
	})
	if err != nil {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v", err)
	}
	if len(store.exposureRequests) != 1 || store.rawReads != 0 {
		t.Fatalf("typed requests = %d, raw reads = %d; want 1, 0", len(store.exposureRequests), store.rawReads)
	}
	request := store.exposureRequests[0]
	if request.TenantID != "writer" || request.AccountID != "account-a" || request.Region != "us-east-1" || request.Query != "App" || request.Limit != maxAWSExposureLimit {
		t.Fatalf("typed request = %#v", request)
	}
	if request.Profile.PrimarySourceID != "aws" || request.Profile.CorroboratingSourceID != "vulnview" || len(request.Profile.IndicatorKinds) != 2 {
		t.Fatalf("typed profile = %#v", request.Profile)
	}
	if result.GraphRevision != 42 || result.Counts.AWSEndpoints != 7 || result.Counts.OverlappingVulnViewAssets != 5 {
		t.Fatalf("result counts/revision = %#v", result)
	}
	if len(result.Overlaps) != 1 || result.NeighborhoodURN != "urn:cerebro:writer:internet.host:app.example.com" {
		t.Fatalf("overlaps/neighborhood = %#v, %q", result.Overlaps, result.NeighborhoodURN)
	}
	if !result.Completeness.AWSOnlyTruncated || len(result.CloudAccounts) != 1 || result.CloudAccounts[0].VulnViewScans != 2 {
		t.Fatalf("completeness/accounts = %#v, %#v", result.Completeness, result.CloudAccounts)
	}
}

func TestGetAWSPublicEndpointInsightsFailsClosedWithoutTypedStore(t *testing.T) {
	_, err := New(nil).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{TenantID: "writer"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestGetAWSPublicEndpointInsightsRejectsWrongTenant(t *testing.T) {
	store := &awsExposureStubStore{result: &ports.ExposureCoverageResult{TenantID: "other"}}
	_, err := New(store).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{TenantID: "writer"})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}
