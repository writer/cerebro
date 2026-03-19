package api

import (
	"context"
	"errors"

	"github.com/evalops/cerebro/internal/lineage"
)

var errLineageUnavailable = errors.New("lineage not initialized")

type lineageService interface {
	Available() error
	GetLineage(assetID string) (*lineage.AssetLineage, bool, error)
	GetLineageByCommit(commitSHA string) ([]*lineage.AssetLineage, error)
	GetLineageByImage(imageDigest string) ([]*lineage.AssetLineage, error)
	DetectDrift(ctx context.Context, assetID string, currentState map[string]interface{}, iacState map[string]interface{}) ([]lineage.DriftDetail, error)
}

type serverLineageService struct {
	deps *serverDependencies
}

func newLineageService(deps *serverDependencies) lineageService {
	return serverLineageService{deps: deps}
}

func (s serverLineageService) Available() error {
	if s.deps == nil || s.deps.Lineage == nil {
		return errLineageUnavailable
	}
	return nil
}

func (s serverLineageService) GetLineage(assetID string) (*lineage.AssetLineage, bool, error) {
	if err := s.Available(); err != nil {
		return nil, false, err
	}
	result, ok := s.deps.Lineage.GetLineage(assetID)
	return result, ok, nil
}

func (s serverLineageService) GetLineageByCommit(commitSHA string) ([]*lineage.AssetLineage, error) {
	if err := s.Available(); err != nil {
		return nil, err
	}
	return s.deps.Lineage.GetLineageByCommit(commitSHA), nil
}

func (s serverLineageService) GetLineageByImage(imageDigest string) ([]*lineage.AssetLineage, error) {
	if err := s.Available(); err != nil {
		return nil, err
	}
	return s.deps.Lineage.GetLineageByImage(imageDigest), nil
}

func (s serverLineageService) DetectDrift(ctx context.Context, assetID string, currentState map[string]interface{}, iacState map[string]interface{}) ([]lineage.DriftDetail, error) {
	if err := s.Available(); err != nil {
		return nil, err
	}
	return s.deps.Lineage.DetectDrift(ctx, assetID, currentState, iacState), nil
}

var _ lineageService = serverLineageService{}
