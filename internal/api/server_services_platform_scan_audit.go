package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/scanaudit"
)

var (
	errPlatformScanAuditStoreNotConfigured = errors.New("platform scan audit store not configured")
	errPlatformScanAuditStoreUnavailable   = errors.New("platform scan audit store unavailable")
)

type platformScanAuditService interface {
	ListRecords(ctx context.Context, opts scanaudit.ListOptions) ([]scanaudit.Record, error)
	ListUnifiedFindings(ctx context.Context, opts scanaudit.UnifiedFindingListOptions) ([]scanaudit.UnifiedFinding, error)
	GetRecord(ctx context.Context, namespace, runID string) (*scanaudit.Record, bool, error)
	ExportRecord(ctx context.Context, namespace, runID string) (*scanaudit.ExportPackage, error)
}

type serverPlatformScanAuditService struct {
	deps *serverDependencies
}

func newPlatformScanAuditService(deps *serverDependencies) platformScanAuditService {
	return serverPlatformScanAuditService{deps: deps}
}

func (s serverPlatformScanAuditService) ListRecords(ctx context.Context, opts scanaudit.ListOptions) ([]scanaudit.Record, error) {
	service, closeStore, err := s.service()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	records, err := service.ListRecords(ctx, opts)
	if err != nil {
		if errors.Is(err, scanaudit.ErrUnsupportedNamespace) {
			return nil, cerrors.E(cerrors.Op("api.platformScanAudit.ListRecords"), cerrors.ErrInvalidInput, err)
		}
		return nil, err
	}
	return records, nil
}

func (s serverPlatformScanAuditService) GetRecord(ctx context.Context, namespace, runID string) (*scanaudit.Record, bool, error) {
	service, closeStore, err := s.service()
	if err != nil {
		return nil, false, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	record, ok, err := service.GetRecord(ctx, namespace, runID)
	if err != nil {
		if errors.Is(err, scanaudit.ErrUnsupportedNamespace) {
			return nil, false, cerrors.E(cerrors.Op("api.platformScanAudit.GetRecord"), cerrors.ErrInvalidInput, err)
		}
		return nil, false, err
	}
	return record, ok, nil
}

func (s serverPlatformScanAuditService) ListUnifiedFindings(ctx context.Context, opts scanaudit.UnifiedFindingListOptions) ([]scanaudit.UnifiedFinding, error) {
	service, closeStore, err := s.service()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	findings, err := service.ListUnifiedFindings(ctx, opts)
	if err != nil {
		if errors.Is(err, scanaudit.ErrUnsupportedNamespace) {
			return nil, cerrors.E(cerrors.Op("api.platformScanAudit.ListUnifiedFindings"), cerrors.ErrInvalidInput, err)
		}
		return nil, err
	}
	return findings, nil
}

func (s serverPlatformScanAuditService) ExportRecord(ctx context.Context, namespace, runID string) (*scanaudit.ExportPackage, error) {
	service, closeStore, err := s.service()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	pkg, err := service.ExportRecord(ctx, namespace, runID)
	if err != nil {
		switch {
		case errors.Is(err, scanaudit.ErrUnsupportedNamespace):
			return nil, cerrors.E(cerrors.Op("api.platformScanAudit.ExportRecord"), cerrors.ErrInvalidInput, err)
		case errors.Is(err, scanaudit.ErrRecordNotFound):
			return nil, cerrors.E(cerrors.Op("api.platformScanAudit.ExportRecord"), cerrors.ErrNotFound, "scan audit record not found")
		default:
			return nil, err
		}
	}
	return pkg, nil
}

func (s serverPlatformScanAuditService) service() (scanaudit.Service, func(), error) {
	if s.deps == nil || s.deps.Config == nil {
		return scanaudit.Service{}, nil, errPlatformScanAuditStoreNotConfigured
	}
	store := s.deps.ExecutionStore
	if store != nil {
		return scanaudit.NewService(store, scanaudit.Config{
			RetentionDays: s.deps.Config.AuditRetentionDays,
		}), nil, nil
	}
	store, err := executionstore.NewSQLiteStore(s.deps.Config.ExecutionStoreFile)
	if err != nil {
		return scanaudit.Service{}, nil, errors.Join(errPlatformScanAuditStoreUnavailable, err)
	}
	return scanaudit.NewService(store, scanaudit.Config{
		RetentionDays: s.deps.Config.AuditRetentionDays,
	}), func() { _ = store.Close() }, nil
}
