package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/webhooks"
)

var (
	errThreatIntelUnavailable      = errors.New("threat intel not initialized")
	errRuntimeDetectionUnavailable = errors.New("runtime detection not initialized")
	errRuntimeResponseUnavailable  = errors.New("runtime response not initialized")
)

type threatRuntimeService interface {
	ListThreatFeeds() ([]threatintel.Feed, error)
	SyncThreatFeed(ctx context.Context, id, triggeredBy string) error
	ThreatIntelStats() (map[string]interface{}, error)
	LookupIP(ip string) (*threatintel.Indicator, bool, error)
	LookupDomain(domain string) (*threatintel.Indicator, bool, error)
	LookupCVE(cve string) (*threatintel.Indicator, bool, bool, error)
	ListDetectionRules() ([]runtime.DetectionRule, error)
	RecentRuntimeFindings(limit int) ([]runtime.RuntimeFinding, error)
	ListResponsePolicies() ([]*runtime.ResponsePolicy, error)
	EnableResponsePolicy(id string) error
	DisableResponsePolicy(id string) error
}

type serverThreatRuntimeService struct {
	deps *serverDependencies
}

func newThreatRuntimeService(deps *serverDependencies) threatRuntimeService {
	return serverThreatRuntimeService{deps: deps}
}

func (s serverThreatRuntimeService) ListThreatFeeds() ([]threatintel.Feed, error) {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return nil, errThreatIntelUnavailable
	}
	return s.deps.ThreatIntel.ListFeeds(), nil
}

func (s serverThreatRuntimeService) SyncThreatFeed(ctx context.Context, id, triggeredBy string) error {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return errThreatIntelUnavailable
	}
	if err := s.deps.ThreatIntel.SyncFeed(ctx, id); err != nil {
		return err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventThreatIntelSynced, map[string]interface{}{
			"feed_id":      id,
			"triggered_by": triggeredBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit threat intel sync event", "feed_id", id, "error", err)
		}
	}
	return nil
}

func (s serverThreatRuntimeService) ThreatIntelStats() (map[string]interface{}, error) {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return nil, errThreatIntelUnavailable
	}
	return s.deps.ThreatIntel.Stats(), nil
}

func (s serverThreatRuntimeService) LookupIP(ip string) (*threatintel.Indicator, bool, error) {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return nil, false, errThreatIntelUnavailable
	}
	ind, found := s.deps.ThreatIntel.LookupIP(ip)
	return ind, found, nil
}

func (s serverThreatRuntimeService) LookupDomain(domain string) (*threatintel.Indicator, bool, error) {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return nil, false, errThreatIntelUnavailable
	}
	ind, found := s.deps.ThreatIntel.LookupDomain(domain)
	return ind, found, nil
}

func (s serverThreatRuntimeService) LookupCVE(cve string) (*threatintel.Indicator, bool, bool, error) {
	if s.deps == nil || s.deps.ThreatIntel == nil {
		return nil, false, false, errThreatIntelUnavailable
	}
	ind, found := s.deps.ThreatIntel.LookupCVE(cve)
	return ind, found, s.deps.ThreatIntel.IsKEV(cve), nil
}

func (s serverThreatRuntimeService) ListDetectionRules() ([]runtime.DetectionRule, error) {
	if s.deps == nil || s.deps.RuntimeDetect == nil {
		return nil, errRuntimeDetectionUnavailable
	}
	return s.deps.RuntimeDetect.ListRules(), nil
}

func (s serverThreatRuntimeService) RecentRuntimeFindings(limit int) ([]runtime.RuntimeFinding, error) {
	if s.deps == nil || s.deps.RuntimeDetect == nil {
		return nil, errRuntimeDetectionUnavailable
	}
	return s.deps.RuntimeDetect.RecentFindings(limit), nil
}

func (s serverThreatRuntimeService) ListResponsePolicies() ([]*runtime.ResponsePolicy, error) {
	if s.deps == nil || s.deps.RuntimeRespond == nil {
		return nil, errRuntimeResponseUnavailable
	}
	return s.deps.RuntimeRespond.ListPolicies(), nil
}

func (s serverThreatRuntimeService) EnableResponsePolicy(id string) error {
	if s.deps == nil || s.deps.RuntimeRespond == nil {
		return errRuntimeResponseUnavailable
	}
	return s.deps.RuntimeRespond.EnablePolicy(id)
}

func (s serverThreatRuntimeService) DisableResponsePolicy(id string) error {
	if s.deps == nil || s.deps.RuntimeRespond == nil {
		return errRuntimeResponseUnavailable
	}
	return s.deps.RuntimeRespond.DisablePolicy(id)
}

var _ threatRuntimeService = serverThreatRuntimeService{}
