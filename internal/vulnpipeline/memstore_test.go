package vulnpipeline

import (
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/vulnpipeline/vulnpipelinetest"
)

type memStore = vulnpipelinetest.MemoryStore

func newMemStore() *memStore { return vulnpipelinetest.NewMemoryStore() }

type portsProfile = ports.VulnerabilityProfile

func portsFilter(tenantID string, severities ...string) ports.VulnerabilityObservationFilter {
	return ports.VulnerabilityObservationFilter{TenantID: tenantID, Severities: severities}
}
