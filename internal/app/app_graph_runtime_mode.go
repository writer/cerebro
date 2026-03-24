package app

import (
	"flag"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

func runningUnderGoTest() bool {
	if flag.Lookup("test.v") != nil {
		return true
	}
	return strings.HasSuffix(strings.TrimSpace(os.Args[0]), ".test")
}

func defaultGraphStoreBackendForProcess(testProcess bool) string {
	if testProcess {
		return string(graph.StoreBackendMemory)
	}
	return string(graph.StoreBackendSpanner)
}

func defaultGraphStoreBackend() string {
	return defaultGraphStoreBackendForProcess(runningUnderGoTest())
}

func allowInMemoryGraphStoreForProcess(testProcess, explicit bool) bool {
	return testProcess || explicit
}

func (c *Config) graphStoreBackend() graph.StoreBackend {
	if c == nil {
		return graph.ParseStoreBackend(defaultGraphStoreBackend())
	}
	if strings.TrimSpace(c.GraphStoreBackend) == "" {
		return graph.ParseStoreBackend(defaultGraphStoreBackend())
	}
	return graph.ParseStoreBackend(c.GraphStoreBackend)
}

func (c *Config) graphStoreSecondaryBackend() graph.StoreBackend {
	if c == nil {
		return ""
	}
	if strings.TrimSpace(c.GraphStoreSecondaryBackend) == "" {
		return ""
	}
	return graph.ParseStoreBackend(c.GraphStoreSecondaryBackend)
}

func (c *Config) graphStoreDualWriteMode() graph.DualWriteMode {
	if c == nil {
		return graph.ParseDualWriteMode("")
	}
	return graph.ParseDualWriteMode(c.GraphStoreDualWriteMode)
}

func (c *Config) dualWriteGraphStoreEnabled() bool {
	return c != nil && c.graphStoreSecondaryBackend() != ""
}

func (c *Config) secondaryGraphStoreConfig() *Config {
	if c == nil || !c.dualWriteGraphStoreEnabled() {
		return c
	}
	clone := *c
	clone.GraphStoreBackend = c.GraphStoreSecondaryBackend
	clone.GraphStoreNeptuneEndpoint = c.GraphStoreSecondaryNeptuneEndpoint
	clone.GraphStoreNeptuneRegion = c.GraphStoreSecondaryNeptuneRegion
	clone.GraphStoreNeptunePoolSize = c.GraphStoreSecondaryNeptunePoolSize
	clone.GraphStoreNeptunePoolHealthCheckInterval = c.GraphStoreSecondaryNeptunePoolHealthCheckInterval
	clone.GraphStoreNeptunePoolHealthCheckTimeout = c.GraphStoreSecondaryNeptunePoolHealthCheckTimeout
	clone.GraphStoreNeptunePoolMaxClientLifetime = c.GraphStoreSecondaryNeptunePoolMaxClientLifetime
	clone.GraphStoreNeptunePoolMaxClientUses = c.GraphStoreSecondaryNeptunePoolMaxClientUses
	clone.GraphStoreNeptunePoolDrainTimeout = c.GraphStoreSecondaryNeptunePoolDrainTimeout
	clone.GraphStoreSpannerDatabase = c.GraphStoreSecondarySpannerDatabase
	clone.GraphStoreSpannerAutoBootstrap = c.GraphStoreSecondarySpannerAutoBootstrap
	clone.GraphStoreSecondaryBackend = ""
	clone.GraphStoreSecondaryNeptuneEndpoint = ""
	clone.GraphStoreSecondaryNeptuneRegion = ""
	clone.GraphStoreSecondaryNeptunePoolSize = 0
	clone.GraphStoreSecondaryNeptunePoolHealthCheckInterval = 0
	clone.GraphStoreSecondaryNeptunePoolHealthCheckTimeout = 0
	clone.GraphStoreSecondaryNeptunePoolMaxClientLifetime = 0
	clone.GraphStoreSecondaryNeptunePoolMaxClientUses = 0
	clone.GraphStoreSecondaryNeptunePoolDrainTimeout = 0
	clone.GraphStoreSecondarySpannerDatabase = ""
	clone.GraphStoreSecondarySpannerAutoBootstrap = false
	clone.GraphStoreDualWriteMode = ""
	clone.GraphStoreDualWriteReconciliationPath = ""
	clone.GraphStoreDualWriteReplayEnabled = false
	clone.GraphStoreDualWriteReplayInterval = 0
	clone.GraphStoreDualWriteReplayBatchSize = 0
	return &clone
}

func (c *Config) allowInMemoryGraphStore() bool {
	if c == nil {
		return allowInMemoryGraphStoreForProcess(runningUnderGoTest(), false)
	}
	return allowInMemoryGraphStoreForProcess(runningUnderGoTest(), c.GraphStoreAllowInMemory)
}

func (c *Config) retainHotSecurityGraph() bool {
	return c.graphStoreBackend() == graph.StoreBackendMemory && c.allowInMemoryGraphStore()
}

func (a *App) retainHotSecurityGraph() bool {
	if a == nil {
		return false
	}
	if a.Config == nil {
		return allowInMemoryGraphStoreForProcess(runningUnderGoTest(), false)
	}
	return a.Config.retainHotSecurityGraph()
}
