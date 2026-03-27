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
	_ = testProcess
	return string(graph.StoreBackendNeptune)
}

func defaultGraphStoreBackend() string {
	return defaultGraphStoreBackendForProcess(runningUnderGoTest())
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

func (c *Config) allowMissingGraphStoreEndpoint() bool {
	if c == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(c.WarehouseBackend), "sqlite") && strings.TrimSpace(c.GraphStoreNeptuneEndpoint) == ""
}

func (a *App) retainHotSecurityGraph() bool {
	_ = a
	return runningUnderGoTest()
}
