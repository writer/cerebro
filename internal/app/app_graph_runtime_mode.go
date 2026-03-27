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

func allowInMemoryGraphStoreForProcess(testProcess, explicit bool) bool {
	_ = testProcess
	_ = explicit
	return false
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

func (a *App) retainHotSecurityGraph() bool {
	_ = a
	return runningUnderGoTest()
}
