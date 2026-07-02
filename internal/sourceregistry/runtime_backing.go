package sourceregistry

import (
	"strings"
	"sync"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
)

var builtinRuntimeRegistry struct {
	once     sync.Once
	registry *sourcecdk.Registry
	err      error
}

// EntryRuntimeExecutable reports whether a catalog entry is backed by an
// executable built-in runtime.
func EntryRuntimeExecutable(entry connectorcatalog.Entry) bool {
	if entry.Generateable {
		return true
	}
	if entry.Status != connectorcatalog.StatusNeedsBespokeRuntime {
		return false
	}
	return BuiltinRuntimeRegistered(entry.Definition.SourceID)
}

// BuiltinRuntimeRegistered reports whether sourceID is registered in the
// built-in source registry.
func BuiltinRuntimeRegistered(sourceID string) bool {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return false
	}
	builtinRuntimeRegistry.once.Do(func() {
		builtinRuntimeRegistry.registry, builtinRuntimeRegistry.err = Builtin()
	})
	if builtinRuntimeRegistry.err != nil || builtinRuntimeRegistry.registry == nil {
		return false
	}
	_, ok := builtinRuntimeRegistry.registry.Get(sourceID)
	return ok
}
