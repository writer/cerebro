package connectorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

var worktreeRuntimeDepth struct {
	once  sync.Once
	value atomic.Value
}

func LoadWorktreeRuntimeDepth() {
	worktreeRuntimeDepth.once.Do(func() {
		worktreeRuntimeDepth.value.Store(discoverWorktreeRuntimeDepth())
	})
}

func WorktreeRuntimeDepth() RuntimeDepthInventory {
	inventory, _ := worktreeRuntimeDepth.value.Load().(RuntimeDepthInventory)
	if inventory == nil {
		return RuntimeDepthInventory{}
	}
	return inventory
}

func WorktreeRuntimeProviderAPIDepth(sourceID string) RuntimeProviderAPIDepth {
	depth := WorktreeRuntimeDepth()[strings.TrimSpace(sourceID)]
	return depth.ProviderAPI
}

func discoverWorktreeRuntimeDepth() RuntimeDepthInventory {
	for _, root := range []string{".", "..", "../.."} {
		if _, err := os.Stat(filepath.Join(root, "sources")); err != nil {
			continue
		}
		inventory, err := DiscoverRuntimeDepth(root)
		if err == nil {
			return inventory
		}
	}
	return RuntimeDepthInventory{}
}
