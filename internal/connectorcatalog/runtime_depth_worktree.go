package connectorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var worktreeRuntimeDepth struct {
	once      sync.Once
	inventory RuntimeDepthInventory
}

func WorktreeRuntimeDepth() RuntimeDepthInventory {
	worktreeRuntimeDepth.once.Do(func() {
		worktreeRuntimeDepth.inventory = discoverWorktreeRuntimeDepth()
	})
	return worktreeRuntimeDepth.inventory
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
