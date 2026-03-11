package providers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewProviderHTTPClientUsesSharedTransport(t *testing.T) {
	clientA := newProviderHTTPClient(30 * time.Second)
	clientB := newProviderHTTPClient(60 * time.Second)

	if clientA.Transport != sharedProviderTransport {
		t.Fatal("expected clientA to use shared provider transport")
	}
	if clientB.Transport != sharedProviderTransport {
		t.Fatal("expected clientB to use shared provider transport")
	}
	if clientA.Timeout != 30*time.Second {
		t.Fatalf("clientA timeout = %s, want 30s", clientA.Timeout)
	}
	if clientB.Timeout != 60*time.Second {
		t.Fatalf("clientB timeout = %s, want 60s", clientB.Timeout)
	}
}

func TestNewProviderHTTPClientDefaultsTimeout(t *testing.T) {
	client := newProviderHTTPClient(0)
	if client.Timeout != 30*time.Second {
		t.Fatalf("default timeout = %s, want 30s", client.Timeout)
	}
}

func TestProviderConstructorsAvoidInlineHTTPClientTimeoutAllocations(t *testing.T) {
	providersDir := providersDirectory(t)
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		t.Fatalf("read providers directory: %v", err)
	}

	violations := make([]string, 0)
	usesFactory := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "http_client.go" {
			continue
		}

		path := filepath.Join(providersDir, name)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		text := string(content)

		if strings.Contains(text, "newProviderHTTPClient(") {
			usesFactory++
		}
		if strings.Contains(text, "&http.Client{Timeout:") {
			violations = append(violations, name)
		}
	}

	if usesFactory == 0 {
		t.Fatal("expected provider constructors to use newProviderHTTPClient")
	}
	if len(violations) > 0 {
		t.Fatalf("found inline http.Client timeout allocations in providers: %s", strings.Join(violations, ", "))
	}
}

func providersDirectory(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}
