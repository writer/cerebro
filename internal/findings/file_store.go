package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/policy"
)

// FileStore provides file-based persistence for findings
// Useful for development/testing when Snowflake is not available
type FileStore struct {
	store    *Store
	filePath string
	mu       sync.Mutex
	dirty    bool
	ticker   *time.Ticker
	done     chan struct{}
}

// NewFileStore creates a file-backed findings store
func NewFileStore(filePath string) (*FileStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	fs := &FileStore{
		store:    NewStore(),
		filePath: filePath,
		done:     make(chan struct{}),
	}

	// Load existing findings
	if err := fs.load(); err != nil {
		// File may not exist yet, that's OK
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("load findings: %w", err)
		}
	}

	// Start auto-save ticker
	fs.ticker = time.NewTicker(30 * time.Second)
	go fs.autoSave()

	return fs, nil
}

// load reads findings from file
func (fs *FileStore) load() error {
	data, err := os.ReadFile(fs.filePath)
	if err != nil {
		return err
	}

	var findings []*Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	// Load into in-memory store
	fs.store.mu.Lock()
	for _, f := range findings {
		f.Status = normalizeStatus(f.Status)
		EnrichFinding(f)
		fs.store.findings[f.ID] = f
	}
	fs.store.mu.Unlock()

	return nil
}

// save writes findings to file
func (fs *FileStore) save() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if !fs.dirty {
		return nil
	}

	findings := fs.store.List(FindingFilter{})

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Write to temp file first, then rename (atomic)
	tmpPath := fs.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}

	if err := os.Rename(tmpPath, fs.filePath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	fs.dirty = false
	return nil
}

// autoSave periodically saves findings to disk
func (fs *FileStore) autoSave() {
	for {
		select {
		case <-fs.done:
			return
		case <-fs.ticker.C:
			_ = fs.save()
		}
	}
}

// Upsert adds or updates a finding
func (fs *FileStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	f := fs.store.Upsert(ctx, pf)
	fs.mu.Lock()
	fs.dirty = true
	fs.mu.Unlock()
	return f
}

func (fs *FileStore) SetAttestor(attestor FindingAttestor, attestReobserved bool) {
	fs.store.SetAttestor(attestor, attestReobserved)
}

// Get retrieves a finding by ID
func (fs *FileStore) Get(id string) (*Finding, bool) {
	return fs.store.Get(id)
}

func (fs *FileStore) Update(id string, mutate func(*Finding) error) error {
	if err := fs.store.Update(id, mutate); err != nil {
		return err
	}
	fs.mu.Lock()
	fs.dirty = true
	fs.mu.Unlock()
	return nil
}

// List returns findings matching the filter
func (fs *FileStore) List(filter FindingFilter) []*Finding {
	return fs.store.List(filter)
}

// Count returns the total number of findings matching the filter
func (fs *FileStore) Count(filter FindingFilter) int {
	return fs.store.Count(filter)
}

// Resolve marks a finding as resolved
func (fs *FileStore) Resolve(id string) bool {
	result := fs.store.Resolve(id)
	if result {
		fs.mu.Lock()
		fs.dirty = true
		fs.mu.Unlock()
	}
	return result
}

// Suppress marks a finding as suppressed
func (fs *FileStore) Suppress(id string) bool {
	result := fs.store.Suppress(id)
	if result {
		fs.mu.Lock()
		fs.dirty = true
		fs.mu.Unlock()
	}
	return result
}

// Stats returns finding statistics
func (fs *FileStore) Stats() Stats {
	return fs.store.Stats()
}

// Sync flushes findings to disk
func (fs *FileStore) Sync(ctx context.Context) error {
	return fs.save()
}

// Close stops the auto-save ticker and saves final state
func (fs *FileStore) Close() error {
	close(fs.done)
	fs.ticker.Stop()
	return fs.save()
}

// Clear removes all findings
func (fs *FileStore) Clear() error {
	fs.store.mu.Lock()
	fs.store.findings = make(map[string]*Finding)
	fs.store.mu.Unlock()

	fs.mu.Lock()
	fs.dirty = true
	fs.mu.Unlock()

	return fs.save()
}

// DefaultFilePath returns the default findings file path
func DefaultFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".cerebro", "findings.json")
}

// Cleanup removes findings older than the specified duration
func (fs *FileStore) Cleanup(maxAge time.Duration) int {
	fs.store.mu.Lock()
	defer fs.store.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, f := range fs.store.findings {
		if f.LastSeen.Before(cutoff) && normalizeStatus(f.Status) == "RESOLVED" {
			delete(fs.store.findings, id)
			removed++
		}
	}

	if removed > 0 {
		fs.mu.Lock()
		fs.dirty = true
		fs.mu.Unlock()
	}

	return removed
}
