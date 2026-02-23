package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type persistedRBACState struct {
	Roles       map[string]*Role       `json:"roles"`
	Permissions map[string]*Permission `json:"permissions"`
	Users       map[string]*User       `json:"users"`
	Tenants     map[string]*Tenant     `json:"tenants"`
}

// NewRBACWithStateFile creates an RBAC service and loads persisted state from disk when available.
func NewRBACWithStateFile(path string) (*RBAC, error) {
	rbac := NewRBAC()
	path = strings.TrimSpace(path)
	if path == "" {
		return rbac, nil
	}

	rbac.stateFile = path
	if err := rbac.loadStateFromFile(); err != nil {
		return nil, err
	}

	return rbac, nil
}

func (r *RBAC) loadStateFromFile() error {
	if r.stateFile == "" {
		return nil
	}

	data, err := os.ReadFile(r.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read RBAC state file: %w", err)
	}

	var state persistedRBACState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode RBAC state file: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for id, role := range state.Roles {
		r.roles[id] = role
	}
	for id, perm := range state.Permissions {
		r.permissions[id] = perm
	}
	if state.Users != nil {
		r.users = state.Users
	}
	if state.Tenants != nil {
		r.tenants = state.Tenants
	}

	return nil
}

func (r *RBAC) persistLocked() error {
	if r.stateFile == "" {
		return nil
	}

	state := persistedRBACState{
		Roles:       r.roles,
		Permissions: r.permissions,
		Users:       r.users,
		Tenants:     r.tenants,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal RBAC state: %w", err)
	}

	dir := filepath.Dir(r.stateFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create RBAC state dir: %w", err)
		}
	}

	tmpFile := r.stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0o600); err != nil {
		return fmt.Errorf("write RBAC state: %w", err)
	}
	if err := os.Rename(tmpFile, r.stateFile); err != nil {
		return fmt.Errorf("commit RBAC state: %w", err)
	}

	return nil
}
