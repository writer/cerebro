package api

import (
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/cerrors"
)

func TestWrapOrgPolicyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantKind error
	}{
		{
			name:     "not found",
			err:      errors.New("policy not found: policy:acceptable-use-policy"),
			wantKind: cerrors.ErrNotFound,
		},
		{
			name:     "invalid input",
			err:      errors.New("owner_id is required"),
			wantKind: cerrors.ErrInvalidInput,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapOrgPolicyError(cerrors.Op("api.orgPolicies.test"), tc.err)
			if err == nil {
				t.Fatal("wrapOrgPolicyError() returned nil")
				return
			}
			if !errors.Is(err, tc.wantKind) {
				t.Fatalf("errors.Is(%v) = false, want true", tc.wantKind)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("errors.Is(%v) = false, want true", tc.err)
			}
			if strings.Contains(err.Error(), "<nil>") {
				t.Fatalf("error message contains <nil>: %q", err.Error())
			}
			if !strings.Contains(err.Error(), tc.err.Error()) {
				t.Fatalf("error message %q does not contain original error %q", err.Error(), tc.err.Error())
			}
		})
	}
}
