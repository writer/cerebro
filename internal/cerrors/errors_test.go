package cerrors

import (
	"errors"
	"strings"
	"testing"
)

func TestE(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		wantErr  bool
		wantKind error
	}{
		{
			name:    "with op and kind",
			args:    []interface{}{Op("test.Op"), ErrNotFound},
			wantErr: true,
		},
		{
			name:    "with op, kind, and message",
			args:    []interface{}{Op("test.Op"), ErrNotFound, "item xyz"},
			wantErr: true,
		},
		{
			name:     "with underlying error",
			args:     []interface{}{Op("test.Op"), errors.New("underlying")},
			wantErr:  true,
			wantKind: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := E(tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("E() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrorIs(t *testing.T) {
	// Create wrapped error
	underlying := errors.New("connection refused")
	err := E(Op("db.Query"), ErrDBConnection, underlying)

	// Should match sentinel
	if !errors.Is(err, ErrDBConnection) {
		t.Error("errors.Is should match ErrDBConnection")
	}

	// Should match underlying
	if !errors.Is(err, underlying) {
		t.Error("errors.Is should match underlying error")
	}

	// Should not match unrelated error
	if errors.Is(err, ErrNotFound) {
		t.Error("errors.Is should not match ErrNotFound")
	}
}

func TestWrap(t *testing.T) {
	// Wrap nil should return nil
	if Wrap(Op("test"), nil) != nil {
		t.Error("Wrap(nil) should return nil")
	}

	// Wrap error should return wrapped error
	underlying := errors.New("original")
	wrapped := Wrap(Op("test.Op"), underlying)
	if wrapped == nil {
		t.Error("Wrap should return non-nil error")
	}

	if !errors.Is(wrapped, underlying) {
		t.Error("wrapped error should contain underlying error")
	}
}

func TestWrapf(t *testing.T) {
	underlying := errors.New("connection failed")
	wrapped := Wrapf(Op("db.Connect"), underlying, "host %s port %d", "localhost", 5432)

	if wrapped == nil {
		t.Error("Wrapf should return non-nil error")
	}

	errMsg := wrapped.Error()
	if errMsg == "" {
		t.Error("error message should not be empty")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrNotFound", ErrNotFound, true},
		{"ErrPolicyNotFound", ErrPolicyNotFound, true},
		{"ErrFindingNotFound", ErrFindingNotFound, true},
		{"ErrAgentNotFound", ErrAgentNotFound, true},
		{"wrapped not found", E(Op("test"), ErrNotFound), true},
		{"other error", ErrDBConnection, false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrInvalidInput", ErrInvalidInput, true},
		{"ErrMissingRequired", ErrMissingRequired, true},
		{"ErrInvalidFormat", ErrInvalidFormat, true},
		{"other error", ErrNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidation(tt.err); got != tt.want {
				t.Errorf("IsValidation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAuth(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrUnauthorized", ErrUnauthorized, true},
		{"ErrForbidden", ErrForbidden, true},
		{"ErrInvalidAPIKey", ErrInvalidAPIKey, true},
		{"other error", ErrNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuth(tt.err); got != tt.want {
				t.Errorf("IsAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorMessage(t *testing.T) {
	err := E(Op("db.Query"), ErrDBQuery, "failed to fetch users")
	msg := err.Error()

	if msg == "" {
		t.Error("error message should not be empty")
	}

	// Should contain operation name
	if !contains(msg, "db.Query") {
		t.Errorf("error message should contain operation name, got: %s", msg)
	}

	// Should contain context message
	if !contains(msg, "failed to fetch users") {
		t.Errorf("error message should contain context, got: %s", msg)
	}
}

func TestEDuplicateOpsPreservesBothOperations(t *testing.T) {
	err := E(Op("first.Op"), Op("second.Op"), ErrNotFound)
	if err == nil {
		t.Fatal("E() returned nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "first.Op") {
		t.Fatalf("expected error message to preserve first op, got %q", msg)
	}
	if !strings.Contains(msg, "second.Op") {
		t.Fatalf("expected error message to preserve second op, got %q", msg)
	}
}

func TestEDuplicateSentinelsRemainReachable(t *testing.T) {
	err := E(Op("lookup"), ErrNotFound, ErrUnauthorized)
	if err == nil {
		t.Fatal("E() returned nil")
	}

	if !errors.Is(err, ErrNotFound) {
		t.Fatal("expected first sentinel to remain reachable")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expected second sentinel to remain reachable")
	}
}

func TestEDuplicateUnderlyingErrorsRemainReachable(t *testing.T) {
	errA := errors.New("error A")
	errB := errors.New("error B")

	err := E(Op("lookup"), errA, errB)
	if err == nil {
		t.Fatal("E() returned nil")
	}

	if !errors.Is(err, errA) {
		t.Fatal("expected first underlying error to remain reachable")
	}
	if !errors.Is(err, errB) {
		t.Fatal("expected second underlying error to remain reachable")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
