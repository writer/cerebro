package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/policy"
)

type mockFindingStore struct{}

func (m *mockFindingStore) Upsert(ctx context.Context, pf policy.Finding) *findings.Finding {
	return nil
}
func (m *mockFindingStore) Get(id string) (*findings.Finding, bool) { return nil, false }
func (m *mockFindingStore) List(filter findings.FindingFilter) []*findings.Finding {
	return []*findings.Finding{}
}
func (m *mockFindingStore) Count(filter findings.FindingFilter) int { return 0 }
func (m *mockFindingStore) Resolve(id string) bool                  { return true }
func (m *mockFindingStore) Suppress(id string) bool                 { return true }
func (m *mockFindingStore) Stats() findings.Stats {
	return findings.Stats{
		Total:      10,
		BySeverity: map[string]int{"critical": 2, "high": 3, "medium": 3, "low": 2},
		ByStatus:   map[string]int{"open": 8, "resolved": 2},
	}
}
func (m *mockFindingStore) Sync(ctx context.Context) error { return nil }

func TestSlackCommandHandler_VerifySignature(t *testing.T) {
	secret := "8f742231b10e8888abcd99yyyzzz85a5"
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: secret}, &mockFindingStore{})

	// Create test request body
	body := "token=gIkuvaNzQIHg97ATvDxqgjtO&team_id=T0001&channel_id=C2147483705&user_id=U2147483697&user_name=steve&command=%2Fcerebro&text=stats"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Compute valid signature
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	// Test valid signature
	req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", timestamp)
	req.Header.Set("X-Slack-Signature", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSlackCommandHandler_RejectsInvalidSignature(t *testing.T) {
	secret := "8f742231b10e8888abcd99yyyzzz85a5"
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: secret}, &mockFindingStore{})

	body := "token=test&command=%2Fcerebro&text=stats"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Test with invalid signature
	req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", timestamp)
	req.Header.Set("X-Slack-Signature", "v0=invalid_signature")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestSlackCommandHandler_RejectsOldTimestamp(t *testing.T) {
	secret := "8f742231b10e8888abcd99yyyzzz85a5"
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: secret}, &mockFindingStore{})

	body := "token=test&command=%2Fcerebro&text=stats"
	// Timestamp from 10 minutes ago (older than 5 min limit)
	oldTimestamp := strconv.FormatInt(time.Now().Unix()-600, 10)

	// Compute signature with old timestamp
	baseString := fmt.Sprintf("v0:%s:%s", oldTimestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", oldTimestamp)
	req.Header.Set("X-Slack-Signature", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for old timestamp, got %d", w.Code)
	}
}

func TestSlackCommandHandler_RejectsFutureTimestamp(t *testing.T) {
	secret := "8f742231b10e8888abcd99yyyzzz85a5"
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: secret}, &mockFindingStore{})

	body := "token=test&command=%2Fcerebro&text=stats"
	// Timestamp from 10 minutes in the future (beyond 5 min limit)
	futureTimestamp := strconv.FormatInt(time.Now().Unix()+600, 10)

	// Compute signature with future timestamp
	baseString := fmt.Sprintf("v0:%s:%s", futureTimestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(baseString))
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", futureTimestamp)
	req.Header.Set("X-Slack-Signature", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for future timestamp, got %d", w.Code)
	}
}

func TestSlackCommandHandler_RejectsMissingHeaders(t *testing.T) {
	secret := "test-secret"
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: secret}, &mockFindingStore{})

	body := "token=test&command=%2Fcerebro&text=stats"

	tests := []struct {
		name      string
		timestamp string
		signature string
	}{
		{"missing timestamp", "", "v0=signature"},
		{"missing signature", strconv.FormatInt(time.Now().Unix(), 10), ""},
		{"both missing", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.timestamp != "" {
				req.Header.Set("X-Slack-Request-Timestamp", tt.timestamp)
			}
			if tt.signature != "" {
				req.Header.Set("X-Slack-Signature", tt.signature)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", w.Code)
			}
		})
	}
}

func TestSlackCommandHandler_SkipsVerificationWithoutSecret(t *testing.T) {
	// Handler without signing secret should skip verification
	handler := NewSlackCommandHandler(SlackCommandConfig{SigningSecret: ""}, &mockFindingStore{})

	body := url.Values{
		"token":   {"test"},
		"command": {"/cerebro"},
		"text":    {"stats"},
	}.Encode()

	req := httptest.NewRequest(http.MethodPost, "/slack/commands", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No signature headers

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should succeed without verification
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 without signing secret, got %d", w.Code)
	}
}

func TestSlackCommandHandler_HandleCommand(t *testing.T) {
	handler := NewSlackCommandHandler(SlackCommandConfig{}, &mockFindingStore{})

	tests := []struct {
		name     string
		text     string
		wantType string
	}{
		{"help command", "help", "ephemeral"},
		{"stats command", "stats", "ephemeral"},
		{"findings command", "findings", "ephemeral"},
		{"unknown command", "unknown", "ephemeral"},
		{"empty command", "", "ephemeral"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := SlackCommand{Text: tt.text}
			resp := handler.HandleCommand(cmd)

			if resp.ResponseType != tt.wantType {
				t.Errorf("expected response type %s, got %s", tt.wantType, resp.ResponseType)
			}
		})
	}
}
