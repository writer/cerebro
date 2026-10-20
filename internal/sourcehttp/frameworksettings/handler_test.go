package frameworksettings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubFrameworkSettingsStore struct {
	settings map[string]ports.ComplianceFrameworkSettings
}

func newStubFrameworkSettingsStore() *stubFrameworkSettingsStore {
	return &stubFrameworkSettingsStore{settings: map[string]ports.ComplianceFrameworkSettings{}}
}

func (s *stubFrameworkSettingsStore) Ping(context.Context) error { return nil }

func (s *stubFrameworkSettingsStore) PutComplianceFrameworkSettings(_ context.Context, settings *ports.ComplianceFrameworkSettings) error {
	copied := *settings
	copied.EnabledFrameworks = append([]string(nil), settings.EnabledFrameworks...)
	copied.UpdatedAt = time.Now().UTC()
	s.settings[strings.TrimSpace(settings.TenantID)] = copied
	return nil
}

func (s *stubFrameworkSettingsStore) GetComplianceFrameworkSettings(_ context.Context, tenantID string) (*ports.ComplianceFrameworkSettings, error) {
	settings, ok := s.settings[strings.TrimSpace(tenantID)]
	if !ok {
		return nil, ports.ErrComplianceFrameworkSettingsNotFound
	}
	settings.EnabledFrameworks = append([]string(nil), settings.EnabledFrameworks...)
	return &settings, nil
}

func testHandler(store ports.StateStore) Handler {
	return NewHandler(store, func(_ context.Context, requested string) (string, error) {
		if requested != "" && requested != "local" {
			return "", errors.New("tenant forbidden")
		}
		return "local", nil
	})
}

func testRequest(method, body string) *http.Request {
	return httptest.NewRequest(method, "/grc/framework-settings", strings.NewReader(body))
}

func decodeFrameworkSettings(t *testing.T, recorder *httptest.ResponseRecorder) Response {
	t.Helper()
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, recorder.Body.String())
	}
	return response
}

func TestHandleGetFrameworkSettingsReturnsDefaults(t *testing.T) {
	handler := testHandler(newStubFrameworkSettingsStore())
	recorder := httptest.NewRecorder()
	handler.Get(recorder, testRequest(http.MethodGet, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	response := decodeFrameworkSettings(t, recorder)
	if response.Persisted {
		t.Fatal("Persisted = true, want defaults for a tenant that never saved")
	}
	want := []string{"SOC 2", "ISO 27001:2022", "CIS AWS Foundations Benchmark v2.0"}
	if response.Settings.TenantID != "local" || !reflect.DeepEqual(response.Settings.EnabledFrameworks, want) {
		t.Fatalf("settings = %#v, want local tenant with %v", response.Settings, want)
	}
}

func TestHandlePutFrameworkSettingsPersistsCanonicalSelection(t *testing.T) {
	store := newStubFrameworkSettingsStore()
	handler := testHandler(store)
	recorder := httptest.NewRecorder()
	body := `{"enabled_frameworks":["cis aws foundations benchmark v2.0","SOC 2","SOC 2"]}`
	handler.Put(recorder, testRequest(http.MethodPut, body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	response := decodeFrameworkSettings(t, recorder)
	want := []string{"SOC 2", "CIS AWS Foundations Benchmark v2.0"}
	if !response.Persisted || !reflect.DeepEqual(response.Settings.EnabledFrameworks, want) {
		t.Fatalf("response = %#v, want persisted %v", response, want)
	}
	if got := store.settings["local"].EnabledFrameworks; !reflect.DeepEqual(got, want) {
		t.Fatalf("stored = %v, want %v", got, want)
	}

	// An explicit empty list is a valid choice and must not fall back to defaults.
	recorder = httptest.NewRecorder()
	handler.Put(recorder, testRequest(http.MethodPut, `{"enabled_frameworks":[]}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty selection status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.Get(recorder, testRequest(http.MethodGet, ""))
	if response := decodeFrameworkSettings(t, recorder); !response.Persisted || len(response.Settings.EnabledFrameworks) != 0 {
		t.Fatalf("after empty save = %#v, want persisted empty selection", response)
	}
}

func TestHandlePutFrameworkSettingsRejectsInvalidSelections(t *testing.T) {
	for name, body := range map[string]string{
		"unknown framework":  `{"enabled_frameworks":["SOC 3"]}`,
		"upcoming framework": `{"enabled_frameworks":["nist-ai-rmf-1.0"]}`,
		"missing list":       `{}`,
		"malformed body":     `{"enabled_frameworks":`,
	} {
		t.Run(name, func(t *testing.T) {
			store := newStubFrameworkSettingsStore()
			handler := testHandler(store)
			recorder := httptest.NewRecorder()
			handler.Put(recorder, testRequest(http.MethodPut, body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s, want 400", recorder.Code, recorder.Body.String())
			}
			if len(store.settings) != 0 {
				t.Fatalf("invalid selection was stored: %#v", store.settings)
			}
		})
	}
}

func TestHandlePutFrameworkSettingsRejectsOtherTenant(t *testing.T) {
	store := newStubFrameworkSettingsStore()
	handler := testHandler(store)
	recorder := httptest.NewRecorder()
	handler.Put(recorder, testRequest(http.MethodPut, `{"tenant_id":"other","enabled_frameworks":["SOC 2"]}`))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", recorder.Code, recorder.Body.String())
	}
	if len(store.settings) != 0 {
		t.Fatalf("cross-tenant write was stored: %#v", store.settings)
	}
}

func TestHandlePutFrameworkSettingsWithoutStoreIsUnavailable(t *testing.T) {
	handler := testHandler(nil)
	recorder := httptest.NewRecorder()
	handler.Put(recorder, testRequest(http.MethodPut, `{"enabled_frameworks":["SOC 2"]}`))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s, want 503", recorder.Code, recorder.Body.String())
	}
}
