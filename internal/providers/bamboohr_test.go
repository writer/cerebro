package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBambooHRProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "bamboohr-token" || password != "x" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/employees/directory":
			page, _ := strconv.Atoi(req.URL.Query().Get("page"))
			employees := []map[string]interface{}{}
			switch page {
			case 1:
				employees = bambooHRTestEmployees(200, 1)
			case 2:
				employees = bambooHRTestEmployees(1, 201)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"employees": employees,
			})
			return

		case "/v1/meta/departments":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"departments": []map[string]interface{}{{
					"id":        "dept-1",
					"name":      "Security",
					"parent_id": "dept-root",
				}},
			})
			return

		case "/v1/meta/locations":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"locations": []map[string]interface{}{{
					"id":      "loc-1",
					"name":    "HQ",
					"city":    "San Francisco",
					"state":   "CA",
					"country": "US",
				}},
			})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewBambooHRProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL + "/v1",
		"token": "bamboohr-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["bamboohr_employees"] != 201 {
		t.Fatalf("bamboohr_employees rows = %d, want 201", rowsByTable["bamboohr_employees"])
	}
	if rowsByTable["bamboohr_departments"] != 1 {
		t.Fatalf("bamboohr_departments rows = %d, want 1", rowsByTable["bamboohr_departments"])
	}
	if rowsByTable["bamboohr_locations"] != 1 {
		t.Fatalf("bamboohr_locations rows = %d, want 1", rowsByTable["bamboohr_locations"])
	}
}

func TestBambooHRProviderSync_IgnoresPermissionDeniedMetaEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "bamboohr-token" || password != "x" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/v1/employees/directory":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"employees": []map[string]interface{}{{
					"id":             "emp-1",
					"employeeNumber": "E-1",
					"firstName":      "Alex",
					"lastName":       "Admin",
					"workEmail":      "alex@example.com",
				}},
			})
			return

		case "/v1/meta/departments", "/v1/meta/locations":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewBambooHRProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   server.URL + "/v1",
		"token": "bamboohr-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if rowsByTable["bamboohr_employees"] != 1 {
		t.Fatalf("bamboohr_employees rows = %d, want 1", rowsByTable["bamboohr_employees"])
	}
	if rowsByTable["bamboohr_departments"] != 0 {
		t.Fatalf("bamboohr_departments rows = %d, want 0", rowsByTable["bamboohr_departments"])
	}
	if rowsByTable["bamboohr_locations"] != 0 {
		t.Fatalf("bamboohr_locations rows = %d, want 0", rowsByTable["bamboohr_locations"])
	}
}

func TestBambooHRProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewBambooHRProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":   "https://api.bamboohr.com/v1",
		"token": "bamboohr-token",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), "https://evil.example.com/v1/employees/directory")
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func bambooHRTestEmployees(count int, start int) []map[string]interface{} {
	employees := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		employees = append(employees, map[string]interface{}{
			"id":             "emp-" + strconv.Itoa(id),
			"employeeNumber": "E-" + strconv.Itoa(id),
			"firstName":      "User",
			"lastName":       strconv.Itoa(id),
			"displayName":    "User " + strconv.Itoa(id),
			"workEmail":      "user" + strconv.Itoa(id) + "@example.com",
			"department":     "Security",
			"location":       "HQ",
			"jobTitle":       "Engineer",
			"supervisorEId":  "emp-1",
			"status":         "active",
			"hireDate":       "2024-01-01",
			"lastChanged":    "2026-02-25T09:00:00Z",
		})
	}
	return employees
}
