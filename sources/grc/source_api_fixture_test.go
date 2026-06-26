package grc

import (
	"encoding/json"
	"net/http"
	"testing"
)

func newTestAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s, want POST", r.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if payload["client_id"] != testClientID || payload["client_secret"] != testClientSecret {
				t.Fatalf("unexpected token credentials: %#v", payload)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "test-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			requireBearer(t, r)
			if r.URL.Query().Get("pageCursor") == "cursor-2" {
				writePage(t, w, false, "", []map[string]any{{
					"id":                               "vendor-2",
					"name":                             "Beta SaaS",
					"status":                           "APPROVED",
					"residualRiskLevel":                "LOW",
					"lastSecurityReviewCompletionDate": "2026-02-01T00:00:00Z",
				}})
				return
			}
			writePage(t, w, true, "cursor-2", []map[string]any{{
				"id":                               "vendor-1",
				"name":                             "Acme SaaS",
				"websiteUrl":                       "https://acme.example",
				"securityOwnerUserId":              "user-1",
				"status":                           "IN_REVIEW",
				"inherentRiskLevel":                "HIGH",
				"residualRiskLevel":                "MEDIUM",
				"nextSecurityReviewDueDate":        "2026-06-01T00:00:00Z",
				"lastSecurityReviewCompletionDate": "2025-06-01T00:00:00Z",
				"category":                         map[string]any{"displayName": "ai"},
			}})
		case "/v1/contracts":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                     "contract-1",
				"name":                   "Acme contract",
				"customerTrustAccountId": "account-1",
				"vendorId":               "vendor-1",
				"ownerId":                "user-1",
				"controlIds":             []string{"control-1", "control-2"},
				"evidenceId":             "evidence-1",
				"evidenceCasUri":         "evidencecas://contracts/contract-1",
				"status":                 "ACTIVE",
				"contractType":           "msa",
				"tags":                   []string{"critical", "renewal"},
				"dataTypes":              []string{"customer_data"},
				"jurisdictions":          []string{"US"},
				"executedDate":           "2026-04-01T00:00:00Z",
				"creationDate":           "2026-03-01T00:00:00Z",
			}})
		case "/v1/regulatory-notifications":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":               "notification-1",
				"title":            "DORA incident notification",
				"framework":        "DORA",
				"regulator":        "EU",
				"incidentId":       "incident-1",
				"incidentTitle":    "Payments outage",
				"notificationType": "initial",
				"controlIds":       []string{"dora-art-19"},
				"status":           "sent",
				"sentAt":           "2026-06-01T00:00:00Z",
			}})
		case "/v1/recovery-objectives":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":              "objective-1",
				"name":            "Payments recovery objective",
				"serviceId":       "payments-api",
				"targetType":      "service",
				"businessProcess": "Payment Processing",
				"rtoMinutes":      60,
				"rpoMinutes":      15,
				"controlIds":      []string{"cp-10"},
				"impactTier":      "critical",
				"status":          "approved",
				"reviewedAt":      "2026-05-01T00:00:00Z",
			}})
		case "/v1/authorization-packages":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "ato-1",
				"name":         "Writer Cloud authorization package",
				"framework":    "FedRAMP Rev. 5",
				"impactLevel":  "Moderate",
				"systemId":     "writer-cloud",
				"systemName":   "Writer Cloud",
				"targetType":   "cloud_service_offering",
				"controlIds":   []string{"fedramp-ca-7"},
				"evidenceId":   "ssp-evidence-1",
				"status":       "authorized",
				"authorizedAt": "2026-04-15T00:00:00Z",
			}})
		case "/v1/poam-items":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "poam-1",
				"findingId":    "finding-1",
				"title":        "GuardDuty not enabled",
				"riskRating":   "high",
				"status":       "open",
				"targetId":     "aws-prod",
				"targetType":   "account",
				"controlIds":   []string{"si-4"},
				"evidenceType": "poam_record",
				"evidenceId":   "poam-evidence-1",
				"openedAt":     "2026-05-15T00:00:00Z",
			}})
		case "/v1/training-attestations":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "attestation-1",
				"personId":     "person-1",
				"userId":       "user-1",
				"courseId":     "security-101",
				"courseName":   "Security Awareness",
				"trainingType": "security_awareness",
				"completedAt":  "2026-06-01T00:00:00Z",
				"controlIds":   []string{"training-control"},
				"evidenceId":   "training-evidence-1",
				"status":       "complete",
			}})
		case "/v1/discovered-vendors":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":               "discovered-vendor-1",
				"name":             "Acme, Inc.",
				"normalizedName":   "Acme",
				"category":         map[string]any{"name": "ai"},
				"source":           "expense",
				"discoveredDate":   "2026-05-01T00:00:00Z",
				"numberOfAccounts": 3,
				"ignored": map[string]any{
					"ignoredAtDate":   "2026-05-02T00:00:00Z",
					"ignoredReason":   "duplicate",
					"ignoredByUserId": "user-1",
				},
			}})
		case "/v1/event-logs":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":     "event-log-1",
				"action": "vendor.review.created",
				"actor":  map[string]any{"type": "user", "id": "user-1"},
				"date":   "2026-05-03T00:00:00Z",
				"targets": []map[string]any{
					{"type": "vendor", "id": "vendor-1"},
					{"type": "control", "id": "control-1"},
				},
			}})
		case "/v1/groups":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "group-1",
				"name":         "Security",
				"creationDate": "2026-01-01T00:00:00Z",
			}})
		case "/v1/vendor-risk-attributes":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":               "risk-attr-1",
				"name":             "Sensitive data",
				"description":      "Vendor processes sensitive data.",
				"vendorCategories": []string{"ai", "infrastructure"},
				"enabled":          true,
				"riskLevel":        "HIGH",
			}})
		case "/v1/people":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "person-1",
				"userId":       "user-1",
				"emailAddress": "designer@example.com",
				"employment": map[string]any{
					"department":     "Design",
					"employeeNumber": "E-1001",
					"jobTitle":       "Product Designer",
					"manager":        "manager@example.com",
					"managerId":      "person-manager",
					"status":         "CURRENT",
				},
			}})
		case "/v1/vulnerabilities":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                "vuln-1",
				"name":              "CVE-2026-4242",
				"packageIdentifier": "pkg:golang/example/module@1.2.3",
				"severity":          "HIGH",
				"cvssSeverityScore": 8.7,
				"targetId":          "target-1",
				"integrationId":     "integration-1",
				"isFixable":         true,
				"remediateByDate":   "2026-05-30T00:00:00Z",
				"lastDetectedDate":  "2026-05-10T00:00:00Z",
			}})
		case "/v1/vulnerability-remediations":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                "remediation-1",
				"vulnerabilityId":   "vuln-1",
				"vulnerableAssetId": "asset-1",
				"severity":          "HIGH",
				"detectedDate":      "2026-05-01T00:00:00Z",
				"slaDeadlineDate":   "2026-06-30T00:00:00Z",
			}})
		case "/v1/vulnerable-assets":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":            "target-1",
				"displayName":   "App Server",
				"hostname":      "app.writer.com",
				"ipAddress":     "203.0.113.10",
				"url":           "https://app.writer.com",
				"assetType":     "server",
				"integrationId": "integration-1",
				"vulnerabilities": []map[string]any{{
					"id":                "CVE-2026-4242",
					"name":              "CVE-2026-4242",
					"packageIdentifier": "pkg:golang/example/module@1.2.3",
				}},
				"lastSeenDate": "2026-05-11T00:00:00Z",
			}})
		case "/v1/monitored-computers":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                    "computer-1",
				"integrationId":         "kandji",
				"lastCheckDate":         "2026-06-24T17:00:00Z",
				"screenlock":            map[string]any{"outcome": "OK"},
				"diskEncryption":        map[string]any{"outcome": "OK"},
				"passwordManager":       map[string]any{"outcome": "NEEDS_ATTENTION"},
				"antivirusInstallation": map[string]any{"outcome": "OK"},
				"operatingSystem":       map[string]any{"type": "MACOS", "version": "15.5"},
				"owner":                 map[string]any{"id": "person-1", "displayName": "Designer One", "emailAddress": "designer@example.com"},
				"serialNumber":          "serial-1",
				"udid":                  "udid-1",
			}})
		case "/v1/tests":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":     "test-1",
				"name":   "Control test 1",
				"status": "FAIL",
				"controls": []map[string]any{
					{"id": "control-1", "externalId": "CC6.2", "name": "Logical access"},
					{"id": "control-2", "externalId": "CC7.1", "name": "Monitoring"},
				},
			}})
		default:
			http.NotFound(w, r)
		}
	})
}
