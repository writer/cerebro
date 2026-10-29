package cloudidentitysource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

const (
	testOrg          = "123456789012"
	testOrgScopePath = "organizations/" + testOrg
	testProjectID    = "my-project"
	testProjectNum   = "111111111111"
	testGSAEmail     = "deploy@" + testProjectID + ".iam.gserviceaccount.com"
)

func writeJSONGCP(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func testGCPReader(t *testing.T, handler http.HandlerFunc, configure func(*GCPOptions)) *gcpReader {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	options := GCPOptions{
		TokenSource:            oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}),
		Organization:           testOrg,
		CloudAssetBaseURL:      server.URL,
		IAMBaseURL:             server.URL,
		ResourceManagerBaseURL: server.URL,
		MaxPages:               5,
		Now:                    func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	if configure != nil {
		configure(&options)
	}
	reader, err := NewGCPReader(options)
	if err != nil {
		t.Fatalf("NewGCPReader() error = %v", err)
	}
	return reader.(*gcpReader)
}

func TestNewGCPReaderRequiresTokenSourceAndOrganization(t *testing.T) {
	if _, err := NewGCPReader(GCPOptions{Organization: testOrg}); err == nil {
		t.Fatal("NewGCPReader() accepted a missing TokenSource")
	}
	if _, err := NewGCPReader(GCPOptions{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})}); err == nil {
		t.Fatal("NewGCPReader() accepted a missing Organization")
	}
	if _, err := NewGCPReader(GCPOptions{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}), Organization: "123/../456"}); err == nil {
		t.Fatal("NewGCPReader() accepted a non-numeric organization id")
	}
}

func TestObserveServiceAccountCollectsGrantsAcrossProjectsAndFoldersWithConditionsAndTrust(t *testing.T) {
	var sawQuotaHeader string
	page := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		sawQuotaHeader = r.Header.Get("X-Goog-User-Project")
		switch {
		case r.URL.Path == "/v3/projects/"+testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID, "state": "ACTIVE"})
		case r.URL.Path == "/v1/projects/"+testProjectID+":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{
				{"resourceId": map[string]any{"type": "project", "id": testProjectNum}},
			}})
		case r.URL.Path == "/v1/projects/"+testProjectID+"/serviceAccounts/"+testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectID + "/serviceAccounts/x", "projectId": testProjectID, "email": testGSAEmail, "disabled": false})
		case r.URL.Path == "/v1/projects/"+testProjectID+"/serviceAccounts/"+testGSAEmail+":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"version": 1, "bindings": []map[string]any{
				{"role": "roles/iam.workloadIdentityUser", "members": []string{"serviceAccount:other@x.iam.gserviceaccount.com"}},
			}})
		case r.URL.Path == "/v1/"+testOrgScopePath+":searchAllIamPolicies" && strings.HasPrefix(r.URL.Query().Get("query"), "resource="):
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		case r.URL.Path == "/v1/"+testOrgScopePath+":searchAllIamPolicies":
			page++
			if page == 1 {
				writeJSONGCP(t, w, http.StatusOK, map[string]any{
					"results": []map[string]any{
						{
							"resource": "//cloudresourcemanager.googleapis.com/projects/222222222222",
							"project":  "projects/222222222222",
							"policy":   map[string]any{"bindings": []map[string]any{{"role": "roles/storage.objectViewer", "members": []string{"serviceAccount:" + testGSAEmail}}}},
						},
						{
							"resource": "//secretmanager.googleapis.com/projects/" + testProjectID + "/secrets/db",
							"project":  "projects/" + testProjectID,
							"policy": map[string]any{"bindings": []map[string]any{{
								"role":      "roles/secretmanager.secretAccessor",
								"members":   []string{"serviceAccount:" + testGSAEmail},
								"condition": map[string]any{"title": "temp", "expression": `request.time < timestamp("2027-01-01T00:00:00Z")`},
							}}},
						},
					},
					"nextPageToken": "page-2",
				})
				return
			}
			writeJSONGCP(t, w, http.StatusOK, map[string]any{
				"results": []map[string]any{
					{
						"resource": "//cloudresourcemanager.googleapis.com/folders/999",
						"folders":  []string{"folders/999"},
						"policy":   map[string]any{"bindings": []map[string]any{{"role": "roles/pubsub.subscriber", "members": []string{"serviceAccount:" + testGSAEmail}}}},
					},
				},
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, func(o *GCPOptions) { o.QuotaProject = "quota-proj" })

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if sawQuotaHeader != "quota-proj" {
		t.Fatalf("X-Goog-User-Project header = %q, want quota-proj", sawQuotaHeader)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if got := len(observation.Policy.Grants); got != 3 {
		t.Fatalf("len(Grants) = %d, want 3 (cross-project + conditional + folder-scoped)", got)
	}
	var sawCondition, sawCrossProject, sawFolder bool
	for _, grant := range observation.Policy.Grants {
		if len(grant.Conditions) > 0 && grant.Conditions[0].Expression != "" {
			sawCondition = true
		}
		if len(grant.Resources) == 1 && grant.Resources[0] == "//cloudresourcemanager.googleapis.com/projects/222222222222" {
			sawCrossProject = true
		}
		if len(grant.Resources) == 1 && grant.Resources[0] == "//cloudresourcemanager.googleapis.com/folders/999" {
			sawFolder = true
		}
	}
	if !sawCondition {
		t.Fatal("no grant preserved its CEL condition expression")
	}
	if !sawCrossProject {
		t.Fatal("no grant captured a binding defined in a different project than the GSA's own")
	}
	if !sawFolder {
		t.Fatal("no grant captured a folder-scoped binding")
	}
	if len(observation.Policy.Trust) != 1 || observation.Policy.Trust[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("Trust = %+v, want exactly the workloadIdentityUser SA-resource binding", observation.Policy.Trust)
	}
	if observation.ResolvedIdentifiers["project_number"] != testProjectNum {
		t.Fatalf("ResolvedIdentifiers[project_number] = %q, want %q", observation.ResolvedIdentifiers["project_number"], testProjectNum)
	}
}

func TestObserveServiceAccountAccessDeniedProducesGapNotExcess(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "caller lacks cloudasset.assets.searchAllIamPolicies", "status": "PERMISSION_DENIED"}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v, want nil error with a gap instead", err)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true after a 403 from searchAllIamPolicies")
	}
	if len(observation.Policy.Grants) != 0 {
		t.Fatalf("Grants = %+v, want none when the search was denied (no excess may be fabricated from a refusal)", observation.Policy.Grants)
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_permission_denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_permission_denied", observation.Policy.Gaps)
	}
}

func TestObserveServiceAccountPaginationBudgetExceededIsAGapNotSilentTruncation(t *testing.T) {
	calls := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			calls++
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}, "nextPageToken": "always-more"})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, func(o *GCPOptions) { o.MaxPages = 2 })

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("searchAllIamPolicies calls = %d, want exactly MaxPages (2)", calls)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true despite an exhausted pagination budget")
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_search_iam_policies_pagination_truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_search_iam_policies_pagination_truncated", observation.Policy.Gaps)
	}
}

func TestObserveKubernetesServiceAccountAppliesBroaderPrincipalSetsButNotUnrelatedNamespaces(t *testing.T) {
	var sawQuery string
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			sawQuery = r.URL.Query().Get("query")
			base := "iam.googleapis.com/projects/" + testProjectNum + "/locations/global/workloadIdentityPools/" + testProjectID + ".svc.id.goog"
			writeJSONGCP(t, w, http.StatusOK, map[string]any{
				"results": []map[string]any{
					{"resource": "//storage.googleapis.com/b/exact-bucket", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/storage.objectViewer", "members": []string{"principal://" + base + "/subject/ns/payments/sa/worker"}},
					}}},
					{"resource": "//bigquery.googleapis.com/projects/" + testProjectID + "/datasets/ds", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/bigquery.dataViewer", "members": []string{"principalSet://" + base + "/namespace/payments"}},
					}}},
					{"resource": "//logging.googleapis.com/projects/" + testProjectID, "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/logging.logWriter", "members": []string{"principalSet://" + base + "/*"}},
					}}},
					{"resource": "//storage.googleapis.com/b/other-namespace-bucket", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/storage.admin", "members": []string{"principalSet://" + base + "/namespace/checkout"}},
					}}},
				},
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID:       "k8s://cluster-a/payments/sa/worker",
		Provider: ci.GCP,
		Kind:     gcpKindKubernetesServiceAccount,
		Project:  testProjectID,
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	wantQuery := `policy:"` + testProjectID + `.svc.id.goog"`
	if sawQuery != wantQuery {
		t.Fatalf("search query = %q, want %q (must scope by pool, not a single exact subject, so namespace/pool-wide principalSet grants are not filtered out server-side)", sawQuery, wantQuery)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if got := len(observation.Policy.Grants); got != 3 {
		t.Fatalf("len(Grants) = %d, want 3 (exact + namespace-wide + pool-wide), got %+v", got, observation.Policy.Grants)
	}
	for _, grant := range observation.Policy.Grants {
		if grant.Role == "roles/storage.admin" {
			t.Fatalf("grant %+v leaked from an unrelated namespace principalSet", grant)
		}
	}
}

func TestObserveKubernetesServiceAccountRefusesUnresolvedProjectPlaceholder(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no GCP call should be made for an unresolved project, got %s", r.URL.Path)
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID:       "k8s://cluster-a/payments/sa/worker",
		Provider: ci.GCP,
		Kind:     gcpKindKubernetesServiceAccount,
		Project:  "${project_id}",
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	found := false
	for _, gap := range observation.Gaps {
		if gap.Code == "gcp_project_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_project_unresolved for a placeholder project", observation.Gaps)
	}
	if len(observation.Policy.Grants) != 0 {
		t.Fatalf("Grants = %+v, want none when the project could not be resolved", observation.Policy.Grants)
	}
}

func TestObserveUnsupportedPrincipalKindIsAScopedGap(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no GCP call should be made for an unsupported principal kind, got %s", r.URL.Path)
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: "arn:aws:iam::1:role/x", Provider: ci.AWS, Kind: "aws_iam_role"}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if len(observation.Gaps) != 1 || observation.Gaps[0].Code != "gcp_principal_kind_unsupported" {
		t.Fatalf("Gaps = %+v, want exactly one gcp_principal_kind_unsupported", observation.Gaps)
	}
}

func TestObserveServiceAccountOutboundImpersonationGrantStaysInGrantsNotTrust(t *testing.T) {
	const targetGSAEmail = "target@other-project.iam.gserviceaccount.com"
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{
				"results": []map[string]any{
					{
						"resource": "//iam.googleapis.com/projects/other-project/serviceAccounts/" + targetGSAEmail,
						"policy": map[string]any{"bindings": []map[string]any{{
							"role":    "roles/iam.serviceAccountTokenCreator",
							"members": []string{"serviceAccount:" + testGSAEmail},
						}}},
					},
				},
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if len(observation.Policy.Trust) != 0 {
		t.Fatalf("Trust = %+v, want none: this principal's own resource had no bindings, only an outbound grant", observation.Policy.Trust)
	}
	found := false
	for _, grant := range observation.Policy.Grants {
		if grant.Role == "roles/iam.serviceAccountTokenCreator" && len(grant.Resources) == 1 && grant.Resources[0] == "//iam.googleapis.com/projects/other-project/serviceAccounts/"+targetGSAEmail {
			found = true
		}
	}
	if !found {
		t.Fatalf("Grants = %+v, want the outbound serviceAccountTokenCreator grant on the OTHER service account to remain a Grant, not be hidden in Trust", observation.Policy.Grants)
	}
}

func TestObserveKubernetesServiceAccountCanonicalURIInputSkipsProjectResolution(t *testing.T) {
	canonical := gcpCanonicalKSAURI(testProjectNum, testProjectID, "payments", "worker")
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/projects/"+testProjectID {
			t.Fatalf("canonical principal:// input must not trigger a redundant Resource Manager project lookup")
		}
		if r.URL.Path != "/v1/"+testOrgScopePath+":searchAllIamPolicies" {
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
		base := "iam.googleapis.com/projects/" + testProjectNum + "/locations/global/workloadIdentityPools/" + testProjectID + ".svc.id.goog"
		writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{
			{"resource": "//storage.googleapis.com/b/bucket", "policy": map[string]any{"bindings": []map[string]any{
				{"role": "roles/storage.objectViewer", "members": []string{"principal://" + base + "/subject/ns/payments/sa/worker"}},
			}}},
		}})
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: canonical, Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if !observation.Policy.Complete || len(observation.Policy.Grants) != 1 {
		t.Fatalf("Observation = %+v, want one complete grant from the canonical URI input alone", observation)
	}
	if observation.ResolvedIdentifiers["project_number"] != testProjectNum {
		t.Fatalf("ResolvedIdentifiers[project_number] = %q, want %q", observation.ResolvedIdentifiers["project_number"], testProjectNum)
	}
}

func TestObserveKubernetesServiceAccountCrossClusterSamePrincipalEmitsIdenticalCanonicalAlias(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	clusterA, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID: "k8s://cluster-a/payments/sa/worker", Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount, Project: testProjectID,
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	clusterB, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID: "k8s://cluster-b/payments/sa/worker", Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount, Project: testProjectID,
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	wantCanonical := gcpCanonicalKSAURI(testProjectNum, testProjectID, "payments", "worker")
	aliasA := clusterA.ResolvedIdentifiers["gcp_ksa_principal:k8s://cluster-a/payments/sa/worker"]
	aliasB := clusterB.ResolvedIdentifiers["gcp_ksa_principal:k8s://cluster-b/payments/sa/worker"]
	if aliasA != wantCanonical || aliasB != wantCanonical {
		t.Fatalf("cross-cluster aliases = %q / %q, want both to equal the same canonical principal %q so a caller can union them (identity sameness)", aliasA, aliasB, wantCanonical)
	}
	if _, ok := clusterA.ResolvedIdentifiers["kubernetes_cluster"]; ok {
		t.Fatal(`ResolvedIdentifiers must not carry a generic "kubernetes_cluster" key that would conflict when merging same-principal cohorts across clusters`)
	}
}

func TestObserveServiceAccountResolvesCrossProjectCallerProjectNumbers(t *testing.T) {
	const callerProject = "gke-host-project"
	const callerProjectNum = "333333333333"
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v3/projects/" + callerProject:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + callerProjectNum, "projectId": callerProject})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount},
		Consumers: []ci.Workload{
			{CloudProject: callerProject},
			{CloudProject: callerProject}, // duplicate must not trigger a second lookup
			{CloudProject: testProjectID}, // same as the GSA's own project: must reuse, not re-call
		},
	})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if got := observation.ResolvedIdentifiers["project_number"]; got != testProjectNum {
		t.Fatalf("ResolvedIdentifiers[project_number] = %q, want the GSA's own project number %q", got, testProjectNum)
	}
	if got := observation.ResolvedIdentifiers["gcp_project_number:"+callerProject]; got != callerProjectNum {
		t.Fatalf("ResolvedIdentifiers[gcp_project_number:%s] = %q, want the caller's OWN project number %q, distinct from the GSA's own project", callerProject, got, callerProjectNum)
	}
	if got := observation.ResolvedIdentifiers["gcp_project_number:"+testProjectID]; got != testProjectNum {
		t.Fatalf("ResolvedIdentifiers[gcp_project_number:%s] = %q, want %q reused from the GSA's own resolution", testProjectID, got, testProjectNum)
	}
}

func TestObserveServiceAccountCallerProjectResolutionFailureIsScopedGap(t *testing.T) {
	const callerProject = "gke-host-project"
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v3/projects/" + callerProject:
			writeJSONGCP(t, w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount},
		Consumers: []ci.Workload{{CloudProject: callerProject}},
	})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true despite a denied caller project lookup")
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_permission_denied" && gap.Scope == callerProject {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want a gcp_permission_denied gap scoped to %q", observation.Policy.Gaps, callerProject)
	}
	if _, ok := observation.ResolvedIdentifiers["gcp_project_number:"+callerProject]; ok {
		t.Fatal("ResolvedIdentifiers must not fabricate a caller project number when resolution failed")
	}
}

func TestObserveKubernetesServiceAccountEmitsSelfKeyedCallerProjectNumber(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID: "k8s://cluster-a/payments/sa/worker", Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount, Project: testProjectID,
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if got := observation.ResolvedIdentifiers["gcp_project_number:"+testProjectID]; got != testProjectNum {
		t.Fatalf("ResolvedIdentifiers[gcp_project_number:%s] = %q, want %q (same key format as the GSA cross-project case)", testProjectID, got, testProjectNum)
	}
}

func TestObserveServiceAccountIAMPolicyUsesPostWithRequestedPolicyVersionThree(t *testing.T) {
	var sawMethod string
	var sawBody []byte
	var sawQuery string
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			sawMethod = r.Method
			sawQuery = r.URL.Query().Get("options.requestedPolicyVersion")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read getIamPolicy request body: %v", err)
			}
			sawBody = body
			if r.Method != http.MethodPost {
				writeJSONGCP(t, w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{"code": 405, "message": "method not allowed: this endpoint requires POST"}})
				return
			}
			if len(body) != 0 {
				writeJSONGCP(t, w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": 400, "message": "the request body must be empty"}})
				return
			}
			if sawQuery != "3" {
				writeJSONGCP(t, w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": 400, "message": "options.requestedPolicyVersion must be 3"}})
				return
			}
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"version": 3, "bindings": []map[string]any{
				{"role": "roles/iam.workloadIdentityUser", "members": []string{"serviceAccount:other@x.iam.gserviceaccount.com"}},
			}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if sawMethod != http.MethodPost {
		t.Fatalf("getIamPolicy method = %q, want POST", sawMethod)
	}
	if len(sawBody) != 0 {
		t.Fatalf("getIamPolicy request body = %q, want empty per the documented contract", sawBody)
	}
	if sawQuery != "3" {
		t.Fatalf("getIamPolicy options.requestedPolicyVersion query = %q, want %q", sawQuery, "3")
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if len(observation.Policy.Trust) != 1 || observation.Policy.Trust[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("Trust = %+v, want the SA's own policy bindings, which a GET, non-empty body, or missing-version request would never successfully decode", observation.Policy.Trust)
	}
}

func TestObserveServiceAccountInheritedAncestorImpersonationTrust(t *testing.T) {
	const folderID = "888888888888"
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{
				{"resourceId": map[string]any{"type": "project", "id": testProjectNum}},
				{"resourceId": map[string]any{"type": "folder", "id": folderID}},
			}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/roles/iam.serviceAccountTokenCreator":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "roles/iam.serviceAccountTokenCreator", "includedPermissions": []string{"iam.serviceAccounts.getAccessToken"}})
		case "/v1/roles/storage.objectViewer":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "roles/storage.objectViewer", "includedPermissions": []string{"storage.objects.get"}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			query := r.URL.Query().Get("query")
			switch {
			case strings.HasPrefix(query, "resource=//cloudresourcemanager.googleapis.com/folders/"+folderID):
				writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{
					{
						"resource": "//cloudresourcemanager.googleapis.com/folders/" + folderID,
						"folders":  []string{"folders/" + folderID},
						"policy": map[string]any{"bindings": []map[string]any{
							{
								"role":    "roles/iam.serviceAccountTokenCreator",
								"members": []string{"user:alice@example.com"},
							},
							{
								// Known role, known NOT impersonation-capable: must
								// be dropped from Trust, not just left unmatched.
								"role":    "roles/storage.objectViewer",
								"members": []string{"user:bob@example.com"},
							},
						}},
					},
				}})
			default:
				writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
			}
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	found := false
	for _, grant := range observation.Policy.Trust {
		if grant.Role == "roles/storage.objectViewer" {
			t.Fatalf("Trust = %+v, want the known-incapable storage.objectViewer binding dropped, not kept", observation.Policy.Trust)
		}
		if grant.Role == "roles/iam.serviceAccountTokenCreator" && len(grant.Resources) == 1 && grant.Resources[0] == "//cloudresourcemanager.googleapis.com/folders/"+folderID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Trust = %+v, want the inherited parent-folder Token Creator binding", observation.Policy.Trust)
	}
	if len(observation.Policy.Trust) != 1 {
		t.Fatalf("Trust = %+v, want exactly 1 (the capable binding; the incapable one dropped)", observation.Policy.Trust)
	}
}

// TestObserveServiceAccountAncestorUnreadableRoleBindingRetainedWithGap is
// the R09 regression: Cloud Asset's searchAllIamPolicies contract states
// that a policy.role.permissions:<perm> query term silently drops policy
// bindings whose role the caller cannot read
// (https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies).
// Pre-fix, effectiveAncestryTrust issued exactly that permission-filtered
// query (gcpAncestorTrustQuery), so this fake Cloud Asset server — which
// omits the binding from a permission-filtered search but returns it from
// an unfiltered resource-scoped search, mirroring the documented contract —
// would have observed the ancestor trust as complete AND missing the
// binding. Post-fix, the reader queries unfiltered and resolves the role
// itself; an IAM roles.get denial for that role must retain the binding in
// Trust (conservative possibly-capable) and record an explicit gap, never
// silently drop it.
func TestObserveServiceAccountAncestorUnreadableRoleBindingRetainedWithGap(t *testing.T) {
	const roleName = "projects/other-project/roles/mystery"
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{
				{"resourceId": map[string]any{"type": "project", "id": testProjectNum}},
			}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + roleName:
			// The caller lacks iam.roles.get on this role: Cloud Asset's
			// documented contract is to drop any policy.role.permissions:
			// filtered result mentioning it, which is exactly the gap this
			// reader must now surface instead of silently losing the
			// binding.
			writeJSONGCP(t, w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "caller lacks iam.roles.get", "status": "PERMISSION_DENIED"}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			query := r.URL.Query().Get("query")
			resource := "resource=//cloudresourcemanager.googleapis.com/projects/" + testProjectNum
			if query != resource {
				// This is the regression guard for the contract itself: a
				// permission-filtered query (the pre-fix shape) must never
				// be sent again, since Cloud Asset would then silently
				// drop this exact binding server-side.
				writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
				return
			}
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{
				{
					"resource": "//cloudresourcemanager.googleapis.com/projects/" + testProjectNum,
					"project":  "projects/" + testProjectNum,
					"policy": map[string]any{"bindings": []map[string]any{{
						"role":    roleName,
						"members": []string{"user:mallory@example.com"},
					}}},
				},
			}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	found := false
	for _, grant := range observation.Policy.Trust {
		if grant.Role == roleName && len(grant.Resources) == 1 && grant.Resources[0] == "//cloudresourcemanager.googleapis.com/projects/"+testProjectNum {
			found = true
		}
	}
	if !found {
		t.Fatalf("Trust = %+v, want the unreadable-role ancestor binding retained conservatively, not silently dropped", observation.Policy.Trust)
	}
	gapFound := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_permission_denied" && strings.Contains(gap.Scope, roleName) {
			gapFound = true
		}
	}
	if !gapFound {
		t.Fatalf("Gaps = %+v, want an explicit gap recording the denied role lookup for %q", observation.Policy.Gaps, roleName)
	}
}

func TestObserveServiceAccountAncestryFailureIsIncomplete(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true despite a failed ancestry resolution; inherited impersonation trust cannot be ruled out")
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_permission_denied" && gap.Scope == testProjectID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want a gcp_permission_denied gap scoped to %q", observation.Policy.Gaps, testProjectID)
	}
}

func TestObserveServiceAccountMatchesHierarchyServiceAccountPrincipalSet(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/projects/" + testProjectID + ":getAncestry":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"ancestor": []map[string]any{
				{"resourceId": map[string]any{"type": "project", "id": testProjectNum}},
			}})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"email": testGSAEmail})
		case "/v1/projects/" + testProjectID + "/serviceAccounts/" + testGSAEmail + ":getIamPolicy":
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"bindings": []map[string]any{}})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			if strings.HasPrefix(r.URL.Query().Get("query"), "resource=") {
				writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{}})
				return
			}
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"results": []map[string]any{
				{
					"resource": "//storage.googleapis.com/b/project-bucket",
					"policy": map[string]any{"bindings": []map[string]any{{
						"role":    "roles/storage.objectViewer",
						"members": []string{"principalSet://cloudresourcemanager.googleapis.com/projects/" + testProjectNum + "/type/ServiceAccount"},
					}}},
				},
			}})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{ID: testGSAEmail, Provider: ci.GCP, Kind: gcpKindServiceAccount}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if got := len(observation.Policy.Grants); got != 1 || observation.Policy.Grants[0].Role != "roles/storage.objectViewer" {
		t.Fatalf("Grants = %+v, want exactly the project-level type/ServiceAccount principalSet grant matched", observation.Policy.Grants)
	}
}

func TestObserveKubernetesServiceAccountMatchesLegacyAndClusterScopedForms(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			base := "iam.googleapis.com/projects/" + testProjectNum + "/locations/global/workloadIdentityPools/" + testProjectID + ".svc.id.goog"
			writeJSONGCP(t, w, http.StatusOK, map[string]any{
				"results": []map[string]any{
					{"resource": "//storage.googleapis.com/b/legacy-bucket", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/storage.objectViewer", "members": []string{"serviceAccount:" + testProjectID + ".svc.id.goog[payments/worker]"}},
					}}},
					{"resource": "//bigquery.googleapis.com/projects/" + testProjectID + "/datasets/ds", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/bigquery.dataViewer", "members": []string{"principalSet://" + base + "/kubernetes.cluster/https://container.googleapis.com/v1/projects/" + testProjectID + "/locations/us-central1/clusters/cluster-a"}},
					}}},
				},
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "k8s://cluster-a/payments/sa/worker", Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount, Project: testProjectID},
		Consumers: []ci.Workload{{ID: "w1", Cluster: "cluster-a", Region: "us-central1"}},
	})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("Policy.Complete = false, gaps = %+v", observation.Policy.Gaps)
	}
	if got := len(observation.Policy.Grants); got != 2 {
		t.Fatalf("len(Grants) = %d, want 2 (legacy bracket form + cluster-scoped principalSet), got %+v", got, observation.Policy.Grants)
	}
}

func TestObserveKubernetesServiceAccountUnresolvedPoolFormIsIncomplete(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/projects/" + testProjectID:
			writeJSONGCP(t, w, http.StatusOK, map[string]any{"name": "projects/" + testProjectNum, "projectId": testProjectID})
		case "/v1/" + testOrgScopePath + ":searchAllIamPolicies":
			base := "iam.googleapis.com/projects/" + testProjectNum + "/locations/global/workloadIdentityPools/" + testProjectID + ".svc.id.goog"
			writeJSONGCP(t, w, http.StatusOK, map[string]any{
				"results": []map[string]any{
					{"resource": "//storage.googleapis.com/b/weird-bucket", "policy": map[string]any{"bindings": []map[string]any{
						{"role": "roles/storage.admin", "members": []string{"principalSet://" + base + "/group/undocumented-form"}},
					}}},
				},
			})
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}
	reader := testGCPReader(t, handler, nil)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{Principal: ci.Principal{
		ID: "k8s://cluster-a/payments/sa/worker", Provider: ci.GCP, Kind: gcpKindKubernetesServiceAccount, Project: testProjectID,
	}})
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true despite an unrecognized pool-scoped member form that could apply")
	}
	if len(observation.Policy.Grants) != 0 {
		t.Fatalf("Grants = %+v, want none fabricated from an unrecognized form", observation.Policy.Grants)
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "gcp_ksa_principal_form_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want gcp_ksa_principal_form_unresolved", observation.Policy.Gaps)
	}
}
