package cloudidentitysource

import (
	"errors"
	"testing"
)

func TestAWSParseIAMPrincipalARN(t *testing.T) {
	cases := []struct {
		arn     string
		wantOK  bool
		account string
		kind    string
		name    string
	}{
		{"arn:aws:iam::111111111111:role/my-role", true, "111111111111", "role", "my-role"},
		{"arn:aws:iam::222222222222:user/path/to/my-user", true, "222222222222", "user", "my-user"},
		{"arn:aws:iam::111111111111:policy/my-policy", false, "", "", ""},
		{"not-an-arn", false, "", "", ""},
	}
	for _, tc := range cases {
		got, ok := awsParseIAMPrincipalARN(tc.arn)
		if ok != tc.wantOK {
			t.Fatalf("awsParseIAMPrincipalARN(%q) ok = %v, want %v", tc.arn, ok, tc.wantOK)
		}
		if !ok {
			continue
		}
		if got.Account != tc.account || got.Kind != tc.kind || got.Name != tc.name {
			t.Fatalf("awsParseIAMPrincipalARN(%q) = %+v, want account=%s kind=%s name=%s", tc.arn, got, tc.account, tc.kind, tc.name)
		}
	}
}

func TestAWSParsePodIdentitySubject(t *testing.T) {
	subject, ok := awsParsePodIdentitySubject("k8s://my-cluster/my-namespace/sa/my-service-account")
	if !ok {
		t.Fatalf("expected subject to parse")
	}
	if subject.Cluster != "my-cluster" || subject.Namespace != "my-namespace" || subject.ServiceAccount != "my-service-account" {
		t.Fatalf("unexpected subject: %+v", subject)
	}
	if _, ok := awsParsePodIdentitySubject("arn:aws:iam::111111111111:role/x"); ok {
		t.Fatalf("expected non-k8s id to fail parsing")
	}
}

func TestAWSDecodePolicyDocument(t *testing.T) {
	plain := `{"Version":"2012-10-17"}`
	got, err := awsDecodePolicyDocument(plain)
	if err != nil || string(got) != plain {
		t.Fatalf("expected plain JSON to pass through unchanged, got %q err %v", got, err)
	}
	encoded := `%7B%22Version%22%3A%222012-10-17%22%7D`
	got, err = awsDecodePolicyDocument(encoded)
	if err != nil || string(got) != plain {
		t.Fatalf("expected url-decoded JSON, got %q err %v", got, err)
	}
	if _, err := awsDecodePolicyDocument(""); err == nil {
		t.Fatalf("expected empty document to error")
	}
}

func TestAWSRequestBudgetExceeded(t *testing.T) {
	budget := &awsRequestBudget{max: 2}
	if err := budget.take(); err != nil {
		t.Fatalf("unexpected error on first take: %v", err)
	}
	if err := budget.take(); err != nil {
		t.Fatalf("unexpected error on second take: %v", err)
	}
	if err := budget.take(); !errors.Is(err, errAWSRequestBudgetExceeded) {
		t.Fatalf("expected budget exceeded error, got %v", err)
	}
}

func TestAWSServiceReferencePathAllowed(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"/v1/eks/eks.json", true},
		{"/v1/eks/other.json", false},
		{"/v1/eks", false},
		{"/v1/mapping.json", false},
		{"/v2/mapping.json", false},
		{"/v1/../mapping.json", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := awsServiceReferencePathAllowed(tc.path); got != tc.want {
			t.Fatalf("awsServiceReferencePathAllowed(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestAWSManagedPolicyAccount(t *testing.T) {
	cases := []struct {
		arn     string
		wantOK  bool
		account string
	}{
		{"arn:aws:iam::aws:policy/AdministratorAccess", true, "aws"},
		{"arn:aws:iam::111111111111:policy/my-policy", true, "111111111111"},
		{"arn:aws:iam::111111111111:role/my-role", false, ""},
		{"gcp-role-name", false, ""},
	}
	for _, tc := range cases {
		account, ok := awsManagedPolicyAccount(tc.arn)
		if ok != tc.wantOK || account != tc.account {
			t.Fatalf("awsManagedPolicyAccount(%q) = (%q, %v), want (%q, %v)", tc.arn, account, ok, tc.account, tc.wantOK)
		}
	}
}
