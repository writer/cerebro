package sync

import "testing"

func TestGCPOrgPolicyName(t *testing.T) {
	selfLink := "//orgpolicy.googleapis.com/projects/p1/policies/iam.allowedPolicyMemberDomains"
	if got := gcpOrgPolicyName(selfLink, ""); got != "iam.allowedPolicyMemberDomains" {
		t.Fatalf("expected policy name from self link, got %q", got)
	}

	if got := gcpOrgPolicyName("", " Display Name "); got != "Display Name" {
		t.Fatalf("expected trimmed display name, got %q", got)
	}
}

func TestGCPOrgPolicyConstraint(t *testing.T) {
	attrs := map[string]interface{}{"constraint": "constraints/iam.allowedPolicyMemberDomains"}
	if got := gcpOrgPolicyConstraint("", attrs); got != "constraints/iam.allowedPolicyMemberDomains" {
		t.Fatalf("expected explicit constraint, got %q", got)
	}

	selfLink := "//orgpolicy.googleapis.com/projects/p1/policies/compute.disableSerialPortAccess"
	if got := gcpOrgPolicyConstraint(selfLink, map[string]interface{}{}); got != "constraints/compute.disableSerialPortAccess" {
		t.Fatalf("expected derived constraint from policy name, got %q", got)
	}
}
