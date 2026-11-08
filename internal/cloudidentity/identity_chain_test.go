package cloudidentity

import "testing"

const testIssuerHost = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
const testProviderARN = "arn:aws:iam::123456789012:oidc-provider/" + testIssuerHost

func trustGrant(members []string, conditions []Condition) Grant {
	return Grant{Effect: "Allow", Members: members, Conditions: conditions}
}

func TestValidateIRSATrustExactMatch(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:" + testProviderARN},
		[]Condition{
			{Operator: "StringEquals", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:payments-sa"}},
			{Operator: "StringEquals", Key: testIssuerHost + ":aud", Values: []string{"sts.amazonaws.com"}},
		},
	)}
	result := ValidateIRSATrust(trust, "https://"+testIssuerHost, testProviderARN, "payments", "payments-sa")
	if !result.Matched || !result.Exact || !result.AudienceRestricted || result.BroadPrincipal || result.Inconclusive {
		t.Fatalf("expected exact matched trust, got %+v", result)
	}
}

func TestValidateIRSATrustWildcardSubjectIsBroad(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:" + testProviderARN},
		[]Condition{{Operator: "StringLike", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:*"}}},
	)}
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if !result.Matched || result.Exact {
		t.Fatalf("expected matched but non-exact (wildcard subject) trust, got %+v", result)
	}
}

func TestValidateIRSATrustBroadPrincipalWildcard(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:*"},
		[]Condition{{Operator: "StringEquals", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:payments-sa"}}},
	)}
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if !result.Matched || !result.BroadPrincipal || result.Exact {
		t.Fatalf("expected matched but broad-principal trust, got %+v", result)
	}
}

func TestValidateIRSATrustWrongPrincipalDoesNotMatch(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:arn:aws:iam::999999999999:oidc-provider/other.issuer"},
		[]Condition{{Operator: "StringEquals", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:payments-sa"}}},
	)}
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if result.Matched {
		t.Fatalf("expected no match for a different OIDC provider ARN, got %+v", result)
	}
}

func TestValidateIRSATrustDifferentServiceAccountDoesNotMatch(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:" + testProviderARN},
		[]Condition{{Operator: "StringEquals", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:other-sa"}}},
	)}
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if result.Matched {
		t.Fatalf("expected no match for a different service account subject, got %+v", result)
	}
}

func TestValidateIRSATrustUnresolvedIssuerIsInconclusive(t *testing.T) {
	result := ValidateIRSATrust(nil, "", testProviderARN, "payments", "payments-sa")
	if result.Matched || !result.Inconclusive {
		t.Fatalf("expected inconclusive result for an unresolved issuer, got %+v", result)
	}
}

func TestValidateIRSATrustUnresolvedProviderARNIsInconclusive(t *testing.T) {
	result := ValidateIRSATrust(nil, testIssuerHost, "", "payments", "payments-sa")
	if result.Matched || !result.Inconclusive {
		t.Fatalf("expected inconclusive result for an unresolved provider ARN, got %+v", result)
	}
}

func TestValidateIRSATrustPolicyVariableIsInconclusiveNotNegative(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:" + testProviderARN},
		[]Condition{{Operator: "StringLike", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:${aws:username}:payments-sa"}}},
	)}
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if result.Matched {
		t.Fatalf("policy-variable subject must never resolve to a confirmed match, got %+v", result)
	}
	if !result.Inconclusive {
		t.Fatalf("expected inconclusive, not a confirmed negative, got %+v", result)
	}
}

func TestValidateIRSATrustDenyEffectIgnored(t *testing.T) {
	trust := []Grant{trustGrant(
		[]string{"Federated:" + testProviderARN},
		[]Condition{{Operator: "StringEquals", Key: testIssuerHost + ":sub", Values: []string{"system:serviceaccount:payments:payments-sa"}}},
	)}
	trust[0].Effect = "Deny"
	result := ValidateIRSATrust(trust, testIssuerHost, testProviderARN, "payments", "payments-sa")
	if result.Matched {
		t.Fatalf("a Deny statement must never produce a Matched trust, got %+v", result)
	}
}
