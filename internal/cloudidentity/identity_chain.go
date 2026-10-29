package cloudidentity

import (
	"path"
	"strings"
)

// IRSATrustMatch reports whether a role's parsed trust-policy grants (an
// Evidence's Observed.Trust) actually scope an AssumeRoleWithWebIdentity to
// one cluster's OIDC issuer/provider and the exact Kubernetes service-account
// subject that a configured "aws_iam_role" principal claims to represent. It
// never performs I/O; callers supply the already-resolved cluster OIDC issuer
// host and provider ARN (e.g. from Observation.ResolvedIdentifiers
// "aws_eks_oidc_issuer:<cluster>" / "aws_eks_oidc_provider_arn:<cluster>").
type IRSATrustMatch struct {
	// Matched is true when at least one Allow trust grant both (a) names the
	// cluster's OIDC provider ARN (or a bare "*"/"Federated:*" principal) and
	// (b) conditions on "<issuer>:sub" with a pattern that covers the exact
	// "system:serviceaccount:<namespace>:<name>" subject.
	Matched bool
	// Exact is true only when the matching grant pins the literal subject
	// with no wildcard and names the provider ARN exactly (no "*"); false
	// with Matched true means the role also trusts other service accounts
	// and/or any federated principal, a broader trust than the single
	// configured KSA.
	Exact bool
	// AudienceRestricted is true when a matching grant also restricts the
	// "<issuer>:aud" claim to the STS default "sts.amazonaws.com".
	AudienceRestricted bool
	// BroadPrincipal is true when a matching grant's Principal is a bare "*"
	// or "Federated:*" rather than this cluster's specific OIDC provider ARN.
	BroadPrincipal bool
	// Inconclusive is true when the trust policy could not be safely
	// evaluated (unresolved issuer/provider ARN, or a policy-variable
	// subject pattern we do not evaluate); Matched must not be read as a
	// confirmed negative in that case.
	Inconclusive bool
	Gaps         []Gap
}

// ValidateIRSATrust compares a role's trust grants against the cluster OIDC
// issuer/provider ARN and exact Kubernetes service account subject a
// manifest-derived "aws_iam_role" principal was configured for.
func ValidateIRSATrust(trust []Grant, issuerHost, issuerProviderARN, namespace, serviceAccount string) IRSATrustMatch {
	var result IRSATrustMatch
	host := manifestInventoryStripIssuerScheme(issuerHost)
	scope := namespace + "/" + serviceAccount
	if host == "" {
		result.Inconclusive = true
		result.Gaps = append(result.Gaps, Gap{
			Code:    "cloud_identity.inventory.irsa_issuer_unresolved",
			Scope:   scope,
			Message: "cluster OIDC issuer host was not resolved; IRSA trust could not be evaluated",
		})
		return result
	}
	if issuerProviderARN == "" {
		result.Inconclusive = true
		result.Gaps = append(result.Gaps, Gap{
			Code:    "cloud_identity.inventory.irsa_provider_arn_unresolved",
			Scope:   scope,
			Message: "cluster OIDC provider ARN was not resolved; IRSA trust principal could not be evaluated",
		})
		return result
	}
	subject := "system:serviceaccount:" + namespace + ":" + serviceAccount
	federatedExact := "Federated:" + issuerProviderARN

	for _, grant := range trust {
		if !strings.EqualFold(grant.Effect, "Allow") {
			continue
		}
		principalMatched, principalBroad := manifestInventoryPrincipalMatches(grant.Members, federatedExact)
		if !principalMatched {
			continue
		}

		audienceOK := false
		subjectMatched, subjectExact, inconclusive := false, false, false
		for _, cond := range grant.Conditions {
			key := strings.TrimSpace(cond.Key)
			switch {
			case strings.HasSuffix(key, ":aud"):
				if manifestInventoryConditionIsAudience(cond) {
					audienceOK = true
				}
			case strings.HasSuffix(key, ":sub"):
				if strings.TrimSuffix(key, ":sub") != host {
					continue
				}
				matched, exact, incon := manifestInventoryConditionMatchesSubject(cond.Operator, cond.Values, subject)
				if incon {
					inconclusive = true
				}
				if matched {
					subjectMatched = true
					if exact {
						subjectExact = true
					}
				}
			}
		}
		if inconclusive {
			result.Inconclusive = true
			result.Gaps = append(result.Gaps, Gap{
				Code:    "cloud_identity.inventory.irsa_subject_policy_variable_unsupported",
				Scope:   scope,
				Message: "trust condition subject uses an unevaluated IAM policy variable",
			})
		}
		if subjectMatched {
			result.Matched = true
			if audienceOK {
				result.AudienceRestricted = true
			}
			if principalBroad {
				result.BroadPrincipal = true
			}
			if subjectExact && !principalBroad {
				result.Exact = true
			}
		}
	}
	if result.BroadPrincipal {
		result.Exact = false
	}
	return result
}

// manifestInventoryPrincipalMatches reports whether a trust grant's Members
// authorize the exact federated provider ARN, distinguishing that precise
// match from a bare wildcard principal that would also authorize any other
// OIDC/federated identity provider.
func manifestInventoryPrincipalMatches(members []string, federatedExact string) (matched, broad bool) {
	for _, m := range members {
		switch m {
		case federatedExact:
			return true, false
		case "*", "Federated:*":
			matched = true
			broad = true
		}
	}
	return matched, broad
}

func manifestInventoryStripIssuerScheme(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	issuer = strings.TrimPrefix(issuer, "https://")
	issuer = strings.TrimPrefix(issuer, "http://")
	return strings.TrimSuffix(issuer, "/")
}

func manifestInventoryConditionIsAudience(cond Condition) bool {
	if !strings.HasPrefix(cond.Operator, "StringEquals") {
		return false
	}
	for _, v := range cond.Values {
		if v == "sts.amazonaws.com" {
			return true
		}
	}
	return false
}

// manifestInventoryConditionMatchesSubject evaluates one IRSA trust
// condition's operator/values against the exact service-account subject.
// inconclusive is true when a value contains an IAM policy variable
// ("${...}") that cannot be safely evaluated without live request context.
func manifestInventoryConditionMatchesSubject(operator string, values []string, subject string) (matched, exact, inconclusive bool) {
	for _, v := range values {
		if strings.Contains(v, "${") {
			inconclusive = true
			continue
		}
		switch {
		case strings.HasPrefix(operator, "StringEquals"):
			if v == subject {
				return true, true, inconclusive
			}
		case strings.HasPrefix(operator, "StringLike"):
			if v == subject {
				return true, true, inconclusive
			}
			if ok, _ := path.Match(v, subject); ok {
				matched = true
			}
		}
	}
	return matched, false, inconclusive
}
