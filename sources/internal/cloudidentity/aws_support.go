package cloudidentitysource

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// awsRequestBudget bounds the total number of AWS API / service-reference HTTP
// calls a reader instance will issue. It exists so a misconfigured scan (huge
// fan-out, a hostile pagination loop) cannot run unbounded against live AWS or
// the public SAR endpoint.
type awsRequestBudget struct {
	mu    sync.Mutex
	max   int
	spent int
}

var errAWSRequestBudgetExceeded = fmt.Errorf("cloudidentitysource: aws request budget exceeded")

// take consumes one unit of budget, returning an error once exhausted.
func (b *awsRequestBudget) take() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.spent >= b.max {
		return errAWSRequestBudgetExceeded
	}
	b.spent++
	return nil
}

// awsIAMPrincipal describes an IAM role or user ARN parsed from a Principal.ID.
type awsIAMPrincipal struct {
	Account string
	Kind    string // "role" or "user"
	Name    string
	ARN     string
}

var awsIAMARNPattern = regexp.MustCompile(`^arn:aws[a-zA-Z0-9-]*:iam::(\d{12}):(role|user)/(.+)$`)

// awsParseIAMPrincipalARN parses a full IAM role/user ARN. Paths in the
// resource segment (role/path/name) are kept; Name is the final segment.
func awsParseIAMPrincipalARN(arn string) (awsIAMPrincipal, bool) {
	match := awsIAMARNPattern.FindStringSubmatch(strings.TrimSpace(arn))
	if match == nil {
		return awsIAMPrincipal{}, false
	}
	resource := match[3]
	name := resource
	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		name = resource[idx+1:]
	}
	return awsIAMPrincipal{Account: match[1], Kind: match[2], Name: name, ARN: arn}, true
}

var awsKubernetesServiceAccountPattern = regexp.MustCompile(`^k8s://([^/]+)/([^/]+)/sa/([^/]+)$`)

// awsPodIdentitySubject describes a Kubernetes service-account principal that
// may or may not have a live EKS Pod Identity association.
type awsPodIdentitySubject struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
}

func awsParsePodIdentitySubject(id string) (awsPodIdentitySubject, bool) {
	match := awsKubernetesServiceAccountPattern.FindStringSubmatch(strings.TrimSpace(id))
	if match == nil {
		return awsPodIdentitySubject{}, false
	}
	return awsPodIdentitySubject{Cluster: match[1], Namespace: match[2], ServiceAccount: match[3]}, true
}

// awsClusterKey identifies a cluster's unique live location among a plan's
// consumers: cluster name alone is not a stable identity across accounts or
// regions (two unrelated EKS clusters can share a name).
type awsClusterKey struct {
	Account string
	Region  string
}

// awsConsumerClusterLocations groups consumers by cluster name and returns,
// for each distinct name, the single (account, region) pair every matching
// consumer agrees on in locations. A cluster name whose consumers disagree
// (different account and/or region reported for the same name) is a genuine
// ambiguity -- querying any one of them risks attributing another cluster's
// identity data to this role/service account -- so it is reported in
// ambiguous instead and must never be silently resolved to either side.
func awsConsumerClusterLocations(consumers []ci.Workload) (locations map[string]awsClusterKey, ambiguous map[string]bool) {
	seen := map[string]map[awsClusterKey]bool{}
	for _, workload := range consumers {
		if workload.Cluster == "" {
			continue
		}
		key := awsClusterKey{Account: strings.TrimSpace(workload.CloudAccount), Region: strings.TrimSpace(workload.Region)}
		if seen[workload.Cluster] == nil {
			seen[workload.Cluster] = map[awsClusterKey]bool{}
		}
		seen[workload.Cluster][key] = true
	}
	locations = map[string]awsClusterKey{}
	ambiguous = map[string]bool{}
	for cluster, keys := range seen {
		if len(keys) > 1 {
			ambiguous[cluster] = true
			continue
		}
		for key := range keys {
			locations[cluster] = key
		}
	}
	return locations, ambiguous
}

// awsConsumerRegionForCluster returns the cluster location reported by the
// consumer Workload(s) whose Cluster matches cluster: EKS reads
// (DescribeCluster, Pod Identity association lookups) are regional, and this
// is the only source of truth for which region a given cluster lives in. It
// never falls back to an unrelated consumer's region or the reader-wide
// default. ambiguous is true when consumers disagree on this cluster name's
// account/region, in which case region is always "" and must not be queried.
func awsConsumerRegionForCluster(consumers []ci.Workload, cluster string) (region string, ambiguous bool) {
	locations, ambiguousClusters := awsConsumerClusterLocations(consumers)
	if ambiguousClusters[cluster] {
		return "", true
	}
	return locations[cluster].Region, false
}

// awsReference builds a live-observation Reference: API identifies the exact
// read operation, Scope the account/ARN/cluster it was scoped to, ObservedAt
// the retrieval time, and Digest a stable hash of the retrieved content.
func awsReference(api, scope string, observedAt time.Time, digest string) ci.Reference {
	return ci.Reference{API: api, Scope: scope, ObservedAt: observedAt, Digest: digest}
}

// awsDecodePolicyDocument URL-decodes an IAM policy document as returned by
// GetRolePolicy/GetUserPolicy/GetGroupPolicy/GetPolicyVersion/
// AssumeRolePolicyDocument. IAM policy documents are RFC 3986 percent-encoded
// JSON; a document that is already valid JSON (no percent escapes) is
// returned unchanged.
func awsDecodePolicyDocument(raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("cloudidentitysource: empty policy document")
	}
	if !strings.Contains(raw, "%") {
		return []byte(raw), nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, fmt.Errorf("decode policy document: %w", err)
	}
	return []byte(decoded), nil
}

func awsGap(code, scope, message string, refs ...ci.Reference) ci.Gap {
	return ci.Gap{Code: code, Scope: scope, Message: message, References: refs}
}

// awsDependentPermissionsIncompleteGapCode marks a service whose published
// Operations[].AuthorizedActions JSON has two confirmed, permanent gaps
// verified directly against the live feed (not merely the docs) — it
// excludes permissions required via Forward Access Sessions, and it
// excludes resource/configuration-triggered dependent actions (for example,
// s3:PutObject with server-side encryption requires kms:GenerateDataKey/
// kms:Decrypt, which does not appear anywhere in s3.json's PutObject
// AuthorizedActions). This no longer flips Definitions.Complete: the
// authoritative per-operation signal is
// OperationDefinition.DependenciesComplete, which stays false for every
// live-fed operation except the hand-curated profiles in
// aws_definitions_curated.go that were verified against their own primary
// API reference "Permissions" section.
const awsDependentPermissionsIncompleteGapCode = "aws_dependent_permissions_incomplete"
