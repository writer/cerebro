// Package cloudidentitysource holds the typed Source CDK extension adapters for
// the Kubernetes cloud-identity scan. Every exported name here is a provider
// prefix (AWS/GCP/...) to avoid collisions in this shared package; unexported
// helpers in this file are additionally prefixed aws to the same end.
package cloudidentitysource

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	// DefaultAWSSessionName names the assumed-role session when callers do not
	// configure one; it is visible to the target account's CloudTrail.
	DefaultAWSSessionName = "cerebro-cloud-identity-scan"
	// DefaultAWSAssumeRoleDuration bounds how long assumed credentials live
	// before this reader must assume the role again.
	DefaultAWSAssumeRoleDuration = 15 * time.Minute
	// DefaultAWSRequestBudget bounds the number of AWS API and service-reference
	// HTTP calls a single reader instance will issue across its lifetime.
	DefaultAWSRequestBudget = 4000
	// DefaultAWSMaxPages bounds pagination loops per collection so a
	// misbehaving or hostile API cannot force unbounded iteration.
	DefaultAWSMaxPages = 50
)

// AWSOptions configures NewAWSReader. All fields are explicit dependencies;
// nothing is read from the environment or ambient credentials beyond what the
// injected aws.Config already carries.
type AWSOptions struct {
	// Config is the base/management aws.Config used to call sts:AssumeRole
	// into each referenced member account. Its Region is used for assumed
	// clients unless Region is set below.
	Config aws.Config
	// RoleName is the IAM role name assumed in every referenced account (for
	// example "cerebro-org-scan-role"); it is combined with each principal's
	// account id to form the role ARN. Required.
	RoleName string
	// Region overrides the region used to construct assumed-role IAM/EKS
	// clients; defaults to Config.Region.
	Region string
	// SessionName overrides the assumed-role session name.
	SessionName string
	// ExternalID is passed as the STS ExternalId parameter when set.
	ExternalID string
	// AssumeRoleDuration overrides DefaultAWSAssumeRoleDuration.
	AssumeRoleDuration time.Duration
	// RequestBudget overrides DefaultAWSRequestBudget.
	RequestBudget int
	// MaxPages overrides DefaultAWSMaxPages.
	MaxPages int
	// HTTPClient is the bounded, host-allowlisted client used only for the
	// public AWS Service Reference (SAR) fetches; reuse a client built with
	// internal/sourcehttp (NewClient/HardenClient). Optional: when nil,
	// NewAWSReader builds its own bounded sourcehttp client.
	HTTPClient *http.Client
	// ServiceReferenceBaseURL overrides the official AWS Service Reference
	// host, for tests only; production callers must leave this empty so the
	// fixed public host allowlist applies.
	ServiceReferenceBaseURL string
	// Clock overrides time.Now for deterministic tests.
	Clock func() time.Time

	// STSClientFactory builds the narrow STS port from an aws.Config; it
	// defaults to a real sts.Client. Tests inject a fake directly.
	STSClientFactory func(aws.Config) awsSTSAssumeRoleAPI
	// IAMClientFactory builds the narrow IAM port from an assumed aws.Config;
	// it defaults to a real iam.Client.
	IAMClientFactory func(aws.Config) awsIAMReadAPI
	// EKSClientFactory builds the narrow EKS port from an assumed aws.Config;
	// it defaults to a real eks.Client.
	EKSClientFactory func(aws.Config) awsEKSReadAPI
}

// awsReader implements ci.CloudReader for AWS IAM/EKS. One instance is meant
// to live for a single collection run; it caches assumed-role configs and
// fetched definitions for that run only.
type awsReader struct {
	options  AWSOptions
	clock    func() time.Time
	budget   *awsRequestBudget
	maxPages int

	assume     *awsAssumeCache
	serviceRef *awsServiceReferenceCache
	policies   *awsPolicyCache
	roles      *awsRoleCache
}

// awsAssumeCache memoizes one member account's assumed-role aws.Config for
// the lifetime of a reader (one collection run).
type awsAssumeCache struct {
	mu      sync.Mutex
	assumed map[string]awsAssumedConfig
}

func newAWSAssumeCache() *awsAssumeCache {
	return &awsAssumeCache{assumed: make(map[string]awsAssumedConfig)}
}

func (c *awsAssumeCache) get(account string) (awsAssumedConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.assumed[account]
	return cached, ok
}

func (c *awsAssumeCache) store(account string, cfg awsAssumedConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.assumed[account] = cfg
}

// awsServiceReferenceCache memoizes the AWS Service Reference service
// index and per-service definitions fetched over HTTP, for the lifetime of
// a reader instance.
type awsServiceReferenceCache struct {
	mu          sync.Mutex
	index       map[string]string // service -> service JSON url
	indexErr    error
	definitions map[string]awsCachedDefinitions // service -> definitions
}

func newAWSServiceReferenceCache() *awsServiceReferenceCache {
	return &awsServiceReferenceCache{definitions: make(map[string]awsCachedDefinitions)}
}

func (c *awsServiceReferenceCache) getIndex() (index map[string]string, indexErr error, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index != nil || c.indexErr != nil {
		return c.index, c.indexErr, true
	}
	return nil, nil, false
}

func (c *awsServiceReferenceCache) setIndexErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.indexErr = err
}

func (c *awsServiceReferenceCache) setIndex(index map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index = index
}

func (c *awsServiceReferenceCache) getDefinitions(service string) (awsCachedDefinitions, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.definitions[service]
	return cached, ok
}

func (c *awsServiceReferenceCache) storeDefinitions(service string, def awsCachedDefinitions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.definitions[service] = def
}

// awsPolicyCache memoizes one managed policy's expanded (default version)
// grants, keyed by ARN, for the lifetime of a reader instance.
type awsPolicyCache struct {
	mu    sync.Mutex
	cache map[string]ci.ManagedPolicy
}

func newAWSPolicyCache() *awsPolicyCache {
	return &awsPolicyCache{cache: make(map[string]ci.ManagedPolicy)}
}

func (c *awsPolicyCache) get(arn string) (ci.ManagedPolicy, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.cache[arn]
	return cached, ok
}

func (c *awsPolicyCache) store(arn string, policy ci.ManagedPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[arn] = policy
}

// awsRoleCache memoizes one IAM role's fully-resolved live observation,
// keyed by role ARN, for the lifetime of a reader instance (see
// awsRoleObservation).
type awsRoleCache struct {
	mu    sync.Mutex
	cache map[string]awsRoleObservation
}

func newAWSRoleCache() *awsRoleCache {
	return &awsRoleCache{cache: make(map[string]awsRoleObservation)}
}

func (c *awsRoleCache) get(roleARN string) (awsRoleObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.cache[roleARN]
	return cached, ok
}

func (c *awsRoleCache) store(roleARN string, observation awsRoleObservation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[roleARN] = observation
}

// awsRoleObservation caches one role's fully-resolved live policy state so a
// role observed both directly (aws_iam_role) and via a resolved Pod Identity
// association (aws_kubernetes_service_account) in the same run is fetched
// from AWS exactly once.
type awsRoleObservation struct {
	policy      ci.PolicyState
	definitions ci.Definitions
	err         error
}

type awsCachedDefinitions struct {
	actions    []ci.ActionDefinition
	operations []ci.OperationDefinition
	gaps       []ci.Gap
	reference  ci.Reference
	err        error
}

// NewAWSReader builds a ci.CloudReader backed by live AWS IAM/EKS reads and
// the public AWS Service Reference. It performs no calls until Observe/Define
// are invoked.
func NewAWSReader(ctx context.Context, options AWSOptions) (ci.CloudReader, error) {
	_ = ctx
	if options.RoleName == "" {
		return nil, fmt.Errorf("cloudidentitysource: aws reader requires RoleName")
	}
	if options.Config.Region == "" && options.Region == "" {
		return nil, fmt.Errorf("cloudidentitysource: aws reader requires a region (Config.Region or Region)")
	}
	if options.SessionName == "" {
		options.SessionName = DefaultAWSSessionName
	}
	if options.AssumeRoleDuration <= 0 {
		options.AssumeRoleDuration = DefaultAWSAssumeRoleDuration
	}
	if options.RequestBudget <= 0 {
		options.RequestBudget = DefaultAWSRequestBudget
	}
	if options.MaxPages <= 0 {
		options.MaxPages = DefaultAWSMaxPages
	}
	if options.STSClientFactory == nil {
		options.STSClientFactory = func(cfg aws.Config) awsSTSAssumeRoleAPI { return sts.NewFromConfig(cfg) }
	}
	if options.IAMClientFactory == nil {
		options.IAMClientFactory = func(cfg aws.Config) awsIAMReadAPI { return iam.NewFromConfig(cfg) }
	}
	if options.EKSClientFactory == nil {
		options.EKSClientFactory = func(cfg aws.Config) awsEKSReadAPI { return eks.NewFromConfig(cfg) }
	}
	if options.HTTPClient == nil {
		options.HTTPClient = sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: awsServiceReferenceSourceID, Timeout: sourcehttp.DefaultTimeout})
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &awsReader{
		options:    options,
		clock:      clock,
		budget:     &awsRequestBudget{max: options.RequestBudget},
		maxPages:   options.MaxPages,
		assume:     newAWSAssumeCache(),
		serviceRef: newAWSServiceReferenceCache(),
		policies:   newAWSPolicyCache(),
		roles:      newAWSRoleCache(),
	}, nil
}

func (r *awsReader) region() string {
	if r.options.Region != "" {
		return r.options.Region
	}
	return r.options.Config.Region
}
