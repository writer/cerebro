package cloudidentitysource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// awsServiceReferenceSourceID tags every request made to the official AWS
// Service Reference endpoint for sourcehttp's safety machinery.
const awsServiceReferenceSourceID = "cloud_identity_aws_servicereference"

// awsDefaultServiceReferenceBaseURL is the fixed public host allowlisted for
// SAR fetches; production callers must never override it.
const awsDefaultServiceReferenceBaseURL = "https://servicereference.us-east-1.amazonaws.com"

// awsServiceReferenceIndexPath is the bare root path. Per the published
// AWS Service Authorization Reference docs
// (https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html),
// GET "/" returns the full list of services and their per-service document
// URLs. (NOTE: "/v1/mapping.json" is a *different*, SDK-language-keyed
// document — {"SDK":{"Python":{"Boto3":{"<botocore-name>":{"service","url"}}}}}
// — not the simple index; this reader does not need it, since the per-
// service "Operations[].SDK[]" entries already carry SDK method aliases.)
const awsServiceReferenceIndexPath = "/"

// awsServiceReferenceMappingEntry is one row of the official SAR index
// returned from the bare root path.
type awsServiceReferenceMappingEntry struct {
	Service string `json:"service"`
	URL     string `json:"url"`
}

// awsServiceReferenceAction is one Action entry inside a per-service SAR
// document. Only the fields this reader consumes are declared; unknown
// fields are ignored by json.Unmarshal.
type awsServiceReferenceAction struct {
	Name      string `json:"Name"`
	Resources []struct {
		Name string `json:"Name"`
	} `json:"Resources"`
}

// awsServiceReferenceAuthorizedAction is one permission authorized by a
// published Operation. A non-empty Context means the permission only
// applies under that documented condition (e.g. iam:PassRole scoped by
// iam:PassedToService); this reader keeps such entries out of the
// unconditional Permissions list rather than treating them as always
// required.
type awsServiceReferenceAuthorizedAction struct {
	Name    string              `json:"Name"`
	Service string              `json:"Service"`
	Context map[string][]string `json:"Context,omitempty"`
}

type awsServiceReferenceSDKMethod struct {
	Name    string `json:"Name"`
	Method  string `json:"Method"`
	Package string `json:"Package"`
}

// awsServiceReferenceOperation is one entry of a per-service document's
// "Operations" array: the real API-operation-to-authorized-actions mapping,
// including dependent/cross-service permissions (e.g. an EKS operation
// requiring iam:PassRole) and per-language SDK method aliases. Per AWS's own
// documentation this mapping is not published for every service; a service
// document with Actions but no Operations entries is a genuine, scoped gap,
// never silently treated as "no dependent permissions".
type awsServiceReferenceOperation struct {
	Name              string                                `json:"Name"`
	AuthorizedActions []awsServiceReferenceAuthorizedAction `json:"AuthorizedActions"`
	SDK               []awsServiceReferenceSDKMethod        `json:"SDK"`
}

type awsServiceReferenceDocument struct {
	Name       string                         `json:"Name"`
	Actions    []awsServiceReferenceAction    `json:"Actions"`
	Operations []awsServiceReferenceOperation `json:"Operations"`
}

func (r *awsReader) serviceReferenceBaseURL() string {
	if r.options.ServiceReferenceBaseURL != "" {
		return r.options.ServiceReferenceBaseURL
	}
	return awsDefaultServiceReferenceBaseURL
}

// awsServiceReferencePathAllowed refuses any path outside the two documented,
// read-only SAR endpoints: the root index and one service document. This is
// the explicit non-read-API refusal boundary for the HTTP leg of this
// adapter; every call this reader issues is a GET against one of these two
// shapes.
func awsServiceReferencePathAllowed(path string) bool {
	if path == awsServiceReferenceIndexPath {
		return true
	}
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	trimmed := strings.TrimPrefix(path, "/v1/")
	segments := strings.Split(trimmed, "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return false
	}
	return segments[1] == segments[0]+".json"
}

// fetchJSON issues one bounded, retried GET against the SAR host and decodes
// the JSON body. Every call here is a GET to an allowlisted path; no other
// HTTP method is ever constructed by this reader.
func (r *awsReader) fetchServiceReferenceJSON(ctx context.Context, path string, out any) (string, error) {
	if !awsServiceReferencePathAllowed(path) {
		return "", fmt.Errorf("cloudidentitysource: refused non-allowlisted service reference path %q", path)
	}
	if r.options.HTTPClient == nil {
		return "", fmt.Errorf("cloudidentitysource: aws reader requires an HTTPClient for service reference fetches")
	}
	if err := r.budget.take(); err != nil {
		return "", err
	}
	base := r.serviceReferenceBaseURL()
	req, err := sourcehttp.NewRequest(ctx, awsServiceReferenceSourceID, base, false, "GET", path, url.Values{}, nil)
	if err != nil {
		return "", fmt.Errorf("build service reference request %s: %w", path, err)
	}
	body, err := sourcehttp.DoWithRetry(ctx, r.options.HTTPClient, req, sourcehttp.RetryOptions{MaxBodyBytes: sourcehttp.MaxBodyBytes})
	if err != nil {
		return "", fmt.Errorf("fetch service reference %s: %w", path, err)
	}
	if body.StatusCode < 200 || body.StatusCode >= 300 {
		return "", &sourcecdk.HTTPStatusError{Code: body.StatusCode, Message: fmt.Sprintf("service reference %s returned status %d", path, body.StatusCode)}
	}
	if err := json.Unmarshal(body.Body, out); err != nil {
		return "", fmt.Errorf("decode service reference %s: %w", path, err)
	}
	return ci.Digest(string(body.Body)), nil
}

// serviceReferenceIndex lazily fetches and caches the SAR root index for the
// lifetime of this reader.
func (r *awsReader) serviceReferenceIndex(ctx context.Context) (map[string]string, error) {
	r.sarMu.Lock()
	if r.sarIndex != nil || r.sarIndexErr != nil {
		index, err := r.sarIndex, r.sarIndexErr
		r.sarMu.Unlock()
		return index, err
	}
	r.sarMu.Unlock()

	var mapping []awsServiceReferenceMappingEntry
	if _, err := r.fetchServiceReferenceJSON(ctx, awsServiceReferenceIndexPath, &mapping); err != nil {
		r.sarMu.Lock()
		r.sarIndexErr = err
		r.sarMu.Unlock()
		return nil, err
	}
	index := make(map[string]string, len(mapping))
	for _, entry := range mapping {
		if entry.Service != "" && entry.URL != "" {
			index[entry.Service] = entry.URL
		}
	}
	r.sarMu.Lock()
	r.sarIndex = index
	r.sarMu.Unlock()
	return index, nil
}

// serviceDefinitions fetches (or reuses this run's cached) action/operation
// definitions for one AWS IAM service prefix (e.g. "s3", "eks").
func (r *awsReader) serviceDefinitions(ctx context.Context, service string, now time.Time) ([]ci.ActionDefinition, []ci.OperationDefinition, []ci.Gap, error) {
	r.sarMu.Lock()
	if cached, ok := r.sarFetched[service]; ok {
		r.sarMu.Unlock()
		return cached.actions, cached.operations, cached.gaps, cached.err
	}
	r.sarMu.Unlock()

	index, err := r.serviceReferenceIndex(ctx)
	if err != nil {
		r.storeServiceDefinitions(service, nil, nil, nil, ci.Reference{}, err)
		return nil, nil, nil, err
	}
	serviceURL, ok := index[service]
	if !ok {
		err := fmt.Errorf("service %q is not present in the AWS service reference index", service)
		r.storeServiceDefinitions(service, nil, nil, nil, ci.Reference{}, err)
		return nil, nil, nil, err
	}
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		err = fmt.Errorf("parse service reference url for %s: %w", service, err)
		r.storeServiceDefinitions(service, nil, nil, nil, ci.Reference{}, err)
		return nil, nil, nil, err
	}
	// The index points back at the same documented host; re-validate it is
	// still a /v1/<service>/<service>.json path rather than trusting the
	// remote index's URL field outright.
	if !strings.EqualFold("https://"+parsed.Host, r.serviceReferenceBaseURL()) || !awsServiceReferencePathAllowed(parsed.Path) {
		err := fmt.Errorf("cloudidentitysource: refused service reference url %q outside the allowlisted host/path", serviceURL)
		r.storeServiceDefinitions(service, nil, nil, nil, ci.Reference{}, err)
		return nil, nil, nil, err
	}

	var document awsServiceReferenceDocument
	digest, err := r.fetchServiceReferenceJSON(ctx, parsed.Path, &document)
	if err != nil {
		r.storeServiceDefinitions(service, nil, nil, nil, ci.Reference{}, err)
		return nil, nil, nil, err
	}
	reference := ci.Reference{API: serviceURL, Scope: service, ObservedAt: now, Digest: digest}

	actions := make([]ci.ActionDefinition, 0, len(document.Actions))
	for _, action := range document.Actions {
		if action.Name == "" {
			continue
		}
		resourceTypes := make([]string, 0, len(action.Resources))
		for _, resource := range action.Resources {
			if resource.Name != "" {
				resourceTypes = append(resourceTypes, resource.Name)
			}
		}
		actions = append(actions, ci.ActionDefinition{Name: service + ":" + action.Name, ResourceTypes: resourceTypes, References: []ci.Reference{reference}})
	}

	// The real API-operation-to-authorized-action mapping (including
	// cross-service dependent permissions, e.g. an EKS operation requiring
	// iam:PassRole) lives in Operations[].AuthorizedActions, not in Actions.
	// AWS does not publish this mapping for every service; a document with
	// Actions but no Operations is a genuine, scoped coverage gap rather than
	// a fabricated 1:1 action<->operation assumption.
	var gaps []ci.Gap
	operations := make([]ci.OperationDefinition, 0, len(document.Operations))
	for _, op := range document.Operations {
		if op.Name == "" {
			continue
		}
		opScope := service + ":" + op.Name
		if len(op.AuthorizedActions) == 0 {
			// AWS published this operation but attached no authorized-action
			// data to it. That is an unresolved dependency set, never "this
			// operation requires nothing": the resulting Permissions stay
			// empty, but the gap keeps that absence from being read as a
			// confirmed zero-permission fact.
			gaps = append(gaps, awsGap("aws_operation_authorized_actions_unknown", opScope, "AWS published this operation with no authorized-action data; its required permissions are unknown, not confirmed absent", reference))
		}
		var permissions, conditional []string
		seenPermission := map[string]bool{}
		seenConditional := map[string]bool{}
		for _, authorized := range op.AuthorizedActions {
			if authorized.Name == "" || authorized.Service == "" {
				continue
			}
			permission := authorized.Service + ":" + authorized.Name
			if len(authorized.Context) > 0 {
				if !seenConditional[permission] {
					conditional = append(conditional, permission)
					seenConditional[permission] = true
				}
				continue
			}
			if !seenPermission[permission] {
				permissions = append(permissions, permission)
				seenPermission[permission] = true
			}
		}
		sdkMethods := []string{op.Name}
		seenMethod := map[string]bool{op.Name: true}
		// SDKServices collects every distinct SDK/service namespace denoting
		// this same operation (the document's own prefix plus each SDK[].Name
		// the feed reports, e.g. a Bedrock operation reachable through both
		// "bedrock" and "bedrockruntime"); entries are not positional with
		// SDKMethods.
		sdkServices := []string{service}
		seenService := map[string]bool{service: true}
		for _, sdk := range op.SDK {
			if sdk.Method != "" && !seenMethod[sdk.Method] {
				sdkMethods = append(sdkMethods, sdk.Method)
				seenMethod[sdk.Method] = true
			}
			if sdk.Name != "" && !seenService[sdk.Name] {
				sdkServices = append(sdkServices, sdk.Name)
				seenService[sdk.Name] = true
			}
		}
		built := ci.OperationDefinition{
			Provider:               ci.AWS,
			Service:                service,
			Operation:              op.Name,
			SDKMethods:             sdkMethods,
			SDKServices:            sdkServices,
			Permissions:            permissions,
			ConditionalPermissions: conditional,
			DependenciesComplete:   false,
			References:             []ci.Reference{reference},
		}
		curated, curatedGaps := awsApplyCuratedOperationProfile(built, now)
		operations = append(operations, curated)
		gaps = append(gaps, curatedGaps...)
	}

	if len(document.Operations) == 0 && len(document.Actions) > 0 {
		gaps = append(gaps, awsGap("aws_operation_mapping_unsupported", service, "AWS has not published an operation-to-authorized-action mapping for this service; action definitions are complete but per-operation dependent-permission data is unavailable", reference))
	} else if len(document.Operations) > 0 {
		// Verified directly against the live feed: AuthorizedActions excludes
		// (a) permissions required when an operation is invoked on the
		// caller's behalf via Forward Access Sessions, and (b) resource/
		// configuration-triggered dependent actions not expressed as a
		// distinct API call (e.g. s3:PutObject with server-side encryption
		// also requires kms:GenerateDataKey/kms:Decrypt, which does not
		// appear in s3.json's PutObject entry at all). This is informational:
		// OperationDefinition.DependenciesComplete (false by default, true
		// only for the hand-curated profiles in aws_definitions_curated.go)
		// is the field a validator checks before trusting an operation's
		// Permissions/ConditionalPermissions as a removal basis.
		gaps = append(gaps, awsGap(awsDependentPermissionsIncompleteGapCode, service, "AWS Service Reference authorized-action data excludes Forward-Access-Session permissions and resource/configuration-triggered dependent actions (e.g. SSE-KMS) for operations without a hand-curated profile; see OperationDefinition.DependenciesComplete", reference))
	}
	r.storeServiceDefinitions(service, actions, operations, gaps, reference, nil)
	return actions, operations, gaps, nil
}

func (r *awsReader) storeServiceDefinitions(service string, actions []ci.ActionDefinition, operations []ci.OperationDefinition, gaps []ci.Gap, reference ci.Reference, err error) {
	r.sarMu.Lock()
	defer r.sarMu.Unlock()
	r.sarFetched[service] = awsCachedDefinitions{actions: actions, operations: operations, gaps: gaps, reference: reference, err: err}
}
