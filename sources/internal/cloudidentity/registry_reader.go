package cloudidentitysource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	registrySourceID = "cloud_identity_registry"

	defaultRegistryMaxManifestBytes = 4 << 20 // 4 MiB; multi-platform indexes stay well under this.
	defaultRegistryMaxConfigBytes   = 2 << 20 // 2 MiB
	defaultRegistryTimeout          = 30 * time.Second
	ecrTokenRefreshSkew             = 5 * time.Minute
	// maxPlatformManifestsForAgreement bounds how many runnable platform
	// entries of a manifest-list/index are checked for source-label
	// agreement before an exact pin is asserted for the whole image.
	maxPlatformManifestsForAgreement = 10

	ociAcceptHeader = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
)

// ErrUnsupportedRegistryHost is returned when an image reference's registry
// host is neither an Amazon ECR nor a Google Artifact Registry/GCR host. No
// other registry kind is supported; this adapter never substitutes a SaaS
// registry-inspection API.
var ErrUnsupportedRegistryHost = errors.New("registry host is not a supported ECR or Artifact Registry/GCR host")

// ErrGoogleCredentialsNotConfigured is returned when an Artifact
// Registry/GCR image read requires a Google OAuth2 token source and none
// was configured on the reader. This is a required-credential-
// configuration failure, distinct from an unsupported registry host.
var ErrGoogleCredentialsNotConfigured = errors.New("no google token source is configured")

// ErrDigestMismatch indicates a manifest or image reference's content
// hashed to a different digest than was declared, pinned, or requested --
// corrupted transport, a cache-poisoned mirror, or a compromised registry.
// Subject identifies the specific declared-vs-computed relationship
// (requested pin, response header, or digest-addressed reference) for
// diagnostics; callers that only care about the integrity category should
// use errors.As and ignore it.
type ErrDigestMismatch struct {
	Subject  string
	Expected string
	Actual   string
}

func (e *ErrDigestMismatch) Error() string {
	return fmt.Sprintf("cloudidentitysource: %s: digest mismatch: expected %s, got %s", e.Subject, e.Expected, e.Actual)
}

// RegistryOptions configures NewRegistryReader.
type RegistryOptions struct {
	// AWSConfig authenticates ECR control-plane calls (GetAuthorizationToken,
	// and — when AWSRoleName is set — AssumeRole). Required to read images
	// hosted on *.dkr.ecr.*.amazonaws.com.
	AWSConfig aws.Config
	// AWSRoleName optionally names an IAM role (e.g. an org-wide scan role)
	// assumed per ECR account: arn:aws:iam::<account-id>:role/<AWSRoleName>,
	// using AWSConfig's own credentials as the trust anchor. Required to
	// read ECR registries in accounts other than AWSConfig's own account;
	// empty keeps AWSConfig's credentials in direct use for every account.
	AWSRoleName string
	// ECRBaseEndpoint overrides the ECR control-plane endpoint; tests only.
	ECRBaseEndpoint string
	// GoogleTokenSource authenticates Google Artifact Registry/GCR calls.
	// Required to read images hosted on *-docker.pkg.dev or *gcr.io.
	GoogleTokenSource oauth2.TokenSource
	// HTTPClient is the base client the hardened OCI data-plane client
	// wraps. A nil value starts from http.DefaultTransport.
	HTTPClient *http.Client
	// AllowLoopbackBaseURL permits loopback/private registry hosts; tests
	// only.
	AllowLoopbackBaseURL bool
	// LookupIPAddrs overrides DNS resolution for host-safety pinning; tests
	// only.
	LookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)
	// RegistryBaseURL maps a lower-cased registry host (as it appears in an
	// image reference) to an override origin (scheme://host[:port]); tests
	// only. Production always dials https://<host> directly.
	RegistryBaseURL map[string]string
	// MaxManifestBytes bounds a single manifest/index response. Defaults to
	// 4 MiB.
	MaxManifestBytes int
	// MaxConfigBytes bounds the image config blob response. Defaults to 2
	// MiB.
	MaxConfigBytes int
	// Manifest-list/index platform selection is intentionally not a
	// single-value option here: a list/index reference names a whole
	// multi-platform image, and ReadImage checks every runnable platform's
	// own source labels for agreement (resolvePlatformSourceAgreement)
	// instead of trusting one arbitrarily chosen default platform.
	// Timeout bounds every outbound HTTP request. Defaults to 30s.
	Timeout time.Duration
}

type ecrToken struct {
	basic     string
	expiresAt time.Time
}

type registryReader struct {
	awsConfig         aws.Config
	awsRoleName       string
	ecrBaseEndpoint   string
	googleTokenSource oauth2.TokenSource
	httpClient        *http.Client
	allowLoopback     bool
	registryBaseURL   map[string]string
	maxManifestBytes  int
	maxConfigBytes    int

	ecrClients *registryECRClientCache
	ecrTokens  *registryTokenCache

	stsClientOnce  sync.Once
	stsClientValue *sts.Client
}

// registryECRClientCache memoizes per-account/region ECR control-plane
// clients, built once per reader instance. getOrBuild runs the whole
// get-or-build sequence under one lock so concurrent callers for the same
// account/region never race to build (and discard) duplicate clients.
type registryECRClientCache struct {
	mu      sync.Mutex
	clients map[string]*ecr.Client
}

func newRegistryECRClientCache() *registryECRClientCache {
	return &registryECRClientCache{clients: make(map[string]*ecr.Client)}
}

func (c *registryECRClientCache) getOrBuild(key string, build func() *ecr.Client) *ecr.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[key]; ok {
		return client
	}
	client := build()
	c.clients[key] = client
	return client
}

// registryTokenCache memoizes ECR basic-auth tokens per account/region,
// refreshed ecrTokenRefreshSkew before expiry.
type registryTokenCache struct {
	mu     sync.Mutex
	tokens map[string]ecrToken
}

func newRegistryTokenCache() *registryTokenCache {
	return &registryTokenCache{tokens: make(map[string]ecrToken)}
}

func (c *registryTokenCache) get(key string) (ecrToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.tokens[key]
	return cached, ok
}

func (c *registryTokenCache) store(key string, token ecrToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[key] = token
}

// NewRegistryReader builds an ECR/GAR-backed ci.RegistryReader that performs
// real OCI distribution-API manifest and config reads.
func NewRegistryReader(options RegistryOptions) (ci.RegistryReader, error) {
	maxManifestBytes := options.MaxManifestBytes
	if maxManifestBytes <= 0 {
		maxManifestBytes = defaultRegistryMaxManifestBytes
	}
	maxConfigBytes := options.MaxConfigBytes
	if maxConfigBytes <= 0 {
		maxConfigBytes = defaultRegistryMaxConfigBytes
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultRegistryTimeout
	}

	registryBaseURL := make(map[string]string, len(options.RegistryBaseURL))
	for host, override := range options.RegistryBaseURL {
		host = strings.ToLower(strings.TrimSpace(host))
		override = strings.TrimSpace(override)
		if host == "" || override == "" {
			continue
		}
		registryBaseURL[host] = strings.TrimRight(override, "/")
	}

	hardened := sourcehttp.HardenSourceClient(options.HTTPClient, registrySourceID, timeout, options.AllowLoopbackBaseURL, options.LookupIPAddrs)

	return &registryReader{
		awsConfig:         options.AWSConfig,
		awsRoleName:       strings.TrimSpace(options.AWSRoleName),
		ecrBaseEndpoint:   strings.TrimSpace(options.ECRBaseEndpoint),
		googleTokenSource: options.GoogleTokenSource,
		httpClient:        hardened,
		allowLoopback:     options.AllowLoopbackBaseURL,
		registryBaseURL:   registryBaseURL,
		maxManifestBytes:  maxManifestBytes,
		maxConfigBytes:    maxConfigBytes,
		ecrClients:        newRegistryECRClientCache(),
		ecrTokens:         newRegistryTokenCache(),
	}, nil
}

// ReadImage resolves image to a verified OCI manifest digest and, when the
// config blob and its standard OCI labels are available, an attributed
// source pin. A caller-supplied "@sha256:" digest is treated as the exact
// pin and verified; a tag-only reference is read and reported but never
// promoted to an exact pin by this adapter.
func (r *registryReader) ReadImage(ctx context.Context, image string) (ci.ImageProvenance, error) {
	parsed, err := parseImageReference(image)
	if err != nil {
		return ci.ImageProvenance{}, fmt.Errorf("cloudidentitysource: %w", err)
	}
	provider, accountID, region, ok := detectRegistryProvider(parsed.host)
	if !ok {
		return ci.ImageProvenance{}, fmt.Errorf("cloudidentitysource: image %q: registry host %q: %w", image, parsed.host, ErrUnsupportedRegistryHost)
	}
	authHeader, err := r.authorizationHeader(ctx, provider, accountID, region, parsed.host)
	if err != nil {
		return ci.ImageProvenance{}, err
	}

	base := r.baseURLFor(parsed.host)
	reference := parsed.tag
	if parsed.digest != "" {
		reference = parsed.digest
	}

	manifestBytes, manifestDigest, manifestContentType, err := r.fetchManifest(ctx, base, parsed.host, parsed.repository, reference, authHeader)
	if err != nil {
		return ci.ImageProvenance{}, fmt.Errorf("cloudidentitysource: image %q: %w", image, err)
	}

	if parsed.digest != "" && !strings.EqualFold(manifestDigest, parsed.digest) {
		return ci.ImageProvenance{}, &ErrDigestMismatch{Subject: fmt.Sprintf("image %q pinned digest", image), Expected: parsed.digest, Actual: manifestDigest}
	}

	provenance := ci.ImageProvenance{Image: image, Digest: manifestDigest, DeploymentPinned: parsed.digest != ""}

	if parsed.digest == "" {
		// A tag-only reference is never promoted to DeploymentPinned: a
		// scan-time tag->digest resolution (manifestDigest above) says
		// nothing about which digest the tag named when the workload was
		// actually deployed, and current registry tag-immutability
		// settings cannot retroactively prove that either. Provenance for
		// a tag-only reference stays incomplete rather than pinned.
		provenance.Gaps = append(provenance.Gaps, ci.Gap{
			Code: "registry.tag_not_pinned", Scope: "registry",
			Message: fmt.Sprintf("image %s was resolved from a mutable tag reference; the deployed digest is not independently verified as pinned", image),
		})
	}

	if isManifestList(manifestContentType, manifestBytes) {
		// A manifest-list/index reference names the whole multi-platform
		// image, not any single variant — Digest above is already the
		// index's own digest (what was actually requested/pinned) and must
		// never be replaced by a child manifest's digest. Without an
		// independently known deployment platform, asserting an exact
		// source pin from one arbitrarily selected (or default linux/amd64)
		// child would risk certifying the wrong source, so every runnable
		// platform's own source labels must agree before Exact is set.
		pin, gaps, references := r.resolvePlatformSourceAgreement(ctx, base, parsed.host, parsed.repository, manifestBytes, authHeader)
		provenance.Source = pin
		provenance.Gaps = append(provenance.Gaps, gaps...)
		provenance.References = append([]ci.Reference{{API: "oci.manifest", Digest: manifestDigest}}, references...)
		return provenance, nil
	}

	// Direct single-manifest reference — including a workload's own pinned
	// per-platform digest, which is what a real container runtime records
	// as imageID — unambiguously names one image, so its own config labels
	// decide exactness directly.
	configDescriptor, err := manifestConfigDescriptor(manifestBytes)
	if err != nil {
		provenance.Gaps = append(provenance.Gaps, ci.Gap{
			Code: "registry.manifest_unsupported", Scope: "registry",
			Message: fmt.Sprintf("manifest for %s could not be parsed for a config descriptor: %v", image, err),
		})
		return provenance, nil
	}
	configDigest := configDescriptor.Digest

	configBytes, err := r.fetchBlob(ctx, base, parsed.host, parsed.repository, configDigest, authHeader, r.maxConfigBytes)
	if err != nil {
		// Partial retrieval: the manifest digest is already verified and
		// returned; a config-blob failure degrades to a gap rather than
		// discarding the verified evidence already collected.
		provenance.Gaps = append(provenance.Gaps, ci.Gap{
			Code: "registry.config_unavailable", Scope: "registry",
			Message: fmt.Sprintf("image config blob %s for %s could not be read: %v", configDigest, image, err),
		})
		return provenance, nil
	}
	if !verifyBlobDigest(configBytes, configDigest) {
		return ci.ImageProvenance{}, fmt.Errorf("cloudidentitysource: image %q: config blob %s failed digest verification", image, configDigest)
	}

	labels, err := parseImageConfigLabels(configBytes)
	if err != nil {
		provenance.Gaps = append(provenance.Gaps, ci.Gap{
			Code: "registry.config_unavailable", Scope: "registry",
			Message: fmt.Sprintf("image config for %s could not be decoded: %v", image, err),
		})
		return provenance, nil
	}

	pin, gaps := sourcePinFromLabels(labels)
	provenance.Source = pin
	provenance.Gaps = append(provenance.Gaps, gaps...)
	provenance.References = []ci.Reference{
		{API: "oci.manifest", Digest: manifestDigest},
		{API: "oci.config", Digest: configDigest},
	}
	return provenance, nil
}

// registryPlatformOutcome is one runnable platform's config-label read
// result inside a manifest-list/index.
type registryPlatformOutcome struct {
	platform string
	pin      ci.SourcePin
	ok       bool
}

// resolvePlatformSourceAgreement checks every potentially runnable entry in
// a manifest index/list (bounded to maxPlatformManifestsForAgreement) and
// only returns an exact source pin when all of them were read successfully
// and agree on the same repository/revision/exactness. An entry is only
// excluded as non-runnable when it carries positive evidence of that: an
// explicit unknown/unknown build-attestation platform, a non-empty
// artifactType, a Docker buildx-style attestation-manifest reference
// annotation, or (once its own manifest is read) a non-image config media
// type. An entry with no platform object at all is NOT assumed to be an
// attestation/signature — it is fetched and classified like any other
// entry; one that cannot be read or classified counts as disagreement
// rather than being silently dropped.
func (r *registryReader) resolvePlatformSourceAgreement(ctx context.Context, base, host, repository string, indexBytes []byte, authHeader string) (ci.SourcePin, []ci.Gap, []ci.Reference) {
	var index ociIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return ci.SourcePin{}, []ci.Gap{{
			Code: "registry.manifest_unsupported", Scope: "registry",
			Message: fmt.Sprintf("manifest index could not be parsed: %v", err),
		}}, nil
	}

	var runnable []ociDescriptor
	for _, m := range index.Manifests {
		if indexDescriptorExcludedByEvidence(m) {
			continue
		}
		runnable = append(runnable, m)
	}
	if len(runnable) == 0 {
		return ci.SourcePin{}, []ci.Gap{{
			Code: "registry.manifest_unsupported", Scope: "registry",
			Message: "manifest index has no runnable platform entries",
		}}, nil
	}

	bounded := runnable
	truncated := false
	if len(bounded) > maxPlatformManifestsForAgreement {
		bounded = bounded[:maxPlatformManifestsForAgreement]
		truncated = true
	}

	outcomes := make([]registryPlatformOutcome, 0, len(bounded))
	var references []ci.Reference
	var gaps []ci.Gap

	for _, descriptor := range bounded {
		platformLabel := descriptorRunnableLabel(descriptor)
		childBytes, childDigest, _, err := r.fetchManifest(ctx, base, host, repository, descriptor.Digest, authHeader)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "registry.config_unavailable", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s could not be read: %v", platformLabel, err)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		references = append(references, ci.Reference{API: "oci.manifest.platform", Scope: platformLabel, Digest: childDigest})

		configDescriptor, err := manifestConfigDescriptor(childBytes)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "registry.manifest_unsupported", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s has no config descriptor: %v", platformLabel, err)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		if configDescriptor.MediaType == "" {
			// No media type to classify this entry by: it cannot be
			// confirmed runnable nor excluded as a non-image artifact, so
			// it counts as a read failure rather than being silently
			// dropped.
			gaps = append(gaps, ci.Gap{Code: "registry.manifest_unsupported", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s config has no media type; it could not be classified as a runnable image", platformLabel)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		if !isImageConfigMediaType(configDescriptor.MediaType) {
			// Positive non-runnable evidence: the config is not an
			// OCI/Docker image config (e.g. an attestation, SBOM, or
			// signature artifact attached to the index) -- excluded
			// rather than counted toward or against source agreement.
			continue
		}
		configDigest := configDescriptor.Digest

		configBytes, err := r.fetchBlob(ctx, base, host, repository, configDigest, authHeader, r.maxConfigBytes)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "registry.config_unavailable", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s config blob could not be read: %v", platformLabel, err)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		if !verifyBlobDigest(configBytes, configDigest) {
			gaps = append(gaps, ci.Gap{Code: "registry.config_unavailable", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s config blob failed digest verification", platformLabel)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		references = append(references, ci.Reference{API: "oci.config.platform", Scope: platformLabel, Digest: configDigest})

		labels, err := parseImageConfigLabels(configBytes)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "registry.config_unavailable", Scope: platformLabel, Message: fmt.Sprintf("manifest entry %s config could not be decoded: %v", platformLabel, err)})
			outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel})
			continue
		}
		platformPin, pinGaps := sourcePinFromLabels(labels)
		for _, gap := range pinGaps {
			gap.Scope = platformLabel
			gaps = append(gaps, gap)
		}
		outcomes = append(outcomes, registryPlatformOutcome{platform: platformLabel, pin: platformPin, ok: true})
	}

	if truncated {
		gaps = append(gaps, ci.Gap{
			Code: "registry.platform_manifests_truncated", Scope: "registry",
			Message: fmt.Sprintf("manifest index has more than %d runnable platform entries; only the first %d were checked for source agreement", maxPlatformManifestsForAgreement, maxPlatformManifestsForAgreement),
		})
	}

	agreedPin, agreed, details := aggregatePlatformSourcePins(outcomes)
	if !agreed {
		gaps = append(gaps, ci.Gap{
			Code: "registry.source_revision_platform_mismatch", Scope: "registry",
			Message: fmt.Sprintf("runnable platform manifests do not agree on a single source revision (%s); no deployment platform was independently established, so no exact source pin is asserted", details),
		})
		agreedPin.Exact = false
	}
	if truncated {
		// Entries past the bound were never checked for agreement, so even
		// a full agreement among the checked subset cannot certify the
		// whole multi-platform image as an exact pin.
		agreedPin.Exact = false
	}
	return agreedPin, gaps, references
}

// aggregatePlatformSourcePins reports the single source pin every
// successfully-read platform in outcomes agrees on. An unreadable platform,
// a missing source label, or any repository/revision/exactness mismatch
// counts as non-agreement: partial or conflicting evidence is never
// silently promoted to a proven exact pin.
func aggregatePlatformSourcePins(outcomes []registryPlatformOutcome) (ci.SourcePin, bool, string) {
	details := make([]string, 0, len(outcomes))
	var agreedPin ci.SourcePin
	first := true
	agreed := true
	for _, outcome := range outcomes {
		if !outcome.ok {
			details = append(details, outcome.platform+": unreadable")
			agreed = false
			continue
		}
		details = append(details, fmt.Sprintf("%s: %s@%s", outcome.platform, outcome.pin.Repository, outcome.pin.Revision))
		if outcome.pin.Repository == "" {
			agreed = false
			continue
		}
		if first {
			agreedPin = outcome.pin
			first = false
			continue
		}
		if outcome.pin.Repository != agreedPin.Repository || outcome.pin.Revision != agreedPin.Revision || outcome.pin.Exact != agreedPin.Exact {
			agreed = false
		}
	}
	if first {
		agreed = false
	}
	return agreedPin, agreed, strings.Join(details, "; ")
}

func (r *registryReader) baseURLFor(host string) string {
	if override, ok := r.registryBaseURL[strings.ToLower(host)]; ok {
		return override
	}
	return "https://" + host
}

func (r *registryReader) authorizationHeader(ctx context.Context, provider ci.Provider, accountID, region, host string) (string, error) {
	switch provider {
	case ci.AWS:
		token, err := r.ecrAuthToken(ctx, accountID, region)
		if err != nil {
			return "", fmt.Errorf("cloudidentitysource: ecr authorization for %s: %w", host, err)
		}
		return "Basic " + token, nil
	case ci.GCP:
		if r.googleTokenSource == nil {
			return "", fmt.Errorf("cloudidentitysource: read %s: %w", host, ErrGoogleCredentialsNotConfigured)
		}
		token, err := r.googleTokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("cloudidentitysource: fetch google access token for %s: %w", host, err)
		}
		basic := base64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:" + token.AccessToken))
		return "Basic " + basic, nil
	default:
		return "", fmt.Errorf("cloudidentitysource: unsupported registry provider for %s", host)
	}
}

func (r *registryReader) ecrAuthToken(ctx context.Context, accountID, region string) (string, error) {
	cacheKey := accountID + "/" + region
	if cached, ok := r.ecrTokens.get(cacheKey); ok && time.Until(cached.expiresAt) > ecrTokenRefreshSkew {
		return cached.basic, nil
	}

	client := r.ecrClient(accountID, region)
	output, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", err
	}
	if len(output.AuthorizationData) == 0 || output.AuthorizationData[0].AuthorizationToken == nil {
		return "", fmt.Errorf("ecr returned no authorization data for account %s region %s", accountID, region)
	}
	data := output.AuthorizationData[0]
	token := strings.TrimSpace(*data.AuthorizationToken)
	if token == "" {
		return "", fmt.Errorf("ecr returned an empty authorization token for account %s region %s", accountID, region)
	}
	expiresAt := time.Now().Add(time.Hour)
	if data.ExpiresAt != nil {
		expiresAt = *data.ExpiresAt
	}

	r.ecrTokens.store(cacheKey, ecrToken{basic: token, expiresAt: expiresAt})
	return token, nil
}

// ecrClient returns a cached ECR control-plane client for accountID/region.
// When AWSRoleName is configured, each target account gets its own client
// built from credentials assumed into arn:aws:iam::<accountID>:role/<AWSRoleName>
// (via the base AWSConfig's own STS client), so a single injected base
// principal with sts:AssumeRole into each org member account's scan role
// can read ECR registries that live in other accounts. An empty AWSRoleName
// always uses the base AWSConfig's own credentials directly, unchanged from
// single-account behavior.
func (r *registryReader) ecrClient(accountID, region string) *ecr.Client {
	cacheKey := accountID + "/" + region
	return r.ecrClients.getOrBuild(cacheKey, func() *ecr.Client {
		cfg := r.awsConfig
		if r.awsRoleName != "" && accountID != "" {
			roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, r.awsRoleName)
			provider := stscreds.NewAssumeRoleProvider(r.stsClient(), roleARN)
			cfg.Credentials = aws.NewCredentialsCache(provider)
		}
		endpoint := r.ecrBaseEndpoint
		return ecr.NewFromConfig(cfg, func(o *ecr.Options) {
			o.Region = region
			if endpoint != "" {
				o.BaseEndpoint = &endpoint
			}
		})
	})
}

// stsClient lazily builds the single STS client used to assume each target
// account's scan role; it is built from the unmodified base AWSConfig
// (never from an already-assumed-role config) and reused across accounts.
func (r *registryReader) stsClient() *sts.Client {
	r.stsClientOnce.Do(func() {
		r.stsClientValue = sts.NewFromConfig(r.awsConfig)
	})
	return r.stsClientValue
}

func (r *registryReader) fetchManifest(ctx context.Context, base, host, repository, reference, authHeader string) (body []byte, digest string, contentType string, err error) {
	requestPath := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	req, err := sourcehttp.NewRequest(ctx, registrySourceID, base, r.allowLoopback, http.MethodGet, requestPath, nil, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("build manifest request for %s/%s:%s: %w", host, repository, reference, err)
	}
	req.Header.Set("Accept", ociAcceptHeader)
	req.Header.Set("Authorization", authHeader)

	resp, err := sourcehttp.DoWithRetry(ctx, r.httpClient, req, sourcehttp.RetryOptions{MaxBodyBytes: r.maxManifestBytes})
	if err != nil {
		return nil, "", "", fmt.Errorf("fetch manifest for %s/%s:%s: %w", host, repository, reference, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("manifest request for %s/%s:%s returned HTTP %d", host, repository, reference, resp.StatusCode)
	}
	computed := computeDigest(resp.Body)
	reported := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if reported != "" && !strings.EqualFold(reported, computed) {
		return nil, "", "", &ErrDigestMismatch{Subject: fmt.Sprintf("manifest %s/%s:%s content digest header", host, repository, reference), Expected: reported, Actual: computed}
	}
	// Whenever the requested reference is itself a digest (a caller-pinned
	// digest, or a child manifest fetched by its index-declared digest),
	// the computed content digest must equal it exactly; a registry that
	// serves different bytes for a digest-addressed reference is corrupt or
	// compromised and must never be silently trusted.
	if imageDigestPattern.MatchString(reference) && !strings.EqualFold(reference, computed) {
		return nil, "", "", &ErrDigestMismatch{Subject: fmt.Sprintf("manifest %s/%s@%s requested digest", host, repository, reference), Expected: reference, Actual: computed}
	}
	return resp.Body, computed, resp.Header.Get("Content-Type"), nil
}

func (r *registryReader) fetchBlob(ctx context.Context, base, host, repository, digest, authHeader string, maxBytes int) ([]byte, error) {
	requestPath := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	req, err := sourcehttp.NewRequest(ctx, registrySourceID, base, r.allowLoopback, http.MethodGet, requestPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("build blob request for %s/%s@%s: %w", host, repository, digest, err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", authHeader)

	resp, err := sourcehttp.DoWithRetry(ctx, r.httpClient, req, sourcehttp.RetryOptions{MaxBodyBytes: maxBytes})
	if err != nil {
		return nil, fmt.Errorf("fetch blob %s/%s@%s: %w", host, repository, digest, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blob request for %s/%s@%s returned HTTP %d", host, repository, digest, resp.StatusCode)
	}
	return resp.Body, nil
}

func computeDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyBlobDigest(content []byte, digest string) bool {
	return strings.EqualFold(computeDigest(content), strings.TrimSpace(digest))
}

type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Platform     *ociPlatform      `json:"platform,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

type ociImageConfig struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

func isManifestList(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "manifest.list") || strings.Contains(lower, "image.index") {
		return true
	}
	var probe struct {
		Manifests []json.RawMessage `json:"manifests"`
	}
	return json.Unmarshal(body, &probe) == nil && len(probe.Manifests) > 0
}

// manifestConfigDescriptor decodes manifest body and returns its config
// descriptor (digest, size, and media type), the last of which callers use
// to classify whether an index child is a runnable image at all.
func manifestConfigDescriptor(body []byte) (ociDescriptor, error) {
	var manifest ociManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return ociDescriptor{}, fmt.Errorf("decode manifest: %w", err)
	}
	if strings.TrimSpace(manifest.Config.Digest) == "" {
		return ociDescriptor{}, fmt.Errorf("manifest has no config descriptor digest")
	}
	return manifest.Config, nil
}

// imageConfigMediaTypes are the OCI and Docker image config media types; a
// manifest's config descriptor outside this set names a non-image artifact
// (SBOM, attestation, signature, provenance, …) rather than a runnable
// image variant.
var imageConfigMediaTypes = map[string]bool{
	"application/vnd.oci.image.config.v1+json":       true,
	"application/vnd.docker.container.image.v1+json": true,
}

func isImageConfigMediaType(mediaType string) bool {
	return imageConfigMediaTypes[strings.ToLower(strings.TrimSpace(mediaType))]
}

// indexDescriptorExcludedByEvidence reports whether a manifest-index entry
// carries positive evidence that it is not an independent runnable image
// variant: an explicit unknown/unknown build-attestation platform, a
// non-empty artifactType (OCI 1.1 referrers such as SBOMs, attestations,
// and signatures copy their artifact type onto the index descriptor), or a
// Docker buildx-style attestation-manifest reference annotation. An entry
// with no platform object at all is NOT excluded here -- it must be
// fetched and classified by its own config media type instead of being
// assumed to be a non-image artifact.
func indexDescriptorExcludedByEvidence(m ociDescriptor) bool {
	if m.Platform != nil && (strings.EqualFold(m.Platform.OS, "unknown") || strings.EqualFold(m.Platform.Architecture, "unknown")) {
		return true
	}
	if strings.TrimSpace(m.ArtifactType) != "" {
		return true
	}
	if strings.TrimSpace(m.Annotations["vnd.docker.reference.type"]) != "" {
		return true
	}
	return false
}

// descriptorRunnableLabel names an index entry for gap/reference scoping:
// its platform (os/arch[/variant]) when declared, or a short form of its
// own digest when the index omits platform metadata.
func descriptorRunnableLabel(m ociDescriptor) string {
	if m.Platform != nil && (m.Platform.OS != "" || m.Platform.Architecture != "") {
		label := m.Platform.OS + "/" + m.Platform.Architecture
		if m.Platform.Variant != "" {
			label += "/" + m.Platform.Variant
		}
		return label
	}
	digest := strings.TrimPrefix(m.Digest, "sha256:")
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return "unspecified-platform@" + digest
}

func parseImageConfigLabels(body []byte) (map[string]string, error) {
	var config ociImageConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("decode image config: %w", err)
	}
	return config.Config.Labels, nil
}

// sourcePinFromLabels extracts the standard OCI provenance labels. Revision
// (org.opencontainers.image.revision) is treated as an exact, immutable pin
// only when it is a full 40- or 64-character hex commit id (git SHA-1/SHA-256);
// a floating label such as a branch name ("main"), a short SHA, a tag, or any
// other non-hex value is preserved but marked inferred, matching ref.name.
// Missing labels never fall back to a guessed default branch.
func sourcePinFromLabels(labels map[string]string) (ci.SourcePin, []ci.Gap) {
	repoLabel := strings.TrimSpace(labels["org.opencontainers.image.source"])
	revisionLabel := strings.TrimSpace(labels["org.opencontainers.image.revision"])
	refLabel := strings.TrimSpace(labels["org.opencontainers.image.ref.name"])

	if repoLabel == "" {
		return ci.SourcePin{}, []ci.Gap{{
			Code: "registry.source_label_missing", Scope: "registry",
			Message: "image config has no org.opencontainers.image.source label; source repository is unknown",
		}}
	}
	repository := normalizeSourceLabelRepository(repoLabel)
	if revisionLabel != "" {
		if isImmutableCommitID(revisionLabel) {
			return ci.SourcePin{Repository: repository, Revision: revisionLabel, Exact: true}, nil
		}
		return ci.SourcePin{Repository: repository, Revision: revisionLabel, Exact: false}, []ci.Gap{{
			Code: "registry.source_revision_not_immutable", Scope: "registry",
			Message: fmt.Sprintf("image config org.opencontainers.image.revision label %q is not a full 40- or 64-character hex commit id, so it is not an immutable pin", revisionLabel),
		}}
	}
	if refLabel != "" {
		return ci.SourcePin{Repository: repository, Revision: refLabel, Exact: false}, []ci.Gap{{
			Code: "registry.source_revision_inferred", Scope: "registry",
			Message: "image config lacks org.opencontainers.image.revision; only a non-immutable ref.name label was found, no default-branch fallback was applied",
		}}
	}
	return ci.SourcePin{Repository: repository, Exact: false}, []ci.Gap{{
		Code: "registry.source_revision_missing", Scope: "registry",
		Message: "image config has no revision or ref.name label; source revision is unknown, default-branch resolution is refused",
	}}
}

// isImmutableCommitID reports whether revision is a full 40-character
// (SHA-1) or 64-character (SHA-256) lowercase/uppercase hex git commit id.
// Anything shorter (abbreviated SHAs), a branch/tag name, or non-hex content
// is a floating reference the registry/VCS can repoint later.
func isImmutableCommitID(revision string) bool {
	return commitIDPattern.MatchString(revision)
}

func normalizeSourceLabelRepository(raw string) string {
	trimmed := strings.TrimSpace(raw)
	for _, prefix := range []string{"git+https://github.com/", "git+http://github.com/", "https://github.com/", "http://github.com/", "github.com/"} {
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			trimmed = trimmed[len(prefix):]
			break
		}
	}
	return strings.TrimSuffix(trimmed, ".git")
}

type parsedImage struct {
	host       string
	repository string
	tag        string
	digest     string
}

var (
	imageDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)
	imageTagPattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	// commitIDPattern matches a full 40-character (SHA-1) or 64-character
	// (SHA-256) hex git commit id, the only org.opencontainers.image.revision
	// shapes this adapter treats as immutable.
	commitIDPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
)

// parseImageReference parses a docker/OCI reference of the form
// "host[:port]/repository[:tag][@sha256:digest]". A registry host is
// mandatory; bare "repository:tag" references without a host are refused
// since there is no implicit default registry here.
func parseImageReference(raw string) (parsedImage, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return parsedImage{}, fmt.Errorf("image reference is required")
	}
	rest := trimmed
	digest := ""
	if idx := strings.LastIndex(trimmed, "@"); idx >= 0 {
		digest = trimmed[idx+1:]
		rest = trimmed[:idx]
		if !imageDigestPattern.MatchString(digest) {
			return parsedImage{}, fmt.Errorf("image digest %q is not a supported sha256 digest", digest)
		}
	}
	firstSlash := strings.Index(rest, "/")
	if firstSlash < 0 {
		return parsedImage{}, fmt.Errorf("image reference %q must include a registry host", raw)
	}
	host := rest[:firstSlash]
	if !strings.ContainsAny(host, ".:") && host != "localhost" {
		return parsedImage{}, fmt.Errorf("image reference %q must include a registry host", raw)
	}
	remainder := rest[firstSlash+1:]
	repository := remainder
	tag := ""
	if idx := strings.LastIndex(remainder, "/"); idx >= 0 {
		lastSegment := remainder[idx+1:]
		if tagIdx := strings.LastIndex(lastSegment, ":"); tagIdx >= 0 {
			tag = lastSegment[tagIdx+1:]
			repository = remainder[:idx+1] + lastSegment[:tagIdx]
		}
	} else if tagIdx := strings.LastIndex(remainder, ":"); tagIdx >= 0 {
		tag = remainder[tagIdx+1:]
		repository = remainder[:tagIdx]
	}
	if !imageRepositoryPattern.MatchString(repository) {
		return parsedImage{}, fmt.Errorf("image repository %q is not valid", repository)
	}
	if tag != "" && !imageTagPattern.MatchString(tag) {
		return parsedImage{}, fmt.Errorf("image tag %q is not valid", tag)
	}
	if tag == "" && digest == "" {
		return parsedImage{}, fmt.Errorf("image reference %q must include a tag or digest", raw)
	}
	return parsedImage{host: strings.ToLower(host), repository: repository, tag: tag, digest: digest}, nil
}

var (
	ecrHostPattern         = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$`)
	gcrRegionalHostPattern = regexp.MustCompile(`^[a-z]+\.gcr\.io$`)
)

// detectRegistryProvider classifies a reference's registry host as Amazon
// ECR or Google Artifact Registry/GCR; any other host is unsupported.
func detectRegistryProvider(host string) (provider ci.Provider, accountID string, region string, ok bool) {
	lower := strings.ToLower(host)
	if match := ecrHostPattern.FindStringSubmatch(lower); match != nil {
		return ci.AWS, match[1], match[2], true
	}
	if strings.HasSuffix(lower, "-docker.pkg.dev") || lower == "gcr.io" || gcrRegionalHostPattern.MatchString(lower) {
		return ci.GCP, "", "", true
	}
	return "", "", "", false
}
